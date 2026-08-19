# Database Model — SDIP (PostgreSQL)

**Deliverable:** CLAUDE.md §46.F
**Date:** 2026-08-14
**Status:** Design. Binds migration #1.
**Governed by:** ADR-0001 (append-only), ADR-0003 (tenancy), ADR-0012 (audit), ADR-0014 (no graph DB), ADR-0016 (suppressions)
**Target:** PostgreSQL 16+ with `pgvector ≥ 0.8`, `pg_trgm`, `pgcrypto`

---

## 1. Conventions

| Rule | Rationale |
|---|---|
| **Every tenant-scoped table has `org_id UUID NOT NULL` as the first column of its primary key** | ADR-0003. Not a convention — a load-bearing control |
| **Primary keys are composite: `(org_id, id)`** | Makes a cross-tenant foreign key **structurally impossible** rather than merely forbidden (invariant I1) |
| **Foreign keys are composite: `(org_id, parent_id) REFERENCES parent (org_id, id)`** | Same reason. A child cannot reference a parent in another organization; the database rejects it |
| IDs are **UUIDv7 generated application-side** | Time-ordered (good index locality), opaque, globally unique, and required by ADR-0014's exportability property |
| All timestamps are `timestamptz`, UTC | |
| Enums are Postgres `ENUM` types where the set is closed and slow-changing; `TEXT` + `CHECK` where it churns | Enum changes require a migration; that friction is desirable for decision vocabularies |
| Money is `NUMERIC(12,6)` | Fractions of a cent matter at token scale |
| Every index leads with `org_id` | Without it the RLS predicate turns index scans into sequential scans |
| Table and column names are singular, snake_case | |

**The cost of composite keys, stated honestly:** every join is two columns, SQLAlchemy relationship definitions are more verbose, and a careless `JOIN ON id` silently loses tenant scoping (it will still be caught by RLS, which is the point of having both). This is accepted because the alternative — a single-column PK — makes cross-tenant references *expressible*, and everything expressible eventually gets expressed.

---

## 2. Tenancy and RLS

### 2.1 Roles

```sql
CREATE ROLE sdip_owner   NOLOGIN;                 -- owns objects, runs migrations
CREATE ROLE sdip_app     LOGIN NOINHERIT;         -- the application. NOT the owner.
CREATE ROLE sdip_readonly LOGIN NOINHERIT;        -- reporting
-- No role has BYPASSRLS except a break-glass role whose use alerts.
```

The application **must not** own its tables. Owners and superusers bypass RLS unless `FORCE` is set, and migrations run as the owner — which is why migration review is classified security-relevant and requires a second reviewer.

### 2.2 The policy template — applied to every tenant-scoped table

```sql
ALTER TABLE <t> ENABLE ROW LEVEL SECURITY;
ALTER TABLE <t> FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON <t>
  USING      (org_id = current_setting('app.tenant_id', true)::uuid)
  WITH CHECK (org_id = current_setting('app.tenant_id', true)::uuid);
```

`current_setting(..., true)` returns `NULL` when the GUC is unset, so `org_id = NULL` evaluates to `NULL`, the policy does not pass, and the query returns **zero rows**. **Unset context fails closed.** That is the desired behaviour and it must be covered by a test, because the alternative implementation (`current_setting` without the `missing_ok` flag) raises instead, and a raise is a different failure mode in a background job.

### 2.3 Setting context

```sql
BEGIN;
SET LOCAL app.tenant_id = '…';
-- all statements
COMMIT;
```

**`SET LOCAL`, inside an explicit transaction, always.** With PgBouncer in transaction pooling a session-scoped `SET` leaks to the next request on the same pooled connection — a textbook cross-tenant disclosure. Statement-mode pooling is incompatible with RLS context entirely and must be rejected in configuration review.

Consequence: **every query path runs in a transaction.** Autocommit paths, async background jobs and health checks are the recurring failure sites; the connection factory must make a non-transactional query impossible rather than merely discouraged.

### 2.4 The migration gate (blocking CI)

```sql
-- fails the build if any table with an org_id column lacks RLS or FORCE
SELECT c.relname
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'org_id'
WHERE n.nspname = 'public' AND c.relkind = 'r'
  AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity);
```

---

## 3. Core schema

### 3.1 Organizations and actors

```sql
CREATE TABLE organization (
  id            UUID PRIMARY KEY,
  slug          TEXT NOT NULL UNIQUE,
  name          TEXT NOT NULL,
  snippet_tier  snippet_tier_t NOT NULL DEFAULT 'no_code',   -- ADR-0011
  knowledge_scope_default knowledge_scope_t NOT NULL DEFAULT 'tenant_private', -- ADR-0017
  created_at    timestamptz NOT NULL DEFAULT now()
);
-- No RLS: this is the tenant registry itself, readable only by the control plane.

CREATE TABLE actor (
  org_id     UUID NOT NULL REFERENCES organization(id),
  id         UUID NOT NULL,
  kind       actor_kind_t NOT NULL,          -- human | service | system
  subject    TEXT NOT NULL,                  -- IdP subject
  email      CITEXT,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, id),
  UNIQUE (org_id, subject)
);
```

### 3.2 Assets

```sql
CREATE TABLE repository (
  org_id      UUID NOT NULL,
  id          UUID NOT NULL,
  project_id  UUID NOT NULL,
  provider    TEXT NOT NULL,                 -- github | gitlab | …
  external_id TEXT NOT NULL,
  default_branch TEXT,
  PRIMARY KEY (org_id, id),
  FOREIGN KEY (org_id, project_id) REFERENCES project (org_id, id),
  UNIQUE (org_id, provider, external_id)
);

CREATE TABLE service (
  org_id        UUID NOT NULL,
  id            UUID NOT NULL,
  name          TEXT NOT NULL,
  criticality   criticality_t,               -- NULLABLE ON PURPOSE — see below
  internet_facing BOOLEAN,                   -- NULLABLE ON PURPOSE
  handles_regulated_data BOOLEAN,
  PRIMARY KEY (org_id, id)
);
```

> **`criticality` and `internet_facing` are deliberately nullable.** `NULL` means *unresolved*, which is not the same as *low* or *false*. Unresolved criticality **fails closed** — the finding is treated as the highest tier and is ineligible for auto-deprioritize. A `NOT NULL DEFAULT 'low'` here would silently suppress findings on precisely the assets the system knows least about, which is how this design produces its first incident.

```sql
CREATE TABLE ownership (
  org_id      UUID NOT NULL,
  id          UUID NOT NULL,
  subject_type TEXT NOT NULL,                -- repository | service | path
  subject_id  UUID NOT NULL,
  owner_actor_id UUID,
  owner_team  TEXT,
  source      TEXT NOT NULL,                 -- codeowners | catalog | git_history | manual
  confidence  REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
  resolved_at timestamptz NOT NULL,
  PRIMARY KEY (org_id, id)
);
CREATE INDEX ON ownership (org_id, subject_type, subject_id);
```

### 3.3 Ingestion

```sql
CREATE TABLE scan_run (
  org_id           UUID NOT NULL,
  id               UUID NOT NULL,
  idempotency_key  TEXT NOT NULL,
  tool             TEXT NOT NULL,
  tool_version     TEXT NOT NULL,
  ruleset_version  TEXT,
  ruleset_hash     BYTEA,
  repo_id          UUID,
  commit_sha       TEXT,
  scope_hash       BYTEA NOT NULL,           -- canonical(paths ‖ ruleset ‖ config)
  status           scan_run_status_t NOT NULL DEFAULT 'started',
  finding_count    INTEGER,
  truncation_summary JSONB,
  started_at       timestamptz NOT NULL DEFAULT now(),
  completed_at     timestamptz,
  PRIMARY KEY (org_id, id),
  UNIQUE (org_id, idempotency_key),          -- ADR-0005: the retry contract
  FOREIGN KEY (org_id, repo_id) REFERENCES repository (org_id, id)
);
CREATE INDEX ON scan_run (org_id, repo_id, tool, started_at DESC);
```

The row is created **before parsing**. A retry with the same key returns this row's id and status — 200, not 409.

```sql
CREATE TABLE observation (
  org_id       UUID NOT NULL,
  id           UUID NOT NULL,
  observed_at  timestamptz NOT NULL,
  scan_run_id  UUID NOT NULL,
  identity_id  UUID NOT NULL,
  class        finding_class_t NOT NULL,     -- sast | sca | secret | container | iac
  tool         TEXT NOT NULL,
  tool_version TEXT NOT NULL,
  rule_id      TEXT,
  rule_version TEXT,
  severity_raw TEXT,
  severity_normalized severity_t,
  severity_mapping_version TEXT NOT NULL,
  cvss         JSONB,                        -- [{source, vector, score}] — never one column
  cve_ids      TEXT[],
  purl_name    TEXT,
  purl_version TEXT,
  fixed_version TEXT,
  dependency_path JSONB,                     -- direct/transitive + which path (SARIF cannot carry this)
  file_path    TEXT,
  region       JSONB,
  image_digest TEXT,
  secret_ref   BYTEA,                        -- HMAC, never the secret (ADR-0011)
  in_tool_suppressed BOOLEAN NOT NULL DEFAULT FALSE,
  raw_payload_ref BYTEA,                     -- content hash into the payload store
  PRIMARY KEY (org_id, id, observed_at)
) PARTITION BY RANGE (observed_at);
```

**Partitioned monthly.** Retention is a partition `DETACH` + `DROP`, not a `DELETE` — which is the entire reason a 1–5M-row/day table is operable.

```sql
REVOKE UPDATE, DELETE, TRUNCATE ON observation FROM sdip_app;   -- invariant I2
GRANT  SELECT, INSERT ON observation TO sdip_app;
```

Indexes (per partition):

```sql
CREATE INDEX ON observation (org_id, identity_id, observed_at DESC);  -- "history of this finding"
CREATE INDEX ON observation (org_id, scan_run_id);                    -- run contents
CREATE INDEX ON observation (org_id, purl_name, purl_version)
  WHERE purl_name IS NOT NULL;                                        -- SCA blocking key
CREATE INDEX ON observation (org_id, rule_id, tool_version);          -- drift segmentation
CREATE INDEX ON observation USING GIN (cve_ids);
```

### 3.4 Identity and state

```sql
CREATE TABLE finding_identity (
  org_id              UUID NOT NULL,
  id                  UUID NOT NULL,
  fingerprint_version SMALLINT NOT NULL,
  fingerprint         BYTEA NOT NULL,
  class               finding_class_t NOT NULL,
  first_observed_at   timestamptz NOT NULL,
  PRIMARY KEY (org_id, id),
  UNIQUE (org_id, fingerprint_version, fingerprint)
);

CREATE TABLE observation_fingerprint (
  org_id              UUID NOT NULL,
  observation_id      UUID NOT NULL,
  fingerprint_version SMALLINT NOT NULL,
  fingerprint         BYTEA NOT NULL,
  PRIMARY KEY (org_id, observation_id, fingerprint_version)
);
```

`observation_fingerprint` is what makes ADR-0001's promise real: fingerprint v2 is computed over **stored observations**, so a v2 identity set is derivable without re-parsing raw payloads (which may already have been deleted under the short raw-payload retention).

```sql
CREATE TABLE identity_alias (                 -- cross-version reconciliation, append-only
  org_id            UUID NOT NULL,
  from_identity_id  UUID NOT NULL,
  to_identity_id    UUID NOT NULL,
  reason            TEXT NOT NULL,            -- version_upgrade | split | merge
  algorithm_version SMALLINT NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, from_identity_id, to_identity_id, algorithm_version)
);

CREATE TABLE finding_state (                  -- projection, mutable, low volume
  org_id              UUID NOT NULL,
  identity_id         UUID NOT NULL,
  status              finding_status_t NOT NULL,
  current_decision_id UUID,
  last_observed_at    timestamptz,
  absent_run_count    SMALLINT NOT NULL DEFAULT 0,   -- comparable, complete runs only
  updated_at          timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, identity_id)
);
CREATE INDEX ON finding_state (org_id, status, last_observed_at DESC);
```

`finding_state` is the only high-read, mutable table in the finding path, and it is ~100k rows — small enough that its update rate (hundreds/day) never approaches the bloat problem ADR-0001 exists to avoid.

### 3.5 Correlation

```sql
CREATE TABLE correlation_edge (               -- APPEND ONLY
  org_id            UUID NOT NULL,
  id                UUID NOT NULL,
  a_identity_id     UUID NOT NULL,
  b_identity_id     UUID NOT NULL,
  relation          correlation_relation_t NOT NULL,  -- exact_duplicate | same_root_cause | related | suspected
  confidence        REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
  algorithm_version SMALLINT NOT NULL,
  evidence_json     JSONB NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, id),
  CHECK (a_identity_id < b_identity_id)       -- canonical ordering; no duplicate pairs
);
CREATE UNIQUE INDEX ON correlation_edge (org_id, a_identity_id, b_identity_id, algorithm_version);

CREATE TABLE correlation_cluster_materialized (
  org_id            UUID NOT NULL,
  algorithm_version SMALLINT NOT NULL,
  identity_id       UUID NOT NULL,
  cluster_id        UUID NOT NULL,
  materialized_at   timestamptz NOT NULL,
  PRIMARY KEY (org_id, algorithm_version, identity_id)
);
CREATE INDEX ON correlation_cluster_materialized (org_id, algorithm_version, cluster_id);
```

Two materializations coexist; the API reads whichever version is promoted. Promotion is a row in `reprocessing_job`, not a schema change. **Cluster membership is never written onto a finding row** — that would be the irreversible merge CLAUDE.md §25 forbids.

### 3.6 Evidence

```sql
CREATE TABLE source_record (
  org_id         UUID NOT NULL,              -- public sources are stored per-org or in a shared
  id             UUID NOT NULL,              -- public schema; see §6 on the cache/oracle rule
  source_type    TEXT NOT NULL,              -- nvd | kev | epss | ghsa | osv | vendor_psirt | internal
  source_id      TEXT NOT NULL,
  authority_tier authority_tier_t NOT NULL,  -- A..E
  mutability     mutability_t NOT NULL,
  attestation    attestation_t NOT NULL,
  dispute_state  dispute_state_t NOT NULL DEFAULT 'none',
  first_seen     timestamptz NOT NULL,
  last_verified  timestamptz NOT NULL,
  PRIMARY KEY (org_id, id),
  UNIQUE (org_id, source_type, source_id)
);

CREATE TABLE advisory_snapshot (
  org_id          UUID NOT NULL,
  id              UUID NOT NULL,
  source_record_id UUID NOT NULL,
  version_label   TEXT,
  content_hash    BYTEA NOT NULL,
  affected_ranges JSONB NOT NULL,
  fetched_at      timestamptz NOT NULL,
  PRIMARY KEY (org_id, id),
  UNIQUE (org_id, source_record_id, content_hash)
);
CREATE INDEX ON advisory_snapshot (org_id, source_record_id, fetched_at DESC);
```

`advisory_snapshot` is the mechanism behind two product claims at once: **range-narrowing detection** (diff `affected_ranges` between consecutive snapshots) and `evidence_availability` (what the advisory said on the day of the decision).

```sql
CREATE TABLE evidence (
  org_id          UUID NOT NULL,
  id              UUID NOT NULL,
  decision_id     UUID NOT NULL,
  slot            TEXT NOT NULL,             -- evidence contract slot name
  source_record_id UUID,
  snapshot_id     UUID,
  content_hash    BYTEA NOT NULL,
  body            JSONB,                     -- extractive only; never an LLM paraphrase
  retrieved_at    timestamptz NOT NULL,
  freshness_window INTERVAL,
  relevance_score REAL,
  epss_model_version TEXT,                   -- version pin travels with the value
  PRIMARY KEY (org_id, id)
);
CREATE INDEX ON evidence (org_id, decision_id);

CREATE TABLE evidence_gap  (org_id UUID NOT NULL, decision_id UUID NOT NULL,
                            slot TEXT NOT NULL, reason TEXT NOT NULL,
                            PRIMARY KEY (org_id, decision_id, slot));

CREATE TABLE evidence_drop (org_id UUID NOT NULL, decision_id UUID NOT NULL,
                            evidence_ref TEXT NOT NULL, slot TEXT NOT NULL,
                            score REAL, reason drop_reason_t NOT NULL,
                            PRIMARY KEY (org_id, decision_id, evidence_ref));

CREATE TABLE conflict (org_id UUID NOT NULL, decision_id UUID NOT NULL, rule_id TEXT NOT NULL,
                       evidence_id_a UUID NOT NULL, evidence_id_b UUID NOT NULL,
                       PRIMARY KEY (org_id, decision_id, rule_id, evidence_id_a, evidence_id_b));

CREATE TABLE code_flow      (org_id UUID NOT NULL, id UUID NOT NULL, observation_id UUID NOT NULL,
                             ordinal SMALLINT NOT NULL, PRIMARY KEY (org_id, id));
CREATE TABLE code_flow_step (org_id UUID NOT NULL, code_flow_id UUID NOT NULL, step_index SMALLINT NOT NULL,
                             file_path TEXT, region JSONB, message TEXT,
                             PRIMARY KEY (org_id, code_flow_id, step_index));
```

`code_flow` is structural, not a blob — evidence that cannot be ranked or cited is not evidence (ADR-0004).

### 3.7 Decisions

```sql
CREATE TABLE decision (
  org_id      UUID NOT NULL,
  id          UUID NOT NULL,
  identity_id UUID NOT NULL,
  decided_at  timestamptz NOT NULL DEFAULT now(),

  finding_content_hash BYTEA NOT NULL,

  deterministic_assessment JSONB NOT NULL,   -- score, feature_vector, scoring_model_version, severity_floor
  model_recommendation     JSONB,            -- NULL when the pre-filter decided (the common case)
  policy_decision          JSONB NOT NULL,   -- decision, policy_version, predicates_satisfied[], …
  evidence_availability    JSONB NOT NULL,   -- invariant I13
  untrusted_content        JSONB NOT NULL,   -- segments, bytes, injection verdict, detector version

  disposition disposition_t NOT NULL,        -- denormalized from policy_decision for indexing
  contextual_risk_score REAL NOT NULL CHECK (contextual_risk_score BETWEEN 0 AND 1),
  confidence  REAL CHECK (confidence BETWEEN 0 AND 1),
  review_propensity REAL NOT NULL CHECK (review_propensity BETWEEN 0 AND 1),  -- I14

  redaction_tier snippet_tier_t NOT NULL,
  provider    JSONB,
  prompt_template_version TEXT,
  prompt_template_hash    BYTEA,
  retrieval_config_version TEXT,
  scoring_model_version   TEXT NOT NULL,
  policy_version          TEXT NOT NULL,
  reproducibility JSONB,                     -- prompt_hash, context_manifest_hash
  cost_usd    NUMERIC(12,6),

  PRIMARY KEY (org_id, id)
);
REVOKE UPDATE, DELETE ON decision FROM sdip_app;              -- invariant I9
CREATE INDEX ON decision (org_id, identity_id, decided_at DESC);
CREATE INDEX ON decision (org_id, disposition, decided_at DESC);

CREATE TABLE decision_revision (
  org_id             UUID NOT NULL,
  id                 UUID NOT NULL,
  original_decision_id UUID NOT NULL,
  new_decision_id    UUID NOT NULL,
  actor_id           UUID NOT NULL,
  reason_code        TEXT NOT NULL,
  note               TEXT,
  created_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, id)
);
```

**`contextual_risk_score` carries a `CHECK` constraint because the model never supplies it** — it is computed by the versioned scoring function. (Structured outputs cannot enforce numeric ranges anyway, which is a second reason the score must not come from a model.)

### 3.8 Suppressions — the product

```sql
CREATE TABLE suppression (
  org_id      UUID NOT NULL,
  id          UUID NOT NULL,
  created_from_decision_id UUID NOT NULL,
  scope_kind  suppression_scope_t NOT NULL,  -- finding | rule_in_repo | vulnerability_org_wide | package_everywhere
  scope_predicate JSONB NOT NULL,
  condition_count SMALLINT NOT NULL CHECK (condition_count >= 1),   -- invariant I17
  expires_at  timestamptz NOT NULL,                                 -- mandatory
  approver_actor_id UUID NOT NULL,                                  -- a named human, always
  reason_code TEXT NOT NULL,
  justification TEXT,
  evidence_snapshot_ref BYTEA NOT NULL,
  status      suppression_status_t NOT NULL DEFAULT 'active',
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, id),
  FOREIGN KEY (org_id, approver_actor_id) REFERENCES actor (org_id, id)
);
CREATE INDEX ON suppression (org_id, status, expires_at)
  WHERE status = 'active';                   -- the watch-worker's hot path

CREATE TABLE invalidation_condition (
  org_id         UUID NOT NULL,
  suppression_id UUID NOT NULL,
  ordinal        SMALLINT NOT NULL,
  condition_type condition_type_t NOT NULL,  -- kev_listed | epss_above | exploit_published |
                                             -- advisory_range_narrowed | became_reachable |
                                             -- became_internet_facing | criticality_increased |
                                             -- ownership_changed
  threshold      JSONB,
  source_pin     JSONB,                      -- e.g. {"epss_model_version": "v5"}
  PRIMARY KEY (org_id, suppression_id, ordinal)
);

CREATE TABLE reopen_event (
  org_id         UUID NOT NULL,
  id             UUID NOT NULL,
  suppression_id UUID NOT NULL,
  trigger        condition_type_t NOT NULL,
  delta          JSONB NOT NULL,             -- what changed, from → to
  detected_at    timestamptz NOT NULL,
  notified_at    timestamptz,
  analyst_agreed BOOLEAN,                    -- feeds re-litigation precision
  PRIMARY KEY (org_id, id)
);
CREATE INDEX ON reopen_event (org_id, detected_at DESC);
```

**`condition_count >= 1` is a denormalized counter, not a foreign-key count**, because Postgres cannot declaratively require "at least one child row." It is maintained by a `DEFERRABLE INITIALLY DEFERRED` constraint trigger that recounts at commit. The counter is a guardrail; the trigger is the enforcement. Both, because invariant I17 is the product.

`analyst_agreed` on `reopen_event` is the column that measures whether the product works. Re-litigation precision ≥60% is the target; below 40% SDIP is a new alert-fatigue source.

### 3.9 Audit — append-only, chained, anchored

```sql
CREATE TABLE audit_record (
  org_id      UUID NOT NULL,
  seq         BIGINT NOT NULL,               -- monotonic per org
  id          UUID NOT NULL,
  subject_type TEXT NOT NULL,
  subject_id  UUID NOT NULL,
  action      TEXT NOT NULL,
  actor       JSONB NOT NULL,
  payload_ref BYTEA NOT NULL,                -- hash of the payload, NOT the payload
  prev_hash   BYTEA NOT NULL,
  record_hash BYTEA NOT NULL,
  merkle_root_id UUID,
  tsa_token   BYTEA,
  server_time timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, seq)
);
REVOKE UPDATE, DELETE, TRUNCATE ON audit_record FROM sdip_app;
GRANT  SELECT, INSERT ON audit_record TO sdip_app;

CREATE TABLE audit_chain_tip (
  org_id     UUID PRIMARY KEY,
  last_seq   BIGINT NOT NULL,
  last_hash  BYTEA NOT NULL
);
```

> **The concurrency detail everyone gets wrong.** A hash chain requires serialization per organization: two concurrent writers reading the same `prev_hash` produce a fork, and a forked chain is an unverifiable chain. Append is therefore `UPDATE audit_chain_tip … WHERE org_id = $1 RETURNING last_hash, last_seq` inside the same transaction — the row lock serializes writers per tenant while leaving different tenants fully concurrent. Do not use a sequence; sequences are not transactional and gaps break verification.

**The chain is over references, not content** (`payload_ref`), so a leaked secret in a payload can be deleted without breaking the chain — provable existence plus provable deletion (ADR-0012 §4).

### 3.10 Knowledge and governance

```sql
CREATE TABLE memory_entry (
  org_id          UUID NOT NULL,
  id              UUID NOT NULL,
  knowledge_scope knowledge_scope_t NOT NULL DEFAULT 'tenant_private',   -- ADR-0017
  claim           JSONB NOT NULL,
  corroboration   JSONB NOT NULL,            -- distinct analysts / repos / times
  injection_verdict TEXT NOT NULL,
  author_actor_id UUID NOT NULL,
  status          memory_status_t NOT NULL DEFAULT 'active',  -- active | quarantined
  created_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, id)
);

CREATE TABLE memory_derivation (               -- enables cascade rollback (invariant I22)
  org_id UUID NOT NULL, memory_id UUID NOT NULL, decision_id UUID NOT NULL,
  PRIMARY KEY (org_id, memory_id, decision_id)
);

CREATE TABLE outcome_signal (
  org_id      UUID NOT NULL,
  id          UUID NOT NULL,
  identity_id UUID NOT NULL,
  kind        outcome_kind_t NOT NULL,       -- later_kev | later_exploit_published |
                                             -- epss_threshold_crossed | incident_linked | remediated_anyway
  observed_at timestamptz NOT NULL,
  source      TEXT NOT NULL,
  PRIMARY KEY (org_id, id)
);

CREATE TABLE calibrator (
  org_id UUID NOT NULL, id UUID NOT NULL,
  decision_class TEXT NOT NULL, rule_family TEXT,
  kind TEXT NOT NULL,                        -- platt | isotonic | conformal
  params JSONB NOT NULL, fit_date timestamptz NOT NULL,
  sample_size INTEGER NOT NULL, validity_window INTERVAL NOT NULL,
  PRIMARY KEY (org_id, id)
);

CREATE TABLE cost_budget (
  org_id UUID PRIMARY KEY, period TEXT NOT NULL,
  budget_usd NUMERIC(12,2) NOT NULL, spent_usd NUMERIC(12,6) NOT NULL DEFAULT 0,
  degraded_since timestamptz
);

CREATE TABLE reprocessing_job (
  org_id UUID NOT NULL, id UUID NOT NULL,
  kind TEXT NOT NULL,                        -- recorrelate | rescore | reanalyze | reembed
  algorithm_version SMALLINT, scope JSONB NOT NULL,
  progress JSONB NOT NULL, shadow BOOLEAN NOT NULL DEFAULT TRUE,
  promoted_at timestamptz,
  PRIMARY KEY (org_id, id)
);
```

### 3.11 Statistics — a view, not an engine

```sql
CREATE MATERIALIZED VIEW rule_disposition_stats AS
SELECT o.org_id, o.tool, o.rule_id,
       split_part(o.tool_version, '.', 1) AS scanner_major_version,   -- NEVER pool across versions
       count(*) FILTER (WHERE d.disposition = 'false_positive_candidate') AS n_fp,
       count(*) FILTER (WHERE d.disposition = 'prioritize')            AS n_tp,
       count(*)                                                        AS n_decisions,
       sum(1.0 / NULLIF(d.review_propensity, 0))                       AS ht_weight_total,
       min(o.observed_at) AS first_seen, max(o.observed_at) AS last_seen
FROM observation o
JOIN decision d ON d.org_id = o.org_id AND d.identity_id = o.identity_id
GROUP BY 1,2,3,4;
```

Two properties are non-negotiable and both are visible in the SQL: **segmentation by scanner major version** (pooling across a version boundary averages two different detectors and reports a number that describes nothing), and **inverse-propensity weighting** (without it the statistic is computed over reviewed items only, which is the suppression death spiral).

This is the whole of "Pattern Discovery" for the MVP: a view, surfaced with an explicit `n`. No lifecycle, no promotion mechanism, no engine.

---

## 4. Vectors

```sql
CREATE TABLE embedding (
  org_id      UUID NOT NULL,
  id          UUID NOT NULL,
  subject_type embedding_subject_t NOT NULL, -- decision_rationale | remediation_note | advisory_prose
  subject_id  UUID NOT NULL,
  model       TEXT NOT NULL,
  embedding   vector(768) NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, id)
);

CREATE INDEX embedding_hnsw ON embedding
  USING hnsw (embedding vector_cosine_ops) WITH (m = 16, ef_construction = 64);
```

**`subject_type` has exactly three values, and "finding" is not one of them** (ADR-0014). Finding text is templated and near-duplicate; embedding 1M findings produces 1M nearly-identical vectors and a retrieval layer that returns noise. Embedding only what has semantic variance keeps year-one volume at 10k–100k vectors per tenant — which moves the pgvector wall from ~6 months out to ~2–3 years out.

Required session configuration, set explicitly and never left at defaults:

```sql
SET hnsw.iterative_scan = relaxed_order;
SET hnsw.max_scan_tuples = 20000;
```

Without iterative scans, a filtered query against a shared index collects ANN candidates **and then** applies `org_id`, so a tenant holding 0.5% of rows silently receives 2 rows instead of 10. No error — just degraded recall, worst for the smallest tenants, who are the ones on a pilot deciding whether to buy. **Per-tenant recall is a monitored metric**, not an assumption.

Migration path when tenant count crosses the threshold: `PARTITION BY LIST (org_id)` with per-partition HNSW indexes. This is an index topology change with a different memory and latency profile, which is why ADR-0003 requires deciding it early rather than discovering it.

---

## 5. Graph structures

```sql
CREATE TABLE edges (
  org_id     UUID NOT NULL,
  id         UUID NOT NULL,
  src_type   TEXT NOT NULL, src_id UUID NOT NULL,
  dst_type   TEXT NOT NULL, dst_id UUID NOT NULL,
  rel_type   TEXT NOT NULL,
  confidence REAL,
  provenance JSONB NOT NULL,
  inferred   BOOLEAN NOT NULL,               -- inferred vs authoritative must be distinguishable
  algorithm_version SMALLINT,
  valid_from timestamptz NOT NULL DEFAULT now(),
  valid_to   timestamptz,
  PRIMARY KEY (org_id, id)
);
CREATE INDEX ON edges (org_id, src_type, src_id, rel_type) WHERE valid_to IS NULL;
CREATE INDEX ON edges (org_id, dst_type, dst_id, rel_type) WHERE valid_to IS NULL;

CREATE TABLE dependency_closure (             -- the one traversal Postgres will not serve
  org_id UUID NOT NULL,
  root_component_id UUID NOT NULL,
  reachable_component_id UUID NOT NULL,
  min_depth SMALLINT NOT NULL,
  computed_at timestamptz NOT NULL,
  PRIMARY KEY (org_id, root_component_id, reachable_component_id)
);
```

"Which internet-exposed services transitively depend on a package with a KEV CVE" is depth 5–8 at fanout 20–100. Postgres's recursive executor cannot maintain visited state across iterations, so the frontier reaches ~3×10⁸ rows before dedup. Precomputing the closure turns it into one indexed lookup, refreshed on dependency-graph change (lockfile commits, not every scan) — **~10× cheaper than operating a second database** with its own backup, HA, auth and tenant-isolation story.

---

## 6. Retention

| Class | Retention | Mechanism |
|---|---|---|
| **Raw payloads** | **Shortest** — 30 days default | Object store lifecycle rule; referenced by hash only |
| Observations | 13 months | Monthly partition `DETACH` + `DROP` |
| Evidence bodies | 13 months | Follows observations |
| Embeddings | Follows subject | Deleted by `subject_id` on subject deletion |
| Findings / state | Lifetime of the tenant | |
| **Decisions and audit records** | **7 years** | Never partition-dropped; separate WORM export |

CLAUDE.md §44 treats retention as one policy. **It is three, and they conflict**: audit must outlive findings, raw payloads must not outlive the week. The WAL/PITR window must be stated in the DPA, because "deleted" means something different inside it.

**Derived-data deletion is the hard part and it must be designed now:** deleting a repository's findings must cascade through observations, evidence, embeddings, vector index entries, decisions, **and the statistical aggregates computed from them**. Aggregates are recomputed from surviving source — which is only possible because the source is append-only and still present. On a mutable model, this obligation is unfulfillable and the deletion commitment in §44 cannot be honestly made.

---

## 7. Migration order

Each step leaves the database runnable.

| # | Migration | Contains |
|---|---|---|
| 001 | Extensions, roles, enum types, RLS helper functions | `pgvector`, `pg_trgm`, `pgcrypto`; `sdip_app` as non-owner |
| 002 | `organization`, `actor`, `project`, `repository`, `service`, `ownership` | + RLS on all |
| 003 | `scan_run`, `observation` (partitioned), `observation_fingerprint`, partition-creation job | + grants revoking UPDATE/DELETE |
| 004 | `finding_identity`, `identity_alias`, `finding_state` | |
| 005 | `correlation_edge`, `correlation_cluster_materialized` | |
| 006 | `source_record`, `advisory_snapshot`, `evidence`, `evidence_gap`, `evidence_drop`, `conflict`, `code_flow*` | |
| 007 | `decision`, `decision_revision` | + grants; `review_propensity` NOT NULL **from the start** |
| 008 | `suppression`, `invalidation_condition`, `reopen_event` + deferred constraint trigger | |
| 009 | `audit_record`, `audit_chain_tip` | + grants |
| 010 | `memory_entry`, `memory_derivation`, `outcome_signal`, `calibrator` | |
| 011 | `cost_budget`, `usage_ledger`, `reprocessing_job`, `policy`, `sla_clock` | |
| 012 | `embedding` + HNSW index | |
| 013 | `edges`, `dependency_closure` | |
| 014 | `rule_disposition_stats` materialized view + refresh schedule | |

**Migrations 001–009 are the ones that must be right the first time.** Everything from 010 on is additive and cheap to change.

---

## 8. Explicitly banned

Each of these is the *natural* thing to write, which is why it needs to be named.

| Anti-pattern | Why | Instead |
|---|---|---|
| `UPDATE finding SET last_seen = now()` | 1–5 GB/day of dead tuples on a 100 MB table; destroys re-correlation inputs | Append an observation; project state |
| Single-column PK on a tenant-scoped table | Makes cross-tenant references expressible | `(org_id, id)` |
| `cluster_id` column on a finding row | Irreversible merge | Append-only edges + versioned materialization |
| FK column encoding a graph relationship | Invisible to an exporter; makes "graph-ready" false | A row in `edges` |
| `cvss_score REAL` | An unattributed editorial decision between disagreeing sources | `(source, vector, score)` triples |
| `criticality NOT NULL DEFAULT 'low'` | Silently suppresses findings on the least-understood assets | Nullable; unresolved fails closed |
| Redis key `evidence:cve-2024-1234` | Cross-tenant leak with no error and no log line | `t:{org_id}:…` through the single wrapper |
| Cache keyed by bare content hash | A cross-tenant oracle measurable by hit latency | Tenant-derived prefix; shared cache only for wholly public data |
| Embedding every finding | 1M near-identical vectors, noisy retrieval, the vector wall in ~6 months | Three subject types, none of them "finding" |
| `DELETE FROM observation WHERE observed_at < …` | Hours of locking and bloat | `DETACH PARTITION` + `DROP` |
| Sequence-generated `audit_record.seq` | Sequences are non-transactional; gaps break chain verification | `audit_chain_tip` update, which also serializes writers |
| Statistics grouped by `rule_id` alone | Averages two different detectors across a version boundary | Group by `(rule_id, scanner_major_version)` |
| Session-scoped `SET app.tenant_id` | Leaks to the next request under transaction pooling | `SET LOCAL` inside an explicit transaction |
