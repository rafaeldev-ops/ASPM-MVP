# SDIP Architecture Critique — Distributed Systems / Platform / Data Engineering Lens

**Scope:** CLAUDE.md §§8–14, 20–25, read as a build plan for an ingestion + correlation + decision platform.
**Date:** 2026-08-14
**Posture:** adversarial. Strengths are noted only where they change a decision.

---

## 0. Verdict in one page

The brief is unusually disciplined about *what not to build* (no Kafka, no K8s, no graph DB, no multi-agent). That discipline is real and I am not going to relitigate it. The problems are elsewhere, and they are structural:

1. **The primitive is wrong.** §24 makes a mutable canonical finding with `first_seen`/`last_seen` the core object. That model cannot satisfy §25's own requirement ("allow re-correlation as algorithms improve") because it destroys the history you would recompute from. This is the one decision in the brief that is **irreversible** — you cannot retroactively manufacture observation history. Fix before any code. → §5
2. **The cost model is undefined and the range is 44×.** Per-finding LLM analysis at 100k findings/month costs between **$215 and $9,500 per tenant per month** depending entirely on a component the brief does not contain: a deterministic pre-filter. At the high end, COGS exceeds a mid-market ASPM contract. This is a product decision, not an optimization. → §9
3. **Ingestion volume is mis-modelled by ~50×.** The brief reasons in "findings" (10k, 100k). The real quantity is *observations*: a 500-repo org emits 1–5M finding-observations **per day**, of which >99% are byte-identical repeats. Every capacity, cost, and Postgres decision in the brief is sized against the wrong number. → §4
4. **Ten pillars are four services and several tables.** Context Engine, Context Builder, and Evidence Engine are one function. Learning Engine, Pattern Discovery, and Statistical Engine are, at MVP, three materialized views and an append-only table. → §3
5. **The differentiation hypothesis has a data-integrity dependency nobody has named.** §16's organizational statistics (FP rate by rule, recurrence, remediation time) are only meaningful if scanner and rule versions are pinned per observation. Without drift tracking, you are computing averages across incomparable populations and calling it a moat. → §11.3
6. **Commodity already delivers the headline value prop.** Reachability analysis at the scanner layer cuts SCA findings by 92% (Endor Labs) and high/critical false positives by up to 98% (Semgrep) — measured, shipping, 2026. §34's wedge ("we reduce the amount of security work") is a claim those vendors already substantiate with a stronger mechanism than SDIP can run, because SDIP sits *above* the scanner and has no call graph. → §12

Nothing here says don't build. It says the MVP in §36 Phase 1 is about 40% components that should not exist yet and is missing about 10 that must.

---

## 1. Factual baseline corrections

The brief pins nothing and is already stale in three places. §18 explicitly demands version pinning; apply the same rule to every external dependency.

| Brief says | Current as of 2026-08-14 | Consequence |
|---|---|---|
| "EPSS" (§5, §8) | **EPSS v5**, announced 2026-05-13 by Empirical Security; publishing `v2026.06.15` since 2026-06-15. v4 shipped 2025-03-17. | EPSS scores are **not comparable across model versions**. Any historical risk score, calibration curve (§26), or trend chart that mixes v4 and v5 scores is wrong. Store `epss_model_version` with every score, and treat a model-version change as a **global evidence-invalidation event** (§11.7). |
| "ASVS" (§18) | **ASVS 5.0.0**, released 2025-05-30. 4.0.3 is the prior line; chapter numbering changed. | Pin `ASVS 5.0.0` in the threat model and verification docs. A control map written against 4.0.3 numbering will not survive review. |
| "SARIF" (implied by Semgrep/CodeQL) | **SARIF 2.1.0 + Errata 01** (2023-08-28) is the OASIS standard. 2.2 is an open draft; `partialFingerprints` semantics are still under active TC discussion. | Build against 2.1.0. Do **not** assume 2.2 fingerprint guarantees. |

Also: CISA KEV, NVD, and OSV all mutate records in place. §8 says "never present retrieved information as current if its freshness is unknown" — correct, but freshness metadata without an invalidation sweep is decoration. See §11.7.

---

## 2. What the brief gets right (so I don't relitigate it)

- Deferring Kafka, K8s, graph DB, multi-agent. All correct, all for the right stated reasons.
- Modular monolith (§20). Correct. The boundaries in §20 are also mostly the right *module* boundaries — my objection in §3 is that they are being read as *component* boundaries.
- "Do not let the LLM invent a numeric score" (§7). Correct and load-bearing.
- Prefer `needs_review` under low confidence (§27). Correct, and it is also the cost lever — see §9.4.
- Redis-backed workers before anything else (§22). Correct.

---

## 3. The ten-pillar decomposition

**Claim: ten pillars are four runtime services in one deployable, plus a schema.**

| Pillar | What it actually is | Verdict |
|---|---|---|
| **Import** | A real component. Own scaling profile (burst, large payloads), own failure semantics (idempotency, DLQ, admission control), own backpressure needs. | **Real.** Keep. First to extract if you ever extract anything. |
| **Correlation** | A real component. Batch/incremental job with a CPU-bound profile and a re-runnable contract. Different resource shape from everything else. | **Real.** Keep as a worker, not a service. |
| **Context Engine** | §11's flow diagram. | **Collapses.** |
| **Context Builder** | Not in CLAUDE.md as a distinct thing — it is §11's "Evidence Ranking → Context Compression" stages. | **Collapses into Context Engine.** |
| **Evidence Engine** | An `evidence` table + a ranking function + retrieval adapters. | **Collapses into Context Engine.** |
| **Decision Engine** | A real component, but only because it is the thing that spends money and hits rate limits. Its separateness is a *governance* boundary, not a technical one. | **Real.** Keep, for budget/rate-limit isolation. |
| **Memory Graph** | A `nodes`/`edges` schema and some queries. Not a runtime component. | **Not a component. It is a schema.** |
| **Learning Engine** | At MVP: an append-only `decision_revision` table + a nightly aggregate job. | **Premature as an "engine."** |
| **Pattern Discovery** | Requires statistical power that does not exist for 6–12 months per tenant. | **Do not build yet.** |
| **Dashboard** | Frontend. | **Not a backend pillar.** |

**Consequence:** three of the ten (Context Engine / Context Builder / Evidence Engine) are one call:

```
assemble_context(finding_id, policy_version) -> EvidenceBundle
```

Splitting one function into three "engines" means three sets of interfaces, three sets of DTOs, three places to version, and three places where a tenant filter can be forgotten. Every one of those is a real cost and none of them buys anything at MVP.

**The four things that actually run:**

```
api            (FastAPI: ingest endpoints, query, feedback)
ingest-worker  (parse → normalize → persist observations)
correlate-worker (blocking → candidate edges → materialize clusters)
analyze-worker (pre-filter → context assembly → model call → decision)
```

One image, four entrypoints, one Postgres, one Redis. That is the whole MVP topology.

### 3.1 Pattern Discovery specifically: do not build yet

§17 requires every discovered pattern to carry provenance, supporting observations, confidence, lifecycle status, and validation state, plus a "controlled promotion mechanism." That is more machinery than the feature.

The blocking problem is statistical, not architectural. To claim "rule X is a false positive in this org," you need enough *independent, comparably-generated* analyst labels for rule X. In practice: dozens of labelled instances of one rule, generated under one scanner version, by more than one analyst. A pilot tenant produces that for maybe 5–20 rules in the first year. Ship it earlier and it manufactures confident nonsense, which in a security product is worse than shipping nothing — a wrongly-promoted "this rule is always FP" pattern is a systematic false-negative generator, the exact failure mode §33 lists as risk #6.

**Do instead:** a single materialized view, `rule_disposition_stats(org_id, tool, rule_id, scanner_major_version, n_decisions, n_fp, n_tp, first_seen, last_seen)`, surfaced to analysts as *information* with an explicit `n`. No promotion mechanism, no lifecycle, no engine. When some row hits n≥30 and >90% FP, an analyst can act on it. That is the entire feature and it is a view.

---

## 4. Ingestion: what actually breaks

### 4.1 The volume is mis-modelled

§34's worked example ("a customer imports 10,000 findings") describes a **one-time import**, and the whole brief reasons from that shape. The steady-state shape is different by ~50×.

Concrete, per scan:

| Tool | Findings per scan | Notes |
|---|---|---|
| Trivy (fat app image) | 300–2,000 | Base-image OS CVEs dominate; a Debian-based Node image trivially exceeds 800 |
| Checkov (Terraform monorepo) | 1,000–10,000 | |
| Semgrep (`p/default`, medium repo) | 50–500 | |
| SonarQube (legacy codebase) | 1,000s | Mostly non-security; severity mapping is a swamp |
| Gitleaks (full history scan) | 0–5,000 | Enormous variance; history scans are the tail risk |
| Dependabot | 10s | |

A 500-repo org at ~20 pushes/day/repo with image + IaC + SAST + secrets on each:

- **Distinct findings:** 50k–200k
- **Finding-observations:** **1M–5M per day**
- **Fraction byte-identical to the prior scan:** **>99%**

Everything downstream must be sized against observations/day, not findings.

### 4.2 The specific failure at each scale

**10k findings — nothing breaks.** Single Postgres, naive everything. If a design struggles here it is broken, not under-provisioned. This tier is not informative and should not drive any decision.

**100k findings — two things break.**

1. **Naive correlation.** All-pairs on 100k is 5×10⁹ comparisons. At an optimistic 1 µs each, single-threaded, that is **83 minutes**. There is no tuning path; it needs blocking (§6).
2. **Update amplification.** This is the one that actually bites and the brief walks straight into it. §24's canonical finding carries `last_seen`. With a mutable row model, 1M–5M observations/day means **1M–5M UPDATEs/day against a table of ~100k rows** — each row rewritten 10–50× per day.

   Postgres MVCC consequence: every UPDATE writes a new tuple version and leaves a dead one. At ~1 KB/row that is **1–5 GB/day of dead tuples on a ~100 MB table**. HOT updates would mitigate this, but HOT requires that no indexed column change and that the page has free space — and `last_seen` is precisely the column you will index for "show me findings not seen in 7 days." So you get non-HOT updates, index bloat on every index of the table, and autovacuum permanently behind. Symptom: the table's physical size is 50× its logical size, sequential scans get slower every week, and vacuum full needs a maintenance window.

   This is not a tuning problem. It is the data model.

**1M findings/tenant — three more break.**

3. **Re-correlation becomes unschedulable.** A full recompute per tenant is fine (§6.4 quantifies it at 10–20 min). A full recompute across 100 tenants after an algorithm change is 20–30 machine-hours with no progress tracking, no resumability, and no way to compare v1 vs v2 output. The brief has no reprocessing subsystem at all (§11.4).
4. **pgvector index memory.** See §7.
5. **Ingest payload size.** A single SARIF from an unfiltered Checkov or Gitleaks history scan reaches hundreds of MB. §43 lists "denial of service through ingestion" as a threat but §24 specifies no size cap, no streaming parse, and no admission control. A naive `json.load()` on a 500 MB SARIF is ~5–10 GB resident. One misconfigured customer scan OOMs the ingest worker, and because the upload will be retried, it OOMs it repeatedly.

### 4.3 Idempotency — §23 gets this wrong

§23 says contracts must define "idempotency behavior **where applicable**." For scan ingestion it is not "where applicable," it is mandatory and it is the single most-exercised property in the system. CI uploads retry on timeout; a 90-second SARIF import behind a 60-second gateway timeout will be retried by every well-behaved client, guaranteed, on day one.

Required design:

- Client supplies `Idempotency-Key` (or you derive `sha256(payload) + tool + repo + commit`).
- `scan_run` is a first-class row, created **before** parsing, with a unique constraint on that key.
- Retry with the same key returns the existing `scan_run_id` and its status — 200, not 409, and not a second import.
- Import is transactional per scan run, or at minimum has a `status` that distinguishes `partial` from `complete`. A half-imported scan that looks complete will silently mark hundreds of findings "absent → resolved" (§11.1).

### 4.4 Finding identity stability — the concrete problem

Identity is where the whole product lives or dies, and the brief's chosen MVP tool set is worse-equipped than it appears.

| Tool | Fingerprint support | Reality |
|---|---|---|
| CodeQL | `partialFingerprints.primaryLocationLineHash` | Best in class. Computed over whitespace-normalized, line-ending-normalized file content. Survives reformatting and unrelated edits above the finding. |
| Semgrep | Own fingerprint in SARIF | Usable. |
| **Trivy** | **None** | Emits no `partialFingerprints`; this is an open feature request against the project. **You must compute identity yourself.** |
| Gitleaks | Thin | Effectively must compute yourself. |
| Dependabot / Snyk | Native IDs, tool-scoped | Stable within tool, useless across tools. |

So of the brief's own §5 MVP list (Semgrep, Trivy, Gitleaks), **two of three ship no usable fingerprint**. The "just use SARIF fingerprints" plan does not exist.

What actually destabilizes identity, and what to do:

| Perturbation | Naive identity (file+line) | Correct handling |
|---|---|---|
| Code reformatted (prettier/black) | Every finding churns | Normalize whitespace before hashing; hash the *content* of the region, not the line number |
| Unrelated edit above the finding | Line numbers shift → all churn | Never put raw line number in the identity hash |
| File renamed / moved | Total churn | Include a rename-follow pass using git rename detection; identity should survive `git mv` |
| Rule ID renamed by scanner upgrade | Total churn, silently | Requires a rule-alias map + drift detection (§11.3) |
| Same code vendored into 2 repos | Two identities (correct) that must correlate as "same root cause" (a relation, not a merge) | §6 tier 3 |
| Base image bumped | Hundreds of CVE findings resolve + hundreds appear | Package-coordinate identity, not file-path identity |

**Prescription:** identity is a **versioned pure function**, `fingerprint_v{n}(observation) -> bytes`, stored as a column, never as an implicit property of a row. Multiple fingerprint versions coexist on the same observation. That is what makes §25's "re-correlate as algorithms improve" mechanically possible.

---

## 5. The canonical model — right schema, wrong primitive

### 5.1 What SARIF gives you free

Genuinely free, do not rebuild: `tool.driver.{name, version, semanticVersion}`, the full `rules[]` catalogue (id, descriptions, `helpUri`, `defaultConfiguration.level`), `results[].ruleId`, `level`/`kind`, `locations[].physicalLocation.{artifactLocation.uri, region}` including `snippet`, `results[].suppressions` (existing in-tool dismissals), `versionControlProvenance` (repo URI + commit), and — most valuable and most often thrown away — **`results[].codeFlows`**, the ordered taint path.

### 5.2 Where normalization is lossy — specifically

1. **`codeFlows` is the biggest loss and the most valuable evidence.** SARIF represents a taint trace as ordered, nested `threadFlows` of locations. There is no clean single-row relational form, so nearly every aggregator flattens it to the primary location and drops it. But "is this reachable from untrusted input, and by what path" is *exactly* the evidence that makes a SAST triage decision defensible — the thing §1 says the product exists to produce. **Preserve `codeFlows` structurally** (`evidence_code_flow` / `evidence_code_flow_step` tables), not as an opaque JSON blob you cannot rank or cite. If you flatten it, your "evidence-first" positioning is hollow for the entire SAST class.

2. **Severity is a lossy enum cast.** SARIF `level` has four values (`error`/`warning`/`note`/`none`). Trivy natively speaks CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN and loses ordinality on the way into SARIF. Any single canonical `severity` column silently picks a winner. Store `severity_raw` (verbatim string), `severity_normalized`, and `severity_mapping_version` — the last one so a mapping change is detectable rather than a silent rewrite of history.

3. **CVSS has no home in SARIF.** Trivy carries full vectors plus *per-source* scores (NVD, Red Hat, GHSA) in `properties`, and these routinely disagree by 2+ points on the same CVE. A single `cvss_score` column is an unattributed editorial decision. Store `(source, vector, score)` triples.

4. **SCA loses everything that matters.** SARIF has no representation for purl, fixed-version, or dependency path (direct vs transitive, and *which* path). Those three fields are the entire basis of an SCA decision.

   **Therefore: SARIF is the wrong ingestion format for SCA.** Ingest Semgrep/CodeQL via SARIF; ingest Trivy/Snyk via **native JSON**. A "one canonical SARIF pipeline" plan silently discards the dependency graph. This is a concrete, falsifiable design constraint and it contradicts the natural reading of §24.

5. **Multi-location results change counts.** One secret appearing in five files is one result with five locations. Flattening to one location drops four; fanning out to five findings inflates every count and metric in §31.

6. **In-tool suppressions must round-trip.** `results[].suppressions` says a developer already dismissed this in Semgrep/GitHub. Re-surfacing it in SDIP as new is an instant, unrecoverable trust loss with the exact user §6 targets.

### 5.3 The argument: identity + append-only observations, not a mutable canonical finding

**Steelman for the brief's model.** A single canonical row is what every query, list view, and API response needs. Making consumers reconstruct current state from an event log pushes complexity into every reader, and the "just materialize it" answer is a whole extra subsystem.

**Why it still loses.** The canonical finding conflates three things with different lifetimes, different mutation rates, and different correctness requirements:

| Concern | Volume | Mutation rate | Requirement |
|---|---|---|---|
| **Identity** | 100k | Changes only when the fingerprint algorithm version changes | Stable, versioned, recomputable |
| **Observation** | 1–5M/day | **Never** — it is a historical fact | Immutable, append-only, cheap to write |
| **State** | 100k | On decision / lifecycle events (~100s/day) | Mutable, queryable, projected |

Fusing them forces the write pattern of the highest-volume concern onto a table shaped for the lowest-volume one. That is precisely the update-amplification failure in §4.2.

**The five things the split buys, none of which are available retroactively:**

1. **Writes become INSERTs.** Append-only tables partition by time, never bloat, and vacuum trivially. The 1–5 GB/day dead-tuple problem disappears.
2. **§25 becomes mechanically possible.** `fingerprint_v2` can be computed over the *same stored observations*; clusters are re-derived, nothing is destroyed. With a mutable model you have overwritten the inputs and re-correlation of historical data is permanently impossible.
3. **"Absent from scan" becomes representable.** Scan run N contains no observation of identity X. That is a *fact* the lifecycle machine (§11.1) can act on. In a mutable model, "gone" and "never happened" are indistinguishable — which is how platforms silently auto-close real vulnerabilities.
4. **Scanner drift becomes visible** (§11.3): same identity, different `scanner_version`, different attributes.
5. **Audit is free.** §23 wants audit history and §8 wants "what did we know at decision time." Over observations that is a timestamp filter. Over mutable rows it is a second, parallel, hand-maintained audit log that will drift from the primary.

**Resolution — keep the canonical schema, demote it from primitive:**

```
finding_identity(id, org_id, fingerprint_version, fingerprint, class, first_observed_at)
observation(id, org_id, scan_run_id, identity_id, observed_at,
            tool, tool_version, rule_id, rule_version,
            <canonical attributes>, raw_payload_ref)          -- APPEND ONLY
finding_state(identity_id, org_id, status, current_decision_id,
              last_observed_at, updated_at)                    -- projection
```

The §24 canonical attribute list is *correct and should be kept verbatim* — it becomes the shape of the attributes carried on an observation and projected into state. This is a standard fact/dimension split (a metric point vs. a metric series; an event vs. an entity). It is not exotic and it is not event sourcing.

**Why this is the one thing to decide before writing code:** every other decision in this document is reversible at some cost. This one is not. Ship the mutable model for twelve months and the pre-change history does not exist to recompute from — §25 becomes permanently unachievable for all data collected before the fix, and the accumulated-decision-history moat (§4) starts from zero on the day you fix it.

---

## 6. Correlation: the actual algorithm

The brief lists ten correlation *signals* (§25) and zero algorithms. Here is the algorithm and its complexity.

### 6.1 Never all-pairs

n=100k → 5×10⁹ pairs (≈83 min at 1 µs). n=1M → 5×10¹¹ (≈5.8 days). Not a tuning problem.

### 6.2 Four tiers

**Tier 0 — exact identity (hash join, O(n)).** `fingerprint` equality. Absorbs ~99% of re-scan volume. This is not "correlation," it is the observation→identity resolution that happens on ingest. Doing this tier at ingest time is what keeps the correlation worker's input small.

**Tier 1 — blocking (equi-join, O(n)).** Candidates are generated *only* within blocks. Never compare across blocks.

| Finding class | Blocking key | Why it works |
|---|---|---|
| SCA | `(purl_name, purl_version)` and `(cve_id)` | Package coordinates are near-perfect keys |
| SAST | `(repo_id, cwe_normalized, dirname(file_path))` | Cross-tool SAST agreement is at CWE+location granularity, not rule granularity |
| Secrets | `(secret_hash_prefix, repo_id)` | Never block on the secret itself; store only a keyed hash |
| Container | `(image_digest, package_name)` | |

**Tier 2 — in-block scoring (O(Σ bᵢ²), bounded).** Weighted similarity over §25's signals *inside* a block only.

> **The block-size cap is the load-bearing detail.** One pathological block — every finding under `vendor/`, or every CVE in a shared base image — reintroduces O(n²) inside a single block and hangs the worker. Enforce a hard cap `B` (start at 200). A block exceeding `B` must be **skipped and alerted**, never processed. With `B=200`, n=1M: ≤2×10⁸ comparisons — minutes, not days.

**Tier 3 — LSH/MinHash over normalized code snippets.** This is the *only* place LSH earns its cost: detecting the same vulnerable code copy-pasted or vendored across repos, where no shared key exists. It is also the least valuable tier at MVP. **Defer past MVP.** If you build LSH before you have blocking working, you have chosen the sophisticated part over the load-bearing part.

### 6.3 The union-find / §25 conflict, and its resolution

§25 says "do not merge findings irreversibly." Naive union-find is exactly an irreversible merge — once you write a `cluster_id` onto a finding row, the pre-merge state is gone.

**Resolution: never persist cluster membership as mutable state.**

```
correlation_edge(org_id, a_identity_id, b_identity_id,
                 relation,        -- exact_duplicate | same_root_cause | related | suspected
                 confidence, algorithm_version, evidence_json, created_at)   -- APPEND ONLY

correlation_cluster_materialized(org_id, algorithm_version, identity_id, cluster_id)
```

Union-find then runs **in memory at materialization time** (near-linear with path compression), producing a *versioned* materialization. Algorithm v2 inserts new edges at `algorithm_version=2` and materializes alongside v1. You can diff v1 vs v2 cluster assignments, shadow-run v2 for a week, measure against the golden set (§29), and promote by flipping which materialization the API reads. Nothing is ever destroyed.

This is the design that makes §25 true rather than aspirational, and it is not the obvious one.

### 6.4 Batch vs streaming vs incremental

**Incremental by default, with periodic full recompute.** Not streaming (the brief is right to skip Kafka), not pure batch (CI needs a decision in minutes, not overnight).

- New observation → resolve identity (tier 0) → generate candidates against existing blocks (tiers 1–2) → emit edges. Bounded, small.
- Algorithm change → full recompute, per tenant, as a tracked job.

Full recompute cost at 1M findings with blocking: **10–20 min of one worker**. Across 100 tenants: 20–30 machine-hours. That is fine *as a scheduled job* and impossible *as an ad-hoc script* — which is why §11.4 (reprocessing orchestration) is a required missing component, not a nice-to-have.

---

## 7. Postgres + pgvector: where the first real wall is

### 7.1 The wall is not vectors

Ranked by what actually fails first:

| # | Wall | Trigger | Fix |
|---|---|---|---|
| 1 | **Update amplification / table bloat** | ~1M observations/day (§4.2) | Append-only model (§5.3). Architectural, not operational. |
| 2 | **Correlation CPU** | ~100k findings | Blocking (§6). Architectural. |
| 3 | **LLM cost** | ~10k analyzed findings/month | Pre-filter (§9). Product decision. |
| 4 | **pgvector memory** | ~1–5M vectors | Real, but the *fourth* wall, and mostly solvable |
| 5 | Connection/CPU saturation | Later, and boring | Read replica, PgBouncer |

The brief (and the industry) treats vector search as the scaling story. For this workload it is fourth, and walls 1–3 will have killed you first. Budget engineering attention accordingly.

### 7.2 pgvector, quantified

Current guidance, 2026:

- **HNSW is the correct default** below ~5M vectors: 5–50 ms query latency on a tuned index, ~30× better throughput and p99 than IVFFlat at equal recall.
- **HNSW costs ~4× the memory** of IVFFlat at 1M vectors.
- **IVFFlat only past ~50M vectors**, or when memory is the binding constraint. IVFFlat also requires rebuilds as data distribution shifts — bad for a continuously-ingesting corpus.
- Sane starting point: `m=16, ef_construction=64`, tune `ef_search` against a recall target.

**Concrete sizing for SDIP.** What do you actually embed? Not findings — finding text is templated and near-duplicate, so embedding 1M findings produces 1M nearly-identical vectors and a retrieval layer that returns noise. Embed the things with real semantic variance: **analyst decision rationales**, **remediation notes**, and **external advisory prose**. That is 10k–100k vectors per tenant in year one, not millions.

At 768 dimensions: 100k vectors ≈ 300 MB raw; HNSW index ≈ 1.2–1.5 GB resident. Comfortable. At 5M vectors: 15 GB raw, ~60 GB index — you are buying a large memory instance for the index alone.

**This reframes the decision:** the pgvector wall is ~2–3 years away *if you embed selectively*, and ~6 months away *if you reflexively embed every finding*. The architectural choice that matters is **what you embed**, not which index type.

### 7.3 The tenant-filter recall trap — the part that will actually bite

This is a correctness bug that presents as a quality complaint, and it is the pgvector failure mode most likely to hit SDIP given §19.

A query `ORDER BY embedding <=> $1 WHERE org_id = 42 LIMIT 10` against a shared HNSW index walks the graph, collects candidates, *then* applies the filter. If org 42 holds 0.5% of rows, nearly every candidate is discarded and the query silently returns 2 rows instead of 10 — **no error, just degraded recall**. Your smallest tenants get the worst retrieval, and they are the ones on a pilot deciding whether to buy.

pgvector 0.8 addresses this with **iterative index scans**: keep pulling candidates until enough rows pass the filter, bounded by `hnsw.max_scan_tuples`. It works, at the cost of CPU and tail latency, and it still returns short when the bound is hit.

**Required:**
- pgvector **≥ 0.8**, pinned; iterative scans enabled; `hnsw.max_scan_tuples` explicitly set, not defaulted.
- Decide `strict_order` vs `relaxed_order` deliberately — relaxed is usually right for RAG.
- A **recall regression test per tenant-size class** (tiny / medium / large) in the §12 evaluation harness. Without it this degrades silently and you find out from a customer.
- Past a tenant-count threshold, move to **partitioned per-tenant indexes**. Note this is an *index topology* change, which is why it is expensive to retrofit (§10).

### 7.4 Lexical search

§9.3 says Postgres FTS first. Agreed. One concrete caveat: default `tsvector` tokenization mangles the tokens that matter here — `CVE-2024-1234`, `com.fasterxml.jackson.core:jackson-databind`, `python.lang.security.audit.*`. Use a `simple` configuration plus explicit trigram indexes (`pg_trgm`) for identifier-shaped fields, and do not let anyone benchmark "Postgres FTS is bad" against the default English stemmer on CVE IDs.

---

## 8. "Memory Graph in Postgres, graph-DB-ready later" — half true, and say which half

**The honest answer: the *data* migration is cheap. The *query* migration is the actual project. The brief implies both are cheap.**

You do not migrate data to a graph database; you migrate *queries*. Every recursive CTE must be rewritten in Cypher/Gremlin, revalidated for semantic equivalence, and re-benchmarked. With a clean schema the export is a weekend; the query rewrite and revalidation is the multi-month piece. §10 should say this explicitly so nobody budgets it as a data migration.

### 8.1 Schema choices that make it cheap vs expensive

| Cheap | Expensive |
|---|---|
| A **single polymorphic `edges` table**: `(org_id, src_type, src_id, dst_type, dst_id, rel_type, confidence, provenance, inferred, algorithm_version, valid_from, valid_to)` | Per-relationship join tables. Twelve tables → twelve bespoke exporters. |
| **Opaque, stable, global IDs** (UUID/ULID) on every node | Composite natural keys, or IDs only unique within a type — the exporter cannot resolve `src_id` without type dispatch |
| Relationships as **explicit edge rows** | Relationships as **FK columns on entity tables** (`finding.repository_id`). These are invisible to a generic exporter and must be hand-translated one column at a time. **This is the single most common way the "graph-ready" claim becomes false.** |
| Temporal validity on the edge (`valid_from`/`valid_to`) | Temporal semantics in application code |
| `inferred` + `confidence` + `algorithm_version` on every edge (§10 already requires this — good) | Inferred and authoritative edges indistinguishable |

§10's bullet list is right. The failure mode is that a team writes those bullets, then implements relationships as FKs because that is what SQLAlchemy makes easy, and discovers in year two that the "graph-ready" schema has ~40 relationships encoded as FK columns and 6 as edges.

### 8.2 Traversals Postgres genuinely will not serve

Postgres's recursive executor is an iterative set processor, not a traversal engine: it **cannot maintain visited state across iterations**, cannot prune already-explored nodes mid-walk, and collapses duplicates only at the end. That single property determines everything below.

| Traversal | Depth × fanout | Postgres verdict |
|---|---|---|
| finding → repo → owner | 2 × ~1 | Fine forever. Milliseconds. |
| finding → CVE → package → affected versions | 3 × small | Fine. |
| repo → service → deployment → environment | 3–4 × small | Fine. Tens of millions of edges, sub-second. |
| "Which analyst decisions cite this evidence" | 2 × moderate | Fine — it is a join, not a traversal. |
| **"Which internet-exposed services transitively depend on a package with a KEV CVE"** | **5–8 × fanout 20–100** | **Will not serve.** At depth 5, fanout 50, the frontier is ~3×10⁸ rows *before* dedup, all materialized because visited-state cannot be pruned. Times out or OOMs. |
| **Attack-chain discovery** (§17) | variable depth, high fanout | Same failure. |

**The important part: the answer is not Neo4j.** For the one class that fails, you do not need general graph traversal — you need *one specific transitive relation* answered fast. Precompute it:

```
dependency_closure(org_id, root_component_id, reachable_component_id, min_depth, computed_at)
```

Refreshed on dependency-graph change (which is infrequent — lockfile commits, not every scan). That turns the 5–8 hop traversal into a single indexed lookup, costs one materialization job, and is ~10× cheaper than operating a second database with its own backup, HA, auth, and tenant-isolation story.

**Write this down as the position:** SDIP will not need a graph database for the queries it actually has. It needs one polymorphic edge table and one precomputed closure. Deferring the graph DB is not a compromise being tolerated; it is the correct end state. That is a stronger claim than §10 currently makes, and it is defensible.

---

## 9. Cost model: the first-order product question

**This is not an optimization detail. It determines whether the product has a viable gross margin, and the brief does not contain the component that decides it.**

### 9.1 Assumptions (stated so they can be attacked)

Per-finding evidence-first decision prompt, per §7/§8/§11:

| Component | Tokens |
|---|---|
| System prompt + decision schema + scoring rubric (stable, cacheable) | 2,000 |
| Normalized finding + raw payload excerpt | 800 |
| Retrieved evidence: 8–15 chunks × ~400 (CVE, CWE, EPSS, KEV, advisories, org history, prior decisions, contradicting evidence) | 5,000 |
| Code context / snippet / `codeFlows` excerpt | 1,200 |
| **Input total** | **~9,000** |
| Output: decision object + `reasoning_summary` + evidence IDs | ~600 |
| Thinking tokens (Opus 5, adaptive, on by default, judgment task) | ~1,400 |

Pricing, current: **Opus 5 $5/$25**, **Sonnet 5 $3/$15**, **Haiku 4.5 $1/$5** per MTok in/out. Batch API = **50%** off. Prompt cache reads ≈ **0.1×**, writes 1.25×.

### 9.2 Three scenarios at 100k findings/month, one tenant

**A — Naive: Opus 5, every finding, no caching, no batch**

```
input:  9,000 × 100,000 = 900M tok × $5/MTok  = $4,500
output: 2,000 × 100,000 = 200M tok × $25/MTok = $5,000
                                       TOTAL  = $9,500 / tenant / month
```

**B — Sonnet 5 + prompt caching + Batch API**

Cacheable prefix is 2,000 tok (above Sonnet 5's 1,024-tok minimum). Effective input = 7,000 + (2,000 × 0.1) = 7,200.

```
input:  7,200 × 100,000 = 720M × $3  × 0.5 = $1,080
output:   800 × 100,000 =  80M × $15 × 0.5 =   $600
                                     TOTAL = $1,680 / tenant / month
```

**C — Deterministic pre-filter + tiered models (the recommendation)**

```
100,000 raw observations-of-record
  → dedup/correlation removes 40%                    → 60,000
  → deterministic disposition removes 80% of those   → 12,000 reach any model
       (rules: not in KEV AND epss < 0.01 AND not reachable;
        dev-only dependency; fingerprint matches a previously
        accepted FP; severity below policy floor)
  → 12,000 classified by Haiku 4.5 (batch)
  → 1,500 genuinely ambiguous / high-stakes → Opus 5

Haiku tier:  9,000 × 12,000 = 108M × $1  × 0.5 = $54
              600 × 12,000 = 7.2M × $5  × 0.5 = $18
Opus tier:   9,000 ×  1,500 = 13.5M × $5       = $67.50
             2,000 ×  1,500 =   3M × $25       = $75
                                        TOTAL ≈ $215 / tenant / month
```

### 9.3 The conclusion

**$9,500 → $1,680 → $215. A 44× spread, driven almost entirely by a component the brief does not have.**

Scenario A does not clear a mid-market ASPM contract (roughly $2.5k–6.6k/month), so **naive per-finding LLM analysis has negative gross margin**. Scenario C is >95% margin. The delta is not model selection, prompt engineering, or caching — those move it 5.7×. The pre-filter moves it 7.8× more, and it is deterministic code.

**Therefore: per-finding LLM analysis is not economically viable as an architecture. A deterministic pre-filter is a load-bearing structural component, not an optimization.** It belongs in §11 as a named stage between Correlation and Context Assembly, and in the §36 Phase 1 deliverables.

This also happens to be the safer design on §33's risk #6 (false negatives): a deterministic rule that deprioritizes is auditable, versionable, and testable against a golden set. A model that deprioritizes is none of those.

### 9.4 The multiplier nobody has costed: re-analysis

§23 exposes reanalysis endpoints; §26 versions the scoring model; §11.7 (below) requires evidence invalidation. Every one of those re-triggers analysis.

If findings are re-analyzed on each scan rather than on material change, daily CI multiplies every number above by **~30**. Scenario B becomes $50k/month/tenant. That is the actual failure mode — not the first pass.

**Required control — a materiality gate.** Re-invoke the model only when `sha256(canonical(evidence_bundle) || scoring_model_version || prompt_version)` changes. An unchanged bundle returns the cached decision with a new `valid_as_of`. Without this gate the cost model is unbounded and no amount of per-call optimization saves it.

Corollary: this gate is *also* the §30 evaluation gate's foundation — an unchanged bundle producing a different decision is a non-determinism bug you want to detect.

### 9.5 A pricing consequence worth flagging to the product side

§35 lists pricing dimensions including "findings volume" and "analysis volume." Under scenario C, **COGS is driven by the number of findings that survive the pre-filter, not the number ingested.** Pricing per ingested finding while COGS scales with survivors means the customers with the noisiest scanners (highest ingested count, lowest survivor rate) are the most profitable, and the customers with well-tuned scanners subsidize nothing. That is backwards from the value story ("we reduce your work"). Price on repos or developers, not on findings.

---

## 10. Multi-tenancy retrofit cost, quantified

§19 says design the boundaries now and implement later. The boundaries are cheap; two specific things are not, and neither is a boundary.

**Cost now (day 1): ~1–2 engineer-weeks.**
- `org_id UUID NOT NULL` as the **first column of every primary key and every index**
- RLS enabled on every table from migration #1, even while single-tenant, driven by a session GUC
- One cache wrapper; no component touches Redis directly
- One integration test that enumerates `information_schema.tables` and fails on any table missing `org_id` or an RLS policy

**Cost at month 12: ~3–6 engineer-months plus an unbounded security review.** Where it goes:

| Item | Cost |
|---|---|
| Backfill `org_id` across ~25 tables, nullable → NOT NULL | Online migrations on multi-million-row tables; each is a rewrite + index rebuild. Days of wall-clock, plus rollback plans. |
| Rebuild every index with `org_id` leading | Without it the index is not selective and every tenant-scoped query degrades. More rewrites. |
| **Re-embed and rebuild vector indexes** | A shared HNSW index over a mixed-tenant corpus cannot be un-mixed. The dollar cost of re-embedding is small; the cost is the **index topology change** (shared → per-tenant partitioned), which changes your latency and memory profile and therefore your instance sizing. HNSW build on 1M vectors is tens of minutes to hours, per partition. |
| Backfill statistical aggregates | Every §16 metric computed over a mixed corpus is wrong and must be recomputed from source. If you did not keep the source (see §5.3), it cannot be. |
| Security review | Unbounded, and the finding you fear is not in the code. |

**The two that are genuinely expensive, and why:**

1. **Embeddings.** Row-level scoping is a `WHERE`. Vector scoping is an *index topology decision* (§7.3): shared index + filter has a silent recall cliff; per-tenant indexes have a memory cliff. Choosing late means re-embedding *and* re-architecting retrieval *and* re-tuning `ef_search` per class *and* re-running the whole §12 retrieval evaluation. This is the single most expensive retrofit in the system.

2. **Caches — and this is the one that ends the company.** A Redis key like `evidence:cve-2024-1234` looks tenant-neutral. It is not: under §8 an evidence bundle includes org-specific context (prior decisions, asset criticality, compensating controls). Serving org B a bundle assembled for org A is a **cross-tenant data leak with no error, no exception, and no log line** — just a plausible answer containing another customer's security posture. It will be found by a customer's auditor, in a security product, and §33's risk list does not have a line for that because it is not a business risk, it is an extinction event.

**Prescription:** every cache key is `t:{org_id}:{...}`, enforced by a single wrapper with no raw client access anywhere in the codebase, plus a lint rule. That is an afternoon on day 1.

**Bottom line: ~2 weeks now vs. ~4 engineer-months later, and the later path carries a non-recoverable risk.** Build tenancy on day 1. This is the clearest cost/benefit call in the document.

---

## 11. Missing components

Not "underspecified" — **absent**, and each one is load-bearing.

### 11.1 Finding lifecycle state machine — highest priority

§7 defines `decision` values. There is **no finding state**. These are different axes and conflating them is a category error: `prioritize` is an opinion; `open` is a fact.

Required states: `open → reopened → remediated → not_present → suppressed → expired → superseded`.

**The dangerous case is `not_present`.** A finding absent from the latest scan may be: fixed; the file moved; the scanner version changed and the rule no longer fires; the scan config changed; the scan *failed and imported partially* (§4.3). Treating absence as "fixed" mass-auto-resolves real vulnerabilities silently. This is §33's risk #6 realized at scale, and it is the single most damaging bug this class of product ships.

Rules: transition to `not_present` only after N consecutive *successful, comparably-scoped* scan runs (compare `scan_run.scope_hash` and `scanner_version`, not just scan presence). `not_present` ≠ `remediated`; only evidence of a fix (or an analyst) produces `remediated`.

This is only expressible over append-only observations (§5.3). Another reason that decision comes first.

### 11.2 Scan run as a first-class entity
Needed by §11.1, §4.3, and §11.3. `scan_run(id, org_id, tool, tool_version, ruleset_version, ruleset_hash, repo_id, commit_sha, scope_hash, started_at, completed_at, status, finding_count, idempotency_key)`. Without it you cannot distinguish "no findings" from "scan failed."

### 11.3 Scanner and rule version drift — this one guards the moat

Semgrep rule `python.lang.security.audit.foo` v1.2 → v1.3 changes its logic. Same code, different finding. Trivy DB updates change CVE→package matching daily. Base image changes shift hundreds of findings at once.

**Consequence for the core thesis:** §16's organizational statistics — FP rate by rule, recurrence, remediation time — are the claimed moat (§4). Computed across a rule-version boundary, they average two different detectors and report a number that describes nothing. The moat is then built on a metric that is quietly meaningless, and the failure is invisible because the number still looks reasonable.

**Required:** `(tool_version, rule_version, ruleset_hash)` on every observation; a rule-alias map for renames; a drift detector that flags "rule X's finding population changed >30% across a version boundary" and **segments the statistics** rather than pooling them. Every §16 metric is reported per `(rule_id, scanner_major_version)` or it is not reported.

### 11.4 Reprocessing / backfill orchestration
§25 requires re-correlation; §26 versions scoring; §11.7 invalidates evidence. All three need the same subsystem and none of them has it: a job with progress, resumability, per-tenant scoping, rate limiting against the primary workload, **versioned output written alongside the current version**, a shadow-mode diff, and a promotion step. Without it, "re-correlate as algorithms improve" is a script someone runs in tmux and hopes about.

### 11.5 Suppression / exception management with expiry
§7 has `accepted_risk` as a decision value and nothing else. Missing: expiry (accepted risk without a TTL is permanent silent debt — and it is the thing auditors ask about first), approver identity, justification, **scope** (this finding / this rule in this repo / this CVE org-wide / this package everywhere), and re-review triggers on scope change. Scope is a genuinely hard modelling problem — an org-wide CVE suppression must automatically apply to findings that do not exist yet — and it is entirely absent.

### 11.6 Policy / SLA engine
Every buyer asks "show me criticals older than 30 days," and PCI DSS 4.0 / FedRAMP mandate remediation SLAs. No policy object, no SLA clock, no breach detection, no exception workflow. This is a top-three deal-closing capability in this market and it is not in the brief at all. It is also cheap: a policy table, a clock, and a scheduled evaluator.

### 11.7 Evidence freshness invalidation
§8 requires freshness metadata. Metadata without a sweep is decoration. NVD re-scores CVEs; EPSS republishes daily and changed *model version* in June 2026 (§1); KEV adds entries. A decision made at EPSS 0.02, still displayed when EPSS is 0.7, is exactly the "convincing but wrong" failure in §33 risk #7.

Required: content-hash every evidence record; a nightly sweep that re-hashes external evidence and flags dependent decisions `evidence_stale`; a re-analysis trigger gated by §9.4's materiality check.

### 11.8 Ownership resolution
§31 makes "% findings with resolved ownership" a headline metric. No component computes it. It needs CODEOWNERS + service catalog + git history + org chart, with confidence and a manual override. Unglamorous, high value, and the precondition for §6's "who owns it" question.

### 11.9 Ingestion admission control
§43 names DoS-by-ingestion as a threat; §24 specifies no defense. Required: per-tenant upload rate and size quotas, hard payload cap, streaming parse (never `json.load()` a customer file), per-finding validation with a poison-record DLQ so one bad record does not fail a 50k import, and a circuit breaker on repeated OOM from the same tenant.

### 11.10 Deterministic pre-filter
See §9. Structural, not optional.

### 11.11 Data retention and deletion mechanics
§44 says "define retention policy." The policy is the easy half. The mechanics: deleting one repo's findings must cascade through observations, evidence, embeddings, vector index entries, decisions, **and the statistical aggregates computed from them**. Once a decision has contributed to an aggregate and an embedding, GDPR/contractual erasure is architecturally hard — you must either recompute aggregates from surviving source or accept that deleted data still influences outputs. Design now; it is the second-most-expensive retrofit after tenancy.

### 11.12 Per-tenant cost and rate budget
§28 tracks LLM cost. Tracking is not control. One tenant bulk-importing 5M findings must not consume the org's entire model rate limit or a month of margin. Required: per-tenant token budget, queue priority, and a degradation mode (fall back to deterministic-only, mark results `deferred`) rather than an outage.

---

## 12. The competitive fact that should reshape the wedge

§4 correctly says correlation, dedup, EPSS/KEV enrichment, and AI triage are commodity. It understates the problem.

**Reachability analysis at the scanner layer cuts SCA findings by 92% (Endor Labs, function-level call-graph reachability) and reduces high/critical false positives by up to 98% (Semgrep).** Shipping, measured, 2026.

§34's wedge — "we reduce the amount of security work your team needs to do" — is precisely what those numbers already claim, delivered by a *stronger mechanism*: static call-graph analysis is deterministic, explainable, and cheap, versus retrieval-plus-LLM which is probabilistic, expensive, and requires exactly the trust §32 says must be earned.

And SDIP structurally cannot compete on that axis. Reachability requires the call graph. SDIP sits above the scanner and consumes its output; it never sees the code deeply enough to compute one. Absent a customer already running a reachability-capable scanner, SDIP's noise reduction ceiling is dedup + org-history matching — meaningfully lower than 92%.

**Three implications:**

1. **Do not benchmark against raw scanner output.** A pilot that shows "we cut 10,000 findings to 1,000" is unimpressive to a buyer whose SCA vendor already does 92% — and dishonest if their scanner has reachability off. Benchmark against *their current post-scanner triage process*, on **analyst hours**, which is what §31's north-star metric already correctly says.
2. **Ingest reachability as evidence, do not compete with it.** Semgrep and Endor both emit reachability verdicts. That is a first-class evidence type with high reliability — and it is the strongest possible input to §9's deterministic pre-filter. "Not reachable" is the highest-precision auto-deprioritize rule available, it costs zero tokens, and it makes scenario C's 80% deterministic disposition realistic rather than optimistic.
3. **The defensible ground is the part nobody else has:** cross-tool decision memory, the audit trail of *why*, and SLA/exception governance (§11.5, §11.6). Not noise reduction. §4 already gestures at this; the reachability numbers make it a requirement rather than a preference.

---

## 13. Revised MVP shape

**Cut from §36 Phase 1:** Pattern Discovery, Learning Engine as a subsystem, statistical engine as a service, GraphRAG readiness abstractions, contradictory-evidence as a separate retrieval pass (make it a ranking-time requirement — a second retrieval pass doubles cost for an unvalidated benefit), multi-vendor LLM abstraction (one provider; thinking config, structured-output, and cache semantics differ enough per vendor that the abstraction leaks anyway), LSH/MinHash, attack-path analysis.

**Add to Phase 1 (all from §11):** finding lifecycle state machine, scan run entity, scanner/rule version drift tracking, deterministic pre-filter, idempotent ingest with admission control, suppression with expiry, reprocessing orchestration (minimal: versioned output + shadow diff), ownership resolution, per-tenant cost budget.

**Keep and do first, in order:**

1. Append-only observation model + versioned fingerprint (§5.3) — *irreversible, do it first*
2. Tenancy: `org_id` + RLS + prefixed cache keys (§10) — *2 weeks now vs 4 months later*
3. Idempotent ingest + scan run + admission control (§4.3, §11.2, §11.9)
4. Tier 0/1/2 correlation with append-only edges + versioned materialization (§6)
5. Deterministic pre-filter + risk feature computation (§9, §26)
6. Evidence assembly (one function) + single-model decision with materiality gate (§9.4)
7. Analyst feedback as append-only revisions (no "learning engine")
8. Evaluation harness with golden sets *before* step 6 ships (§29, §30)

---

## 14. ADRs this critique requires

| # | Decision | Why it must be an ADR |
|---|---|---|
| 1 | **Append-only observations + versioned identity as the primitive**; canonical schema demoted to attribute shape | The only irreversible decision in the system |
| 2 | **SARIF for SAST, native JSON for SCA**; `codeFlows` preserved structurally | Contradicts the natural reading of §24; determines evidence quality for two whole finding classes |
| 3 | **Correlation via blocking + append-only edges + versioned materialization**; hard block-size cap; no persisted mutable clusters | The only design that makes §25 true rather than aspirational |
| 4 | **Deterministic pre-filter is structural**; model invocation is the exception, gated by evidence-bundle materiality hash | 44× cost swing; determines gross margin |
| 5 | **Full tenancy on day 1** (org_id-leading PKs/indexes, RLS, prefixed cache keys) | 2 weeks vs 4 months, plus non-recoverable leak risk |
| 6 | **No graph database, ever, for the known query set**; one polymorphic edge table + precomputed dependency closure | Stronger and more defensible than §10's "defer"; needs the closure decision recorded |
| 7 | **Selective embedding** (decisions/rationales/advisories, not findings); pgvector ≥0.8 with iterative scans; per-tenant index topology threshold | Moves the vector wall from ~6 months to ~2–3 years |
| 8 | **Version pinning for external knowledge** (EPSS model version, ASVS 5.0.0, SARIF 2.1.0+errata01, NVD/KEV snapshot dates) + invalidation on version change | EPSS v4→v5 already breaks score comparability across the brief's own history |
| 9 | **Finding lifecycle ≠ decision**; `not_present` requires N comparably-scoped successful scans | Prevents silent mass auto-resolution — the worst failure this product class ships |
| 10 | **Statistics segmented by scanner major version** | Without it, the §4 moat metric is meaningless and the failure is invisible |

---

## Sources

- [pgvector performance benchmarks — Instaclustr](https://www.instaclustr.com/education/vector-database/pgvector-performance-benchmark-results-and-5-ways-to-boost-performance/)
- [HNSW vs IVFFlat: choosing a vector index](https://bigdataboutique.com/blog/hnsw-vs-ivfflat-how-to-choose-the-right-vector-index)
- [Scaling vector search in Postgres: memory, filtering, hybrid — ClickHouse](https://clickhouse.com/resources/engineering/scale-vector-search-postgres)
- [pgvector 0.8.0 iterative index scans — Nile](https://www.thenile.dev/blog/pgvector-080)
- [pgvector limitations — ParadeDB](https://www.paradedb.com/learn/postgresql/pgvector-limitations)
- [Filtered HNSW / segment-level indexes — pgvector issue #980](https://github.com/pgvector/pgvector/issues/980)
- [Graph queries with recursive CTEs](https://medium.com/codex/graph-queries-with-recursive-ctes-you-dont-need-neo4j-3aade6fb7f85)
- [Postgres vs Neo4j — PuppyGraph](https://www.puppygraph.com/learn/postgres-vs-neo4j)
- [OWASP ASVS project (5.0.0)](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP ASVS releases](https://github.com/OWASP/ASVS/releases)
- [EPSS data and model versions — FIRST](https://www.first.org/epss/data)
- [Empirical Security releases EPSS V5](https://natlawreview.com/press-releases/empirical-security-releases-epss-v5)
- [SARIF 2.1.0 plus Errata 01 — OASIS](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [SARIF support for code scanning — GitHub Docs](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)
- [CodeQL primaryLocationLineHash generation](https://github.com/github/codeql/discussions/5982)
- [Add partialFingerprints to Trivy SARIF output — discussion #9070](https://github.com/aquasecurity/trivy/discussions/9070)
- [DefectDojo deduplication algorithms](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/deduplication_algorithms/)
- [DefectDojo about deduplication](https://docs.defectdojo.com/triage_findings/finding_deduplication/about_deduplication/)
- [Reachability-driven SCA — Endor Labs](https://www.endorlabs.com/use-case/reachability-sca)
- [Semgrep reachability analysis whitepaper](https://semgrep.dev/assets/content/whitepapers/semgrep-reachabilityanalysis-whitepaper-1225.pdf)
- [Best ASPM tools 2026 — Orca Security](https://orca.security/resources/blog/best-aspm-tools/)
- [ASPM tools buyer's guide 2026](https://appsecsanta.com/aspm-tools)
- Model pricing (Opus 5 $5/$25, Sonnet 5 $3/$15, Haiku 4.5 $1/$5 per MTok; Batch API 50%; cache reads ~0.1×) — Anthropic model catalogue, cached 2026-06-24
