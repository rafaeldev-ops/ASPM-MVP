# Repository Structure — SDIP

**Deliverable:** CLAUDE.md §46.K
**Date:** 2026-08-15
**Shape:** modular monolith, one image, five entrypoints. No microservices, no service extraction until there is a measurable operational, scaling, ownership or security reason.

---

## 1. Tree

```
sdip/
├── CLAUDE.md
├── README.md
├── pyproject.toml                  # ruff · black · mypy(strict) · pytest · import-linter
├── docker-compose.yml              # postgres+pgvector · redis · minio · api · workers
├── Dockerfile                      # one image; entrypoint selects the process
├── .pre-commit-config.yaml
├── .github/workflows/
│   ├── ci.yml                      # lint · types · unit · integration · contract
│   ├── security.yml                # deps · SAST · secret canaries · SBOM · provenance
│   └── eval.yml                    # nightly full evaluation suite + gates
│
├── app/
│   ├── domain/                     # pure. no I/O, no framework, no SQL.
│   │   ├── organizations/          # Organization, Actor, Membership
│   │   ├── assets/                 # Repository, Service, Asset, Deployment, Ownership
│   │   ├── ingestion/              # ScanRun, Observation, RawPayloadRef  (aggregate)
│   │   ├── findings/               # FindingIdentity, Fingerprint, FindingState (aggregate)
│   │   ├── correlation/            # CorrelationEdge, ClusterMaterialization, IdentityAlias
│   │   ├── evidence/               # Evidence, EvidenceSlot, EvidenceGap, EvidenceDrop,
│   │   │                           #   Conflict, SourceRecord, AdvisorySnapshot, CodeFlow
│   │   ├── decisions/              # DeterministicAssessment, ModelRecommendation,
│   │   │                           #   PolicyDecision, Decision, DecisionRevision (aggregate)
│   │   ├── suppressions/           # Suppression, InvalidationCondition, Scope, ReopenEvent
│   │   ├── knowledge/              # MemoryEntry, Calibrator, OutcomeSignal
│   │   ├── governance/             # Policy, SlaClock, CostBudget
│   │   └── shared/                 # value objects: Fingerprint, Purl, CvssTriple, Severity,
│   │                               #   ContentHash, SecretRef, AuthorityTier, ScopePredicate
│   │
│   ├── application/                # orchestration. depends on domain + ports only.
│   │   ├── ingestion/              # parse → redact → persist → resolve identity
│   │   ├── lifecycle/              # the N-scan absence state machine
│   │   ├── correlation/            # blocking, edges, materialization, promotion
│   │   ├── scoring/                # versioned deterministic risk features
│   │   ├── prefilter/              # deterministic disposition — decides IF a model runs
│   │   ├── retrieval/              # evidence contract, slot filling, hybrid search, budget
│   │   ├── policy/                 # ★ THE DECISION AUTHORITY. deterministic, versioned
│   │   ├── analysis/               # model invocation, grounding validation, differential run
│   │   ├── relitigation/           # ★ delta detection, suppression wake-up, reopen events
│   │   ├── learning/               # revisions, audit sampling, retroactive labels, calibration
│   │   ├── reprocessing/           # versioned recompute, shadow diff, promotion
│   │   ├── reporting/              # decision debt, metrics, exports
│   │   └── ports/                  # Protocol definitions the infrastructure implements
│   │
│   ├── infrastructure/             # the only layer that knows about the outside world
│   │   ├── database/
│   │   │   ├── models/             # SQLAlchemy 2.x mapped classes
│   │   │   ├── repositories/       # org-scoped; the ONLY way to reach the database
│   │   │   ├── session.py          # ★ transaction + SET LOCAL app.tenant_id. no other path
│   │   │   └── rls.py
│   │   ├── cache/redis_client.py   # ★ the ONLY Redis access. enforces t:{org_id}: prefixes
│   │   ├── vector/                 # pgvector queries, iterative-scan config, recall probes
│   │   ├── llm/                    # one provider adapter, structured output, refusal handling
│   │   ├── redaction/              # ★ RawScannerPayload → RedactedFinding. non-serializable
│   │   ├── adapters/               # sarif/ · trivy/ · snyk/ · gitleaks/ · defectdojo_import/
│   │   ├── external_knowledge/     # kev/ · epss/ · osv/ · ghsa/ · snapshots + range diffing
│   │   ├── audit/                  # hash chain, chain-tip serialization, Merkle, TSA anchor
│   │   ├── integrations/           # git providers (post-MVP), jira (post-MVP)
│   │   └── observability/          # metrics, tracing, cost ledger
│   │
│   └── interfaces/
│       ├── api/
│       │   ├── v1/                 # routers mirroring docs/api/openapi.yaml
│       │   ├── auth/               # OIDC, roles, step-up, ingest-token minting
│       │   ├── errors.py           # RFC 9457 problem+json
│       │   └── pagination.py       # keyset cursors only
│       └── workers/
│           ├── ingest.py           # holds tenant credentials · egress: git providers
│           ├── correlate.py        # egress: none
│           ├── analyze.py          # talks to the model provider · egress: provider only
│           └── watch.py            # deltas, freshness, retro labels, SLA · egress: feeds + TSA
│
├── phase0/                         # ★ NOT product code. Validation instruments only.
│   ├── v1_backtest.py              #   ★ THE PARTNER RUNS THIS, not us. 1 file · stdlib ·
│   │                               #     1 network call (KEV) · 1 local HTML out
│   ├── v2_riskmodel.py             #   ★ risk-model.md, EXECUTED. --assert is a CI gate:
│   │                               #     tree must be total, no dead rows, no active→depri
│   ├── v4_corpus.py                #   builds + VALIDATES the 50-finding corpus
│   ├── v4_kappa.py                 #   Fleiss κ, bootstrap CI, gate eligibility
│   ├── v4-corpus-v1.0.json         #   frozen evidence · hashed · reused by V2 and V3
│   ├── v4-corpus-v1.0.md           #   annotation packet
│   └── risk-tree-fixture.json      #   720 combinations · the review artifact for a tree change
│                                   #   Every file: stdlib only, no install step.
│                                   #   Deleted or promoted after the V1 gate; never imported by app/
│
├── alembic/versions/               # 001 … 014 per docs/data/database-model.md §7
│
├── eval/
│   ├── datasets/                   # ★ production-classified. versioned, hashed, canaried
│   │   ├── gs_corr/ gs_ident/ gs_dec/ gs_fn/ gs_evid/ gs_inj/ gs_life/ gs_pref/
│   ├── runners/
│   ├── gates/                      # thresholds as code, reviewed like production code
│   └── reports/
│
├── tests/
│   ├── unit/                       # domain logic: scoring, correlation, normalization, policy
│   ├── integration/                # postgres, redis, pgvector, adapters with fixtures
│   ├── contract/                   # OpenAPI behaviour, auth, idempotency, pagination
│   ├── security/                   # ★ isolation suite, canaries, injection fixtures, RLS gates
│   └── fixtures/                   # ★ never real customer data. CI fails on canary/PII patterns
│
├── web/                            # Next.js · TypeScript · Tailwind · shadcn/ui
│   └── app/                        # findings · decision detail · decision debt · reopen queue
│
├── deploy/
├── scripts/
└── docs/                           # see §5
```

★ marks a location where a rule is enforced structurally rather than by convention. There are eight of them, and they are the eight places a review should be slowest.

---

## 2. The dependency rule

```
interfaces ──► application ──► domain
     │              │
     └──────────────┴──────► infrastructure  (via ports, at composition time only)
```

- **`domain/` imports nothing from the other three layers.** No SQLAlchemy, no FastAPI, no Redis, no HTTP client. It is testable with no I/O.
- **`application/` imports `domain/` and `application/ports/`.** It never imports `infrastructure/` directly; concrete adapters are injected at composition time.
- **`infrastructure/` implements ports.** It may import `domain/` types.
- **`interfaces/` wires everything together** and owns transport concerns only.

**Enforced by `import-linter` in CI, not by review.** A layering rule that only exists in a document is a layering rule that is already violated.

```toml
[[tool.importlinter.contracts]]
name = "layers"
type = "layers"
layers = ["app.interfaces", "app.application", "app.domain"]

[[tool.importlinter.contracts]]
name = "domain is pure"
type = "forbidden"
source_modules = ["app.domain"]
forbidden_modules = ["sqlalchemy", "fastapi", "redis", "httpx", "app.infrastructure"]

[[tool.importlinter.contracts]]
name = "redis only through the wrapper"
type = "forbidden"
source_modules = ["app.domain", "app.application", "app.interfaces"]
forbidden_modules = ["redis"]
```

---

## 3. Where does X go?

| Task | Location | Rule it must respect |
|---|---|---|
| A new scanner | `infrastructure/adapters/<tool>/` | Emits `RedactedFinding` only. SARIF for SAST, native JSON for SCA |
| A new correlation signal | `application/correlation/` + a golden-set case | Never writes a mutable cluster id |
| A new risk feature | `application/scoring/features/` | Bumps `scoring_model_version`; triggers re-score as a tracked job |
| A new decision rule | `application/policy/rules/` | Unit-tested; suppressive rules need an independent deterministic predicate |
| A new evidence source | `infrastructure/external_knowledge/` | Carries authority tier, snapshot, content hash and a version pin |
| A new invalidation condition | `domain/suppressions/` + `application/relitigation/` | Reported precision per trigger; disabled below 40% |
| A prompt change | `infrastructure/llm/prompts/` (versioned, hashed) | Blocked by the full evaluation gate |
| A new API endpoint | `interfaces/api/v1/` + `docs/api/openapi.yaml` | Contract test before merge |
| A new table | `alembic/versions/` | `org_id` first in PK and every index; RLS + FORCE; migration gate |
| Anything touching secrets | `infrastructure/redaction/` | Type boundary + canary test. Second reviewer required |

**Changes to redaction, tenant scoping, decision policy, audit integrity or credential handling require a second reviewer and a security ADR.** That is a CODEOWNERS rule, not a norm.

---

## 4. Runtime

One image, five entrypoints:

```
docker run sdip api          # FastAPI
docker run sdip ingest       # parse · redact · persist
docker run sdip correlate    # blocking · edges · materialize
docker run sdip analyze      # prefilter · evidence · policy · model
docker run sdip watch        # deltas · freshness · retro labels · SLA clocks
```

They share the codebase and differ in **credentials and egress policy**, which is the actual reason they are separate processes:

| Process | Credentials | Egress |
|---|---|---|
| `api` | session verification | none outbound |
| `ingest` | tenant integration credentials, KMS | git providers only |
| `correlate` | none | **none** |
| `analyze` | model provider key | model provider only |
| `watch` | none | public feeds + timestamp authority |

`analyze` processes untrusted content and must be structurally unable to reach the credential store. That property is worth more than the convenience of a single worker.

---

## 5. `docs/` — current state

```
docs/
├── adr/                        18 files — ADR-0001…0017 + README     ✔
├── architecture/
│   ├── critique-architecture.md                                      ✔
│   ├── diagrams.md             §46.J                                 ✔
│   └── repository-structure.md §46.K                                 ✔ (this file)
├── product/
│   ├── critique-product.md                                           ✔
│   ├── competitive-positioning.md  §46.C                             ✔
│   ├── mvp-backlog.md              §46.I                             ✔
│   ├── competitive-teardown.md     living, dated                     ✔
│   └── design-partner-kit.md       V0 recruitment                    ✔
├── data/
│   ├── domain-model.md         §46.E                                 ✔
│   ├── database-model.md       §46.F                                 ✔
│   └── retention.md            §44 — split retention + derived deletion  ✔
├── evaluation/
│   ├── critique-ai-rag.md                                            ✔
│   ├── evaluation-system.md    §46.H                                 ✔
│   ├── phase-0-protocols.md    V0–V6, pre-registered thresholds      ✔
│   ├── v4-annotation-kit.md    corpus · forms · fusion rule          ✔
│   ├── exp-001-epss-model-boundary.md   run 2026-08-16               ✔
│   └── exp-002-risk-model-executed.md   run 2026-08-17               ✔
├── api/
│   ├── README.md               conventions                           ✔
│   └── openapi.yaml            §46.G — validated                     ✔
├── threat-model/
│   ├── critique-security.md                                          ✔
│   ├── threat-model.md         §43 — STRIDE per boundary + ASVS 5.0.0
│   │                                 + LLM Top 10 2026 mapping       ✔
│   └── asvs-verification.md    L2 + 16 named L3, IDs verified        ✔
└── decisions/
    └── risk-model.md           §26 — scoring model, versioned        ✔
```

**The §42 artifact list is complete as of 2026-08-16**, and the design phase is closed. What remains is not documentation:

| Item | Kind | Blocks | Due |
|---|---|---|---|
| **V0 — recruit 5 design partners** | Outreach, 2–3 weeks calendar | **Everything.** It is the long pole and it was missing from the backlog | Start now |
| **V5 — Nucleus Q1–Q4** (`competitive-teardown.md` T-1) | A demo conversation — documentation is exhausted | The pitch | **2026-08-22** |
| V4 — annotation-agreement probe | In-house, no external dependency | The shape of the decision contract | Week 1 |
| V1 — decision-debt backtest | Design-partner work | **Ring 0. Do not start R0-1 before the V1 gate** | 2026-09-30 |
| ADR-0017 | An open decision | The moat narrative, and `retention.md` G11 | Before any cross-tenant claim |
| ASVS released PDF (level definitions) | Verification | External attestation only, not the build | On demand |

Protocols for V0–V6 are in [`docs/evaluation/phase-0-protocols.md`](../evaluation/phase-0-protocols.md), with thresholds pre-registered.

---

## 6. Tooling

| Tool | Configuration that matters |
|---|---|
| **Ruff** | Default plus a custom rule banning raw `redis` and raw `sqlalchemy.create_engine` outside their wrappers |
| **Black** | Default |
| **MyPy** | `strict = true`, no exemptions in `infrastructure/redaction/` or `domain/`. This is load-bearing: it is what makes "we forgot to redact" a build failure |
| **import-linter** | §2 contracts |
| **Pytest** | Markers `unit` / `integration` / `contract` / `security` / `eval` |
| **pre-commit** | Ruff, Black, MyPy, secret scan, **canary-pattern check on fixtures** |
| **Alembic** | Every revision runs the RLS migration gate in CI |
| **Dependencies** | Pinned **by digest**; SBOM published; build provenance attested; releases signed |

**CI is not allowed to be green while any of these fail:** the RLS migration gate, the tenant-isolation suite, the canary scan, or evaluation gates G1 (zero new false negatives), G2 (zero injection-caused suppression) and G3 (zero cross-tenant rows).

---

## 7. What is deliberately absent

| Absent | Why |
|---|---|
| `services/` or per-service repos | Modular monolith. Extract only for a measured reason; `ingest` is the first candidate if one ever appears |
| `graph/` | One polymorphic `edges` table plus a precomputed closure covers the known query set |
| `agents/` | No multi-agent pipeline until it beats both the single-model baseline and the deterministic-only ablation |
| `ml/`, `training/` | Nothing here is trained. Calibrators are two-parameter fits and live in `application/learning/` |
| `providers/{openai,gemini,bedrock,ollama}/` | One provider, one adapter, one fallback. A six-vendor abstraction is a tax that leaks anyway |
| `k8s/`, `terraform/eks/` | Docker Compose locally, a container platform in production. Kubernetes when there is a demonstrated need |
| `kafka/`, `events/streaming/` | Redis-backed workers are sufficient at 1–5M observations/day |
| `pattern_discovery/` | It is a materialized view with an explicit `n`, not a module |
