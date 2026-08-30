# Architecture Decision Records — SDIP

**Deliverable:** CLAUDE.md §46.D · **Policy:** CLAUDE.md §38 · **Created:** 2026-08-14

## Purpose

These ADRs record the decisions that the four critique documents in this repository established as material. They are written **before implementation**, per CLAUDE.md §40, and each one answers the six questions in §37.

An ADR exists here only if the decision is (a) hard to reverse, (b) contested by a reasonable alternative, or (c) load-bearing for a product claim. Implementation details do not get ADRs.

## Status vocabulary

| Status | Meaning |
|---|---|
| **Accepted** | The critiques establish the answer with evidence. Build to this. |
| **Proposed** | A genuine fork requiring a human decision. **Do not build past it.** |
| **Superseded by ADR-XXXX** | Replaced. The original text is never edited. |

## Index

### Irreversible — decide before the first migration

| # | Decision | Status | Reversal cost |
|---|---|---|---|
| [0001](0001-append-only-observation-model.md) | Append-only observations, versioned identity, `scan_run` as first-class | Accepted | **Irreversible** — pre-change history cannot be manufactured |
| [0003](0003-tenancy-on-day-one.md) | Full tenancy on day 1: `org_id`-leading keys, RLS FORCE, prefixed cache keys | Accepted | ~2 weeks now vs ~4 engineer-months + unrecoverable leak risk later |
| [0011](0011-secrets-and-credential-posture.md) | Redaction boundary enforced by type; `no_code` default; push-only ingestion | Accepted | A leaked secret cannot be recalled |
| [0012](0012-audit-integrity-and-decision-record.md) | Audit integrity + `evidence_availability` in every decision record | Accepted | Retrofitting immutable data is the worst migration class |

### Ingestion and correlation

| # | Decision | Status |
|---|---|---|
| [0002](0002-finding-lifecycle-vs-decision.md) | Finding lifecycle is not the decision; `not_present` requires N comparably-scoped scans | Accepted |
| [0004](0004-ingestion-formats.md) | SARIF for SAST, native JSON for SCA; `codeFlows` preserved structurally | Accepted |
| [0005](0005-idempotent-ingest-and-admission-control.md) | Idempotency keys, streaming parse, hard caps, poison-record DLQ | Accepted |
| [0006](0006-correlation-blocking-and-versioned-clusters.md) | Blocking + append-only edges + versioned materialization; hard block cap | Accepted |

### Decision engine and AI

| # | Decision | Status |
|---|---|---|
| [0007](0007-decision-authority-split.md) | The policy engine decides; the model recommends and can escalate but never suppress | Accepted |
| [0008](0008-deterministic-prefilter-and-cost-control.md) | Deterministic pre-filter is structural; materiality gate; per-tenant budget ≤$750/mo | Accepted |
| [0009](0009-evidence-contract-and-retrieval.md) | Typed evidence slots, gap records, drop log; no reranker/NLI/abstractive compression in MVP | Accepted |
| [0010](0010-confidence-calibration-and-audit-sampling.md) | Deterministic + calibrated confidence; empirical agreement bands; randomized audit with propensity logging | Accepted |
| [0015](0015-model-provider-strategy.md) | One provider, one adapter; benchmark includes refusal rate and ZDR availability | Accepted |
| [0018](0018-local-first-provider-selection.md) | Local-first: egress topology is the user's choice. Three providers, capped by test; egress class replaces `is_external`; confidence stays deterministic | Accepted — **amends 0015 §1** |

### Knowledge and storage

| # | Decision | Status |
|---|---|---|
| [0013](0013-external-knowledge-integrity.md) | Version pinning, snapshotting, authority tiers, advisory range-narrowing detection | Accepted |
| [0014](0014-no-graph-database.md) | No graph database; one polymorphic edge table + precomputed dependency closure; selective embedding | Accepted |

### Product-structural

| # | Decision | Status |
|---|---|---|
| [0016](0016-perishable-suppressions.md) | No terminal suppression: `deprioritized_until(conditions[])` and evidence-triggered re-litigation | Accepted |
| [0017](0017-cross-tenant-priors.md) | Cross-tenant aggregate priors vs strict isolation | **Proposed — decision required** |
| [0018](0018-local-first-provider-selection.md) | Local-first: egress class is a user choice, capped at three providers by test; amends 0015 §1 | Accepted |

## Reading order for a new engineer

0001 → 0003 → 0007 → 0016. Those four determine the shape of everything else. 0017 is the one open question and it blocks the moat narrative, not the build.

If you are touching the AI layer, read **0011 → 0015 → 0018** in that order. 0018 amends 0015 rather than replacing it, and it is explicit about the one place where reality differs from 0011: the redaction boundary is enforced structurally at runtime, because this repository has no MyPy and no CI to enforce it at build time.

## Provenance

Every ADR cites the critique section that established it:

- `docs/architecture/critique-architecture.md` — data model, correlation, scaling, cost
- `docs/product/critique-product.md` — market, buyer, pricing, wedge
- `docs/threat-model/critique-security.md` — trust boundaries, secrets, audit, tenancy
- `docs/evaluation/critique-ai-rag.md` — retrieval, confidence, evaluation, feedback integrity
- `docs/product/competitive-positioning.md` — what is commodity, contested, and open
