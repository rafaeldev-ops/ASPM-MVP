# ADR-0008 — Deterministic pre-filter is structural; cost is a governed resource

**Status:** Accepted
**Date:** 2026-08-14
**Source:** `critique-architecture.md` §9; `critique-product.md` §7; `critique-security.md` §7
**Depends on:** ADR-0007

---

## Context

CLAUDE.md contains no cost-of-goods model in 48 sections. It exposes reanalysis endpoints (§23), versions the scoring model (§26), and retrieves aggressively (§11) — every one of which re-triggers analysis.

## Problem

**Per-finding LLM analysis at 100k findings/month/tenant costs between $215 and $9,500 depending entirely on a component the brief does not contain.**

| Scenario | Design | Cost/tenant/month |
|---|---|---|
| A | Frontier model, every finding, no caching, no batch | **$9,500** |
| B | Mid-tier + prompt caching + Batch API | **$1,680** |
| C | Deterministic pre-filter + tiered models | **$215** |

Scenario A does not clear a mid-market ASPM contract, so **naive per-finding LLM analysis has negative gross margin**. Model selection, prompt engineering and caching move it 5.7×. The pre-filter moves it a further 7.8×, and it is deterministic code.

The worse failure is re-analysis. If findings are re-analyzed on each scan rather than on material change, daily CI multiplies everything by ~30 — scenario B becomes $50k/month/tenant. Re-analyzing on every EPSS refresh is ~$1.46M/year/tenant on autopilot.

## Decision

### 1. The pre-filter is a named pipeline stage, not an optimization

Order: **normalize → dedupe/correlate → deterministic score → policy → *only then* LLM**, and only for findings in the decision-relevant band (ambiguous deterministic score, or high-risk requiring an explanation).

Deterministic disposition rules (auditable, versionable, testable against a golden set): not in KEV **and** EPSS below θ **and** not reachable; dev-only dependency; fingerprint matches a previously validated FP under ADR-0007's predicate; severity below the policy floor.

**Design target: the model touches ≤10–20% of ingested findings.** This is a tracked metric with an alert, not an aspiration.

> **Amendment 2026-08-17, from [`exp-002`](../evaluation/exp-002-risk-model-executed.md).** The deterministic model was executed for the first time against a realistic 50-finding corpus. **It produced no discrimination for any SAST or secret finding — 36% of the corpus, all banded `track`.** The mechanism is structural, not a bug: applicability is derived from advisory version ranges, package coordinates and dependency scope, and a SAST finding has none of those.
>
> **The ~80% deterministic-disposition rate is therefore unreachable as stated.** If SAST and secrets are ~35% of a tenant's volume, the ceiling is ~65% before any judgment is made — and both the ≤20% touch-rate target and the $750/customer/month COGS ceiling are derived from it.
>
> Three ways out, and the choice is not yet made: (a) accept a higher touch rate on SAST and re-derive the cost model; (b) find deterministic SAST features worth having — rule-level historical FP rates under ADR-0010's IPW, file-path classes such as test and generated code, scanner-supplied taint confidence; (c) route SAST to the cheapest capable tier and reserve escalation for SCA. **Until one is chosen and measured, the 80% figure should not appear in a plan or a pitch.**

Reachability verdicts from Semgrep/Endor/Snyk are the **highest-precision auto-deprioritize input available**, cost zero tokens, and are what makes an 80% deterministic disposition rate realistic rather than optimistic (ADR-0004 ingests them as evidence).

### 2. The materiality gate

Re-invoke the model **only when `sha256(canonical(evidence_bundle) ‖ scoring_model_version ‖ prompt_version)` changes.** An unchanged bundle returns the cached decision with a new `valid_as_of`.

Re-analysis triggers on the **deterministic feature-vector diff**, never on arbitrary evidence refresh: EPSS crossing a policy threshold, KEV listing appearing, an advisory range narrowing (ADR-0013) — not "EPSS moved by 0.001."

Corollary: this gate is also the evaluation gate's foundation — an unchanged bundle producing a different decision is a non-determinism bug worth detecting.

### 3. Cost as a first-class tenant resource

- `analysis_budget_usd_per_period` per tenant, enforced **pre-call** via token counting and **post-call** via actual usage. **Exceeding queues; it does not spend.**
- **Hard ceiling: ~$750/customer/month** — derived from a $45k blended ACV at a 20% COGS ceiling. Instrument cost-per-decision from day one.
- A documented **degradation mode**: fall back to deterministic-only ranking, clearly labelled in the UI, reason recorded in the audit log. Never an outage.
- Spend is surfaced to the tenant in-product.

### 4. Batch-first

The hero workload is "a customer imports 10,000 findings" — that is a batch job, not an interactive one. Batch API pricing is 50% off. Interactive latency matters only for single-finding re-analysis.

### 5. Tiered models

High-volume classification on the cheapest capable tier; a low-volume escalation route to a frontier model behind an explicit router. **If more than ~5% of findings take the escalation route, the deterministic layer is under-built.**

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Analyze every finding with the best model | Negative gross margin; also the least auditable design on the false-negative axis |
| Rely on prompt caching and batch alone | 5.7× improvement against a 44× problem |
| Cache by content hash across tenants | A cross-tenant oracle (ADR-0003) |
| Track cost without controlling it (CLAUDE.md §28) | Tracking is not control. One tenant's 5M-finding import consumes the month's margin |
| Price per finding or per analysis (CLAUDE.md §35) | Prices the thing the product claims to reduce, exposes COGS to the buyer, and makes noisy-scanner customers the profitable ones. Price per developer or repository |

## Consequences

- The pre-filter is a load-bearing safety control as well as an economic one: a deterministic rule that deprioritizes is auditable, versionable and testable against a golden set. A model that deprioritizes is none of those.
- Pre-filter rules become a versioned artifact with their own golden-set evaluation and their own promotion process.
- Differential decisioning (ADR-0007) doubles cost on the suppression path — inside budget because the suppression path is a small fraction of the ≤20% that reaches a model at all.
- Cost per decision joins the observability set (model, prompt version, retrieval config version, scoring version, evidence ids).

## Reversal strategy

Easy to relax, hard to add late — not technically, but organizationally: a product that has never had a budget ceiling has priced and staffed as though COGS were free. Set it before the first pilot invoice.

## Verification

- A cost regression test: golden corpus through the full pipeline with an asserted upper bound on tokens and dollars.
- A test asserting an unchanged evidence bundle produces zero model calls.
- A test asserting budget exhaustion queues rather than spends, and that degraded mode is labelled in the response.
- LLM-touch-rate dashboard with an alert above 20%.
