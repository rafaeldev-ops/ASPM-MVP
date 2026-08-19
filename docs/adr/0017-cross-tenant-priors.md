# ADR-0017 — Cross-tenant aggregate priors, or no data network effect

**Status:** **Proposed — decision required. Do not build past this.**
**Date:** 2026-08-14
**Source:** `critique-ai-rag.md` §6; `critique-security.md` §3.5
**Decision owner:** founder / CEO. This is a business and contractual decision, not a technical one.

---

## Context

CLAUDE.md §4 wants a compounding data advantage from accumulated organizational knowledge. CLAUDE.md §19 forbids cross-organization retrieval, embeddings, decision memory **and analytics**. §17 requires Pattern Discovery across "repeated false-positive patterns" and "scanner-specific noise."

**These cannot all be true.** Read literally, §19 means every customer starts from zero forever and there is no network effect — only per-tenant switching cost. That is a real business, but it is not a moat and must not be described as one.

## The arithmetic that forces the decision

Model per-rule false-positive propensity as Beta–Bernoulli. Organizational data dominates a prior once `n > α + β`.

- Against a **weak** prior (α+β ≈ 2), a handful of labels moves the estimate — but a weak prior means day-one behaviour is essentially raw scanner output, which is worthless.
- Against a **strong cross-tenant prior** (effective sample size 20–50, which is what pooling a rule across customers yields), you need **20–50 labelled instances per rule** before org-specific signal is meaningfully better.

A typical org running Semgrep + Trivy + Gitleaks triggers **50–200 distinct high-volume rules**. At 30 labels per rule: **1,500–6,000 labelled decisions**, ≈ **75–300 analyst-hours ≈ 2–8 analyst-weeks per tenant**, before rule-level organizational memory beats a good generic prior.

For a six-week pilot this is fatal to the moat narrative and irrelevant to the pilot's success — which points at the real finding:

| Knowledge type | Acquired via | Time to value |
|---|---|---|
| Service criticality, ownership, exposure, compensating controls, exception policy | **Configuration + integration** (CMDB, CODEOWNERS, cloud tags, IaC) | **days** |
| Rule-level FP propensity | Triage labels | **months** |
| Fix-efficacy and remediation history | Observed outcomes with closure lag | **quarters** |

**The fast-accruing, high-value organizational context is configuration, not decision history.** What makes the product useful on day 30 is a populated context graph. The decision log starts to matter at month 6.

## The two options

### Option A — Strict isolation (CLAUDE.md §19 as written)

Every tenant's knowledge stays private. No pooled statistics, no shared priors, no cross-tenant patterns.

- **Pro:** the simplest security story in the category; no contractual work; no k-anonymity design; no risk of a cross-tenant inference channel; sellable as-is to regulated buyers.
- **Con:** every customer starts cold, forever. Day-one behaviour is raw scanner output plus public enrichment. **There is no data network effect** — and the moat language in CLAUDE.md §4 must be deleted, not softened.
- **Honest positioning:** "our defensibility in year 1–2 is workflow position and switching friction, not data."

### Option B — Cross-tenant aggregate priors, contractual opt-in

A statistical layer carrying **only** aggregate, non-content-derived priors — e.g. "across N≥10 tenants, Semgrep rule `X` has an FP rate of 0.72 ± 0.06."

Mandatory constraints if chosen:

- `knowledge_scope ENUM('tenant_private','global') NOT NULL`, part of the RLS predicate, **defaulting to `tenant_private`** (ADR-0003).
- `global` reachable only for knowledge derived from public data **or** from tenants with contractual opt-in.
- A published **k-anonymity floor** on contributor count and a documented aggregation method.
- **No raw finding content, no code, no tenant-identifiable signal**, ever.
- Opt-in surfaced in the product UI **and** in the DPA. Never a default.
- **Ban tenant data in shared prompt content** — few-shot examples and "here's how similar orgs decided" content compiled across tenants is a silent leak path no RLS policy covers, because it happens in prompt-assembly code.
- Monitor for cross-tenant inference via aggregate statistics and cache timing.

- **Pro:** the only version of the moat that works on day one; materially better cold-start behaviour; a genuine compounding advantage.
- **Con:** a contractual and privacy surface to design, negotiate and defend; an aggregate is a cross-tenant channel *by design* and an attacker-useful one ("which orgs suppress this rule class"); it complicates every regulated-customer conversation.

## Recommendation (for the decision owner, not yet a decision)

**Option B, scoped to rule-level FP priors only, opt-in, with a k-anonymity floor — and with the moat claim relocated regardless.**

Two things are true independently of which option is chosen:

1. **The near-term differentiator is configuration and integration, not accumulated decisions.** Time-to-populated-context-graph determines whether a pilot succeeds. CLAUDE.md §31's "percentage of findings with resolved ownership" should be promoted to near-north-star for the pilot phase.
2. **The exportable decision log is not the durable asset.** CLAUDE.md §44 promises export and enterprise buyers will demand it, so a competitor can ingest whatever is exported. The durable artifacts are the ones never exported: **calibrators, the correlation graph, the evaluation set, and (under Option B) the cross-tenant priors.** Say that plainly in the moat section rather than pointing at the decision log.

## Consequences of deferring the decision

`knowledge_scope` and the opt-in flag are **cheap to add now and expensive later** — the same shape as ADR-0003 and ADR-0010's `review_propensity`. Recommendation: **add the column and default it to `tenant_private` regardless of which option is chosen**, so the schema does not foreclose Option B while the business decision is pending. Do not build the aggregation pipeline until this ADR is Accepted.

## Verification (once decided)

- Under either option: a test asserting no query returns rows from a second tenant, including aggregate endpoints.
- Under Option B: a test asserting aggregates below the k-anonymity floor are not served; a test asserting no prompt content is compiled from another tenant's data; a documented differential-privacy or aggregation-threshold mechanism reviewed by counsel.
