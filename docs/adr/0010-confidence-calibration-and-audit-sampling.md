# ADR-0010 — Confidence is computed and calibrated; feedback is sampled with logged propensities

**Status:** Accepted
**Date:** 2026-08-14
**Source:** `critique-ai-rag.md` §3, §5, §7, §8
**Depends on:** ADR-0007, ADR-0009

---

## Context

CLAUDE.md §27 correctly separates confidence from risk, lists seven contributing factors, and gives no aggregation rule — while §7 asks the model to emit `"confidence": 0.0` directly. §15's feedback loop and §16's statistics have no mechanism to prevent circular reasoning beyond the sentence "avoid leakage and circular reasoning."

## Problem

**Two problems, both fatal if unaddressed.**

**1. Model confidence is not a probability.** Verbalized LLM confidence clusters in the 80–100% band largely independent of accuracy, and dissociates from log-probabilities. Worse, the two standard fixes are unavailable on the likely model family: the Messages API exposes no logprobs, and `temperature`/`top_p`/`top_k` are removed on the current frontier models (400 error), so temperature-based self-consistency ensembles do not run at all.

**2. The feedback loop is a suppression death spiral with gain > 1.** The system auto-deprioritizes class X → analysts never see X → no label for X → per-rule FP statistics are computed over *reviewed* items only, which are systematically the items the model already believed were real → **measured precision rises monotonically while true recall is unobserved and can fall toward zero** → that statistic is retrieved as "historical organizational evidence" for the next decision on the same rule → patterns are mined from the same biased distribution and promoted.

This is selection bias under missing-not-at-random, structurally identical to reject inference in credit scoring. A rule that draws three unlucky FP labels in its first week can be permanently suppressed, and the system's own metrics report this as improving accuracy. **The loop closes fastest on high-volume, low-severity rules — exactly where the product's value proposition lives. The failure looks like success.**

## Decision

### 1. The model never emits confidence or score

Removed from its schema entirely (ADR-0007). Confidence is computed:

| Stage | Technique | Labels required |
|---|---|---|
| **0 — day one** | Deterministic evidence-completeness score: required slots filled / total, source authority tier, max evidence age vs per-source validity window, conflict count, ownership resolved | **zero** |
| 1 | Platt scaling → P(analyst agrees), per decision class | ~200–500 per class |
| 2 | Isotonic regression | ~1,000–2,000 per class |
| 3 | **Conformal risk control on the auto-deprioritize gate only** — distribution-free bound on true-critical rate among auto-deprioritized findings | ~1,000 for α=0.05; ~5,000–10,000 for α=0.01 |

Conformal assumes exchangeability; a new scanner version, tenant, language ecosystem or EPSS model bump breaks it. Re-calibrate per tenant **and** per scanner-rule family, or scope the published guarantee narrowly.

**Calibrators are models.** They live in a versioned calibration store keyed by tenant, decision class and rule family, each with fit date, sample size and validity window.

### 2. Never render a model confidence to a human

Render an empirical statement instead:

> "Of the last 217 findings scored in this band for this organization, analysts agreed with 94% (95% CI 90–97%)."

Defensible in an audit, requires no belief in model introspection, and degrades gracefully — when n is small the interval is wide and says so.

### 3. Randomized stratified audit with logged propensities

- Sample a fixed fraction ε of auto-deprioritized findings into a **mandatory** review queue, stratified by `(scanner, rule_family, confidence_band, service_criticality)`.
- **Every finding carries `review_propensity`** — the exact probability, known at decision time, that it would be routed to a human. All organizational statistics are computed with Horvitz–Thompson inverse-propensity weighting. **This works only if the sampler is a randomized policy with a recorded probability**; "whatever the analyst happened to click" has unknown propensity and cannot be de-biased. Cheap on day one, **impossible to backfill.**
- Sizing by the rule of three: **n ≥ 600 audited auto-deprioritized findings with zero observed false negatives ⇒ FN ≤ 0.5% at 95%.** That is the number to put in a contract and the number a pilot customer can check.
- **Cost is a line item, not a footnote:** 600 audits × ~4 min ≈ **40 analyst-hours per window**. Subtract it from the savings claim. "We saved 160 hours net of audit" is more credible than "we saved 200."
- SPRT for the continuous monitor; fixed-n estimation for the quarterly report.
- **No bandits.** Thompson/UCB optimize cumulative reward and allocate exploration *away* from arms that look safe — precisely where undiscovered false negatives hide.

### 4. Retroactive outcome labels — the only bias-free source

A nightly job re-scores every past decision against current external state: deprioritized CVEs that later entered KEV, EPSS crossing a threshold, public exploit published, incidents or pentest findings mapping back to a suppressed finding, findings remediated anyway by a developer who disagreed.

Cheap, needs no analyst time, immune to the loop, and the single most credible artifact to put in front of a pilot customer. **MVP Must.** It is also the label source that makes ADR-0016 work.

### 5. Shadow mode at onboarding

For the first 30 days per tenant: the system decides, analysts decide independently, the system's answer stays hidden until the analyst submits. Produces an unbiased calibration set, a clean baseline for the north-star metric, and a measured agreement rate for the sales motion — at no extra cost to the customer, who was going to triage anyway.

### 6. Temporal leakage is enforced in the query

A finding's own prior decision must never be a feature for its own re-decision without a time split. `evidence.created_at < decision.requested_at` is enforced **in the retrieval query**, with a test that injects a future-dated decision and asserts non-retrieval. This bug otherwise ships, because it looks like a feature.

### 7. Ground-truth tiers, with T3 barred from the gate

| Tier | Source | Bias immunity | Use |
|---|---|---|---|
| T0 mechanical | duplicate pairs, version-range applicability, KEV membership, ownership | total | correlation, dedup, enrichment |
| T1 retroactive outcome | later-KEV, later-exploit, later-incident, actually-remediated | total | **the FN gate, and only that** |
| T2 adjudicated consensus | 3 annotators + adjudication on decomposed sub-questions | moderate | exploitability, prioritization |
| T3 production single-label | whatever the on-shift analyst clicked | **poor — this is the label the loop corrupts** | trend monitoring only, **never the release gate** |

Do not ask annotators "is this exploitable?" — four *formal* scoring systems (CVSS, EPSS, SSVC, Microsoft Exploitability Index) show little to no agreement on the same CVEs. Decompose into binary, verifiable sub-questions (reachable from an entry point? entry point externally exposed? public exploit exists? compensating control present and enforcing? does the affected range cover our version?) and **derive** the fused judgment deterministically. Any sub-question with measured κ < 0.6 is not eligible as a release-gate metric.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Use the model's `confidence` field | Not a probability; overconfident; unfixable via logprobs or temperature on the target models |
| Ensemble by resampling at temperature | `temperature` returns 400 on the current frontier models. Use evidence-subset bagging if variance is needed |
| Learn from all analyst decisions | Selection bias under MNAR; converges on the customer's existing blind spots |
| Optimize for analyst agreement | A system at 95% agreement has agreed with a process the customer told us is broken. Agreement is a diagnostic, not an objective |

## Consequences

- `review_propensity` is a mandatory column from migration #1 — the cheapest item in this document and the only one that is strictly impossible to add later.
- The audit quota consumes real analyst hours and must appear in the ROI model and the pricing conversation.
- Shadow mode extends time-to-value by 30 days per tenant; sell it as the baseline capture the customer needs anyway.
- An anti-conformity control is required: surface a held-out fraction of memory-suppressed findings anyway for periodic human audit, and alarm when agreement rises while re-litigation precision falls.

## Reversal strategy

Calibrators, sampling rates and thresholds are all configuration. `review_propensity` and the retroactive-label history are not reversible additions — they are only useful from the day they start.

## Verification

- An annotation-agreement probe before implementation: 3 analysts × 50 findings, holistic vs decomposed κ. Expected result (holistic <0.5, decomposed >0.7) makes the decomposition the core data model.
- A test asserting statistics are computed with inverse-propensity weighting.
- A test asserting the audit sampler's realized rate matches its declared propensity.
- A quarterly deterministic-only ablation (ADR-0008) reported alongside calibration.
