# Risk and Decision Model — SDIP

**Deliverable:** CLAUDE.md §26 · §42 (`docs/decisions/`)
**Date:** 2026-08-16
**Status:** Design. Binds backlog items R1-8 (deterministic scoring) and R1-9 (policy engine).
**Governed by:** ADR-0007 (decision authority), ADR-0008 (pre-filter), ADR-0010 (confidence), ADR-0013 (external knowledge), ADR-0016 (perishable suppressions)
**Consumed by:** `application/scoring/`, `application/policy/`, `decision.deterministic_assessment`, `decision.policy_decision`

---

## 0. The one structural decision in this document

CLAUDE.md §26 asks for "a transparent multi-factor model" that is "explainable and versioned". Almost every implementation of that sentence is a weighted sum of eight factors normalized to `[0,1]`, with a threshold at `0.3` below which findings are auto-deprioritized. That design fails for a reason that is not obvious until it has already shipped:

> **A threshold on a continuous score is where an unjustifiable weight silently becomes a suppression.**

Nobody can defend `w_reachability = 0.22` in a deposition, and nobody can unit-test it. But once a finding scores `0.28` and the gate is `0.30`, that weight *is* the control. The number was invented in a planning meeting, and it is now the reason a real vulnerability was not looked at.

So the model is split in two, and the split is the whole design:

| Part | Form | Owns | May cause suppression |
|---|---|---|---|
| **A — Urgency band** | A **decision tree over discrete decision points**. No weights, no arithmetic | *What class of response this finding warrants* | **Yes** — but only through an enumerable, unit-tested path |
| **B — Ordering score** | A bounded continuous function `[0,1]` | *The order of the queue within a band* | **Never.** No threshold on it is permitted to produce a suppressive outcome |

Part A is auditable because it is finite: six decision points with 3–4 values each is a table of a few hundred rows, every one of which can be reviewed by a human, argued about with a customer, and asserted in a test. Part B exists because analysts need a sorted list and a tree gives ties.

Neither part emits a disposition. **The policy engine emits the disposition** (ADR-0007); this document produces its two structured inputs.

---

## 1. Where this sits in the pipeline

```
observation → identity → evidence assembly
                              │
                              ▼
                    ┌──────────────────────┐
                    │  FEATURE EXTRACTION  │  §2 — typed, sourced, freshness-bounded
                    └──────────┬───────────┘
                               ▼
                    ┌──────────────────────┐
                    │  DECISION POINTS     │  §3 — 6 discrete points, derived by rule
                    └──────────┬───────────┘
                               ▼
              ┌────────────────┴─────────────────┐
              ▼                                  ▼
   ┌────────────────────┐            ┌────────────────────────┐
   │  A. URGENCY BAND   │  §4        │  B. ORDERING SCORE     │  §5
   │  tree, no weights  │            │  continuous, no gates  │
   └─────────┬──────────┘            └───────────┬────────────┘
             └──────────────┬─────────────────────┘
                            ▼
              ┌──────────────────────────────┐
              │  NON-SUPPRESSIBLE OVERLAY    │  §6 — applied last, always
              └──────────────┬───────────────┘
                             ▼
                  DeterministicAssessment
                             │
                             ▼
              pre-filter (ADR-0008) → policy engine (ADR-0007)
```

`DeterministicAssessment` is the JSONB written to `decision.deterministic_assessment`:

```json
{
  "scoring_model_version": "sm-2026.1",
  "feature_schema_version": "fs-3",
  "feature_vector": { "...": "see §2" },
  "decision_points": { "exploitation": "none", "exposure": "open", "...": "..." },
  "urgency_band": "act_soon",
  "band_path": ["exploitation=none", "exposure=open", "applicability=applicable",
                "criticality=high", "control=none"],
  "ordering_score": 0.61,
  "score_contributions": { "epss": 0.08, "exposure": 0.20, "...": "..." },
  "severity_floor": "high",
  "non_suppressible": false,
  "non_suppressible_reason": null,
  "auto_deprioritize_eligible": false,
  "ineligibility_reasons": ["criticality_unresolved"]
}
```

Every field is reproducible from `(feature_vector, scoring_model_version)` alone. That is invariant **I16** and it is what makes a re-score a verification rather than a re-guess.

---

## 2. The feature vector

### 2.1 Rules that apply to every feature

1. **Every feature is a record, not a value:** `(value, source, as_of, authority_tier, validity_window)`. A bare float has no provenance and cannot be defended.
2. **`unknown` is a first-class value and is never coerced to a safe-looking default.** `criticality = NULL` means *unresolved*, not *low* (database-model §3.2). Unresolved fails closed.
3. **Features expire into `unknown`.** Past its `validity_window` a feature does not keep its last value — it degrades to `unknown` and the finding loses auto-deprioritize eligibility. Stale evidence presented as current is the failure mode ADR-0013 exists to prevent.
4. **No feature is derived from a model.** Every value below comes from a scanner, a pinned feed, the asset registry, or the organization's own decision history.
5. **Version pins travel with values.** `epss = 0.042` is meaningless without `epss_model_version = v4`; the pin is part of the feature, not metadata about it.

### 2.2 The features

| # | Feature | Type | Source | Validity | Unknown ⇒ |
|---|---|---|---|---|---|
| **Technical severity** |
| F1 | `cvss_triples[]` | `(source, vector, score)[]` | NVD · GHSA · vendor PSIRT · scanner | 90d | severity from scanner `severity_raw` |
| F2 | `cvss_max_tier_a` | `0–10` | max over authority-tier-A triples | — | — |
| F3 | `cvss_spread` | `0–10` | `max − min` across sources | — | — |
| F4 | `severity_normalized` | enum + `mapping_version` | scanner, mapped | — | fails closed to `high` |
| **Exploit probability and activity** |
| F5 | `epss_score`, `epss_percentile` | `0–1` + `model_version` | EPSS feed (pinned) | 7d | `unknown` |
| F6 | `kev_listed`, `kev_date_added`, `kev_due_date` | bool + dates | CISA KEV | 24h | **fail closed: treat as listed until refreshed** |
| F7 | `exploit_public` | bool + artifact ref | KEV · GHSA · ExploitDB · vendor | 30d | `unknown` |
| F8 | `exploit_maturity` | `none·poc·functional·weaponized` | advisory + artifact | 30d | `unknown` |
| **Applicability — the cheapest true negative in the system** |
| F9 | `range_covers_our_version` | tri-state | `advisory_snapshot.affected_ranges` × observed `purl_version` | per snapshot | `unknown` |
| F10 | `reachability_verdict` | `reachable·not_reachable·unknown` | **scanner-supplied** (Semgrep/Snyk/Endor) | per scan | `unknown` |
| F11 | `dependency_scope` | `direct·transitive·dev_only·optional` | lockfile / `dependency_path` | per scan | `unknown` |
| F12 | `artifact_shipped` | tri-state | build metadata, image manifests | 30d | `unknown` |
| **Exposure** |
| F13 | `internet_facing` | tri-state (**nullable**) | asset registry / deployment | 30d | `unknown` |
| F14 | `environment` | `prod·staging·dev·unknown` | deployment record | 30d | `unknown` |
| F15 | `entry_point_confirmed` | tri-state | Q2 sub-question / config | 30d | `unknown` |
| **Business context** |
| F16 | `service_criticality` | `critical·high·medium·low` (**nullable**) | asset registry | 90d | **treated as `critical`** |
| F17 | `handles_regulated_data` | tri-state | asset registry | 90d | `unknown` |
| F18 | `ownership_resolved`, `ownership_confidence` | bool, `0–1` | CODEOWNERS · catalog · manual | 30d | `false` |
| **Controls and remediation** |
| F19 | `compensating_control` | `none·present·present_enforcing` | config attestation | 30d | `none` |
| F20 | `fix_available`, `fixed_version` | bool, string | advisory · scanner | per scan | `false` |
| F21 | `upgrade_distance` | `patch·minor·major·none` | semver diff | — | `unknown` |
| **Organizational history — scoped, weighted, never global** |
| F22 | `prior_fp_confirmations` | `(n, distinct_analysts, distinct_repos)` | decision history, **`rule_id` AND `repo_id` scoped** (I23) | 180d | `(0,0,0)` |
| F23 | `rule_fp_rate_ipw` | `0–1` + `n` + CI | `rule_disposition_stats`, inverse-propensity weighted, per scanner **major** version | 90d | `unknown` |
| F24 | `recurrence_count` | int | identity history | — | `0` |
| **Temporal** |
| F25 | `age_days` | int | `first_observed_at` | — | — |
| F26 | `sla_remaining` | interval | policy clock | — | — |

**Deliberately not features of risk:** evidence completeness, slot fill rate, conflict count, source agreement. Those are inputs to **confidence** (ADR-0010), and CLAUDE.md §27 is right that the two must not be fused. A finding can be certainly-critical on thin evidence, and a low-risk finding can be exhaustively evidenced. Mixing them produces a number that means neither.

### 2.3 The disagreement rule

`cvss_spread > 2.0` across authority-tier-A sources is **a conflict, not an average.** NVD and Red Hat routinely differ by more than two points on the same CVE; taking the mean produces an editorial judgment that nobody made and nobody can defend.

- `F2 = max` over tier-A sources (fail-safe direction).
- The spread is recorded as a `conflict` row against the decision.
- **A finding with an unresolved tier-A severity disagreement is ineligible for auto-deprioritize.** It is exactly the population where an automated "not important" is least defensible.

---

## 3. Decision points

Six discrete points. Each is derived from features by a stated rule, and each derivation is a unit test. This is the layer where the five annotation sub-questions of `evaluation-system.md` §1.3 become machine-computable — which is the point of having decomposed them.

| DP | Values | Derivation | Sub-question |
|---|---|---|---|
| **DP1 `exploitation`** | `none` · `poc` · `public` · `active` | `active` ⇐ F6 `kev_listed` ∨ confirmed in-the-wild evidence; `public` ⇐ F7; `poc` ⇐ F8 = `poc`; else `none` | Q3 |
| **DP2 `exposure`** | `not_deployed` · `unknown` · `internal` · `controlled` · `open` | **`not_deployed` ⇐ F14 ∈ {`staging`,`dev`} ∨ F12 = false — tested first**; `open` ⇐ F13 = true ∧ F14 = `prod`; `controlled` ⇐ F15 = true ∧ F13 = false; `internal` ⇐ F13 = false ∧ F14 = `prod`; else `unknown` | Q2 |
| **DP3 `applicability`** | `not_applicable` · `unknown` · `applicable` | `not_applicable` ⇐ F9 = false ∨ (F10 = `not_reachable` ∧ tier-A source) ∨ (F11 = `dev_only` ∧ F12 = false); `applicable` ⇐ F9 = true ∧ F10 ≠ `not_reachable`; else `unknown` | Q1, Q5 |
| **DP4 `criticality`** | `low` · `medium` · `high` · `critical` | F16 directly; **`NULL` ⇒ `critical`** | — |
| **DP5 `control`** | `none` · `present` · `enforcing` | F19 directly. `present` without attestation of enforcement is **not** `enforcing` | Q4 |
| **DP6 `fixability`** | `none` · `major` · `minor` · `patch` | F20 ∧ F21 | — |

Three derivations deserve their reasoning stated, because each is a place a careless implementation loses money or misses a breach:

- **`not_applicable` is the highest-value verdict in the system and the most dangerous.** It is what makes an 80% deterministic disposition rate achievable (ADR-0008) — and a wrong `not_applicable` is a silent false negative. It therefore requires a **positive, tier-A-sourced** signal: a scanner reachability verdict or an advisory range that demonstrably excludes our version. Absence of evidence yields `unknown`, never `not_applicable`.
- **`exposure = unknown` is not `internal`, and it is not `not_deployed` either.** A service the asset registry has never heard of is not an internal service; it is a service nobody has mapped. Ownership resolution rate is a product metric precisely because this is where it bites. **`not_deployed` was added by `exp-002`** after the published DP2 collapsed `staging` into `unknown` — discarding a fact we have as a fact we lack, which is how an estate's least important findings crowd out its most important ones while every metric still looks healthy.
- **`kev_listed` fails closed on a stale feed.** If the KEV refresh has not completed inside its 24-hour window, findings are scored as though listed. A daily feed outage must never open a suppression window.

---

## 4. Part A — the urgency band

### 4.1 Bands

| Band | Meaning | Analyst contract |
|---|---|---|
| `act_now` | Exploited or exploitable against an exposed critical asset | Paged; SLA clock in hours |
| `act_soon` | Credible path, real asset | Sprint-level SLA |
| `scheduled` | Real but not urgent | Normal backlog |
| `track` | Applicable, no evidence of exploitability or exposure | Visible, not queued |
| `deprioritize_candidate` | Deterministically supported grounds not to act now | **Candidate only** — §4.3 |

### 4.2 The tree

> **Revised 2026-08-17 after [`exp-002`](../evaluation/exp-002-risk-model-executed.md).** The first published version of this table was executed for the first time and found to be **non-total** — 112 of its 576 inputs matched no rule — and to contain a **dead rule** shadowed by an earlier one. Both are repaired below. The band-transition matrix for the repair is in exp-002 §5; `act_now` was unchanged at +0.
>
> **DP2 also gained a fifth value, `not_deployed`** (§3), so the space is now 4 × 5 × 3 × 4 × 3 = **720 combinations**, not 576.

Evaluated top to bottom; the first matching rule wins. `*` is a wildcard.

| # | DP1 exploitation | DP2 exposure | DP3 applicability | DP4 criticality | DP5 control | Band |
|---|---|---|---|---|---|---|
| 1 | `active` | * | ≠ `not_applicable` | * | * | **`act_now`** |
| 2 | `active` | * | `not_applicable` | * | * | `act_soon` ¹ |
| 3 | `public` | `open` | `applicable` | * | ≠ `enforcing` | **`act_now`** |
| 4 | `public` | `open` | `applicable` | * | `enforcing` | `act_soon` |
| 5 | `public` | `open` | `unknown` | `critical`·`high` | * | `act_soon` |
| 6 | `public` | `internal`·`controlled` | `applicable` | `critical`·`high` | ≠ `enforcing` | `act_soon` |
| 7 | `public` | `unknown` | ≠ `not_applicable` | * | * | `act_soon` ² |
| 8 | `poc` | `open` | `applicable` | * | ≠ `enforcing` | `act_soon` |
| 9 | `poc` | * | `applicable` | `critical` | * | `act_soon` |
| 10 | `none` | `open` | `applicable` | `critical` | * | `act_soon` ⁴ |
| 11 | `poc`·`none` | `open` | `applicable` | `high`·`medium` | * | `scheduled` |
| 12 | `none` | `internal`·`controlled` | `applicable` | `critical` | ≠ `enforcing` | `scheduled` |
| 13 | `public` | `internal`·`controlled` | `applicable` | * | * | `scheduled` ⁴ |
| 14 | `poc` | `internal`·`controlled`·`unknown` | `applicable` | * | * | `scheduled` ⁴ |
| 15 | * | * | `unknown` | * | * | `track` ³ |
| 16 | `none` | `internal`·`controlled` | `applicable` | `low` | `enforcing` | **`deprioritize_candidate`** ⁵ |
| 17 | `public` | * | `not_applicable` | * | * | `track` ⁶ |
| 18 | ≤ `poc` | * | `not_applicable` | * | * | **`deprioritize_candidate`** |
| 19 | ≤ `poc` | `not_deployed` | * | * | * | **`deprioritize_candidate`** ⁷ |
| 20 | * | * | * | * | * | `track` — **catch-all** ⁸ |

¹ An actively exploited vulnerability we believe does not apply to us is a claim about our own inventory, and inventory is the thing organizations are most often wrong about. It is not `act_now`, and it is emphatically not deprioritizable.
² Unknown exposure with a public exploit is escalated, not deferred. The asymmetry of ADR-0007 applied to the deterministic layer: unknown costs analyst hours, wrong-and-quiet costs a breach.
³ Rule 15 absorbs most of the space: unknown applicability dominates a real estate. On `v4-corpus-v1.0` it takes 36% of findings. As ownership and reachability coverage rise it should depopulate and rows 1–14 sharpen. **Band distribution over time is a monitored metric** — a stable 90% `track` means the enrichment layer is not working, not that the estate is healthy.
⁴ **Added by `exp-002`.** Each closes a hole where the published tree matched nothing. Rows 13 and 14 alone covered 43 previously-undefined combinations.
⁵ **Was unreachable in the published version**, shadowed by a `track` row since removed. It matches **2 of 720** combinations. That is worth stating plainly: this document claims two grounds for deprioritization and in practice has one, plus a rounding error. Do not build a plan on the second.
⁶ Graded against rows 2 and 18. A public exploit against something we *believe* does not apply sits between "actively exploited and inapplicable" (escalate) and "no exploit and inapplicable" (deprioritize).
⁷ `not_deployed` is DP2's fifth value, added by `exp-002` because `staging` was collapsing into `unknown` — discarding a fact we have as a fact we lack.
⁸ **The catch-all is not a formality.** It resolves 10% of `v4-corpus-v1.0`: ordinary internal findings with no exploit evidence. It lands on `track` — visible, not queued, **never deprioritizable** — because the default for "we did not think about this" must cost analyst hours, never silence.

The full table is generated from these twenty rules and materialized as a fixture: `4 × 5 × 3 × 4 × 3 = 720` combinations, each with an asserted band ([`phase0/risk-tree-fixture.json`](../../phase0/risk-tree-fixture.json)). A change to any rule diffs the 720 and the diff is reviewed. **That diff is the review artifact** — not the rule text.

**Two properties are asserted in CI, because both defects `exp-002` found are mechanically detectable and neither would have survived a test:**

| Assertion | Catches |
|---|---|
| **The tree is total** — zero unmatched combinations | A rule set that leaves findings with no band |
| **No row is dead** — every row matches ≥1 combination | A rule shadowed by an earlier one, i.e. a policy that exists only in prose |

### 4.3 `deprioritize_candidate` is a candidate, not a decision

Reaching row 14 or 15 makes a finding *eligible for consideration*. It becomes a disposition only if the policy engine's independent predicate also holds (ADR-0007 §1), and it is blocked outright by any of:

| Blocker | Reason |
|---|---|
| `non_suppressible` overlay set (§6) | I19 |
| Any required evidence slot missing (`evidence_gap`) | ADR-0009 — silence is not a negative finding |
| `cvss_spread > 2.0` unresolved | §2.3 |
| `F16 criticality` unresolved | Failing closed on the least-understood assets |
| Feature staleness on any of F6, F9, F10, F13 | The four features the verdict actually rests on |
| Tenant not past the §3.2 auto-suppression gates in `evaluation-system.md` | Auto-suppression is off by default, per tenant |

**In the MVP, `deprioritize_candidate` is a recommendation surfaced to a human. There is no automatic path from this table to a suppressed finding.** Every suppression carries a named approver, conditions and an expiry (ADR-0016).

---

## 5. Part B — the ordering score

### 5.1 What it is for, stated narrowly

Ranking findings **within a band** so the analyst queue has a stable, sensible order. That is the whole job.

```
ordering_score = clamp01( Σ contribution_i )
```

| Component | Contribution | Note |
|---|---|---|
| `cvss_max_tier_a / 10` | × 0.20 | Technical severity, not risk |
| `epss_percentile` | × 0.20 | Percentile, not raw score — raw EPSS is heavily zero-inflated and sorts badly |
| `exploitation` ordinal | × 0.15 | `none` 0 · `poc` .4 · `public` .8 · `active` 1.0 |
| `exposure` ordinal | × 0.15 | `unknown` .5 · `internal` .3 · `controlled` .5 · `open` 1.0 |
| `criticality` ordinal | × 0.15 | unresolved scores as `critical` |
| `applicability` ordinal | × 0.10 | `not_applicable` 0 · `unknown` .5 · `applicable` 1.0 |
| `recurrence`/`age` pressure | × 0.05 | Bounded; prevents old findings sinking forever |

### 5.2 The three rules that keep it honest

1. **No threshold on `ordering_score` may produce a suppressive outcome.** Not in the policy engine, not in the pre-filter, not in a UI default filter, not in a report. Enforced by a test that asserts no policy predicate references `ordering_score`, and by code review on `application/policy/`.
2. **It never crosses a band boundary.** A `track` finding at `0.71` sorts below every `scheduled` finding at `0.20`. Sorting is `(band, ordering_score)`, lexicographic. A weight error can therefore mis-order a queue; it can never re-classify a finding.
3. **It is not a probability and is never rendered as one.** No "78% risk". The UI renders the band, the decision-point path, and the ordinal position. Where a probability-shaped statement is wanted, ADR-0010 §2 supplies the only defensible one — the empirical agreement band.

The weights above are round numbers chosen for legibility, and that is deliberate and disclosed: they are ordering hints, not measurements. **Because they cannot cause a suppression, they do not need to be calibrated to be safe** — which is precisely the property the single-score design gives away.

---

## 6. The non-suppressible overlay

Applied after the band, unconditionally, and outside the score entirely (invariant I19, ADR-0016, EU CRA Art. 14 — live 2026-09-11):

```
if kev_listed or confirmed_active_exploitation:
    non_suppressible      = True
    non_suppressible_reason = "kev_listed" | "active_exploitation"
    band                  = max(band, act_soon)
    auto_deprioritize_eligible = False
```

No policy predicate, no analyst action, no model recommendation and no scoring version can clear this flag. The API returns `422` with `non_suppressible_reason` on any attempt (`docs/api/README.md` §2.3), and the attempt is itself an audited event — a repeated attempt to suppress a KEV finding is a signal worth having.

Note the interaction with rule 2 of the tree: an `active` exploitation with `not_applicable` is escalated to `act_soon` by the tree *and* pinned non-suppressible by the overlay. Two independent mechanisms, deliberately.

---

## 7. Versioning

### 7.1 What is versioned, and how

| Artifact | Identifier | Changes when |
|---|---|---|
| Feature schema | `feature_schema_version` = `fs-{n}` | A feature is added, removed, or its type/derivation changes |
| Scoring model | `scoring_model_version` = `sm-{year}.{n}` | A tree rule, a decision-point derivation, or a score weight changes |
| Policy | `policy_version` | Owned by ADR-0007, not this document |

Both are `NOT NULL` on `decision` and both are in the reproducibility manifest.

### 7.2 The promotion path — no in-place scoring changes, ever

A scoring change is a `reprocessing_job` (database-model §3.10), not a deploy:

1. New version computes into shadow output alongside the promoted version.
2. **Band-transition matrix** produced: how many findings moved between which bands, in which direction.
3. Any finding moving *into* `deprioritize_candidate` is enumerated, capped, and reviewed. A change that quietly deprioritizes 4,000 findings is exactly the change that must never be a silent deploy.
4. Evaluation gates run: **G1 (zero GS-FN auto-deprioritized) is absolute**; G5, G6, G10 apply per `evaluation-system.md` §3.1.
5. Explicit promotion. The old version's outputs are retained — decisions are immutable (I9), so a re-score produces new decision records with `DecisionRevision` links, never an edit.

### 7.3 Re-score triggers — the materiality gate

Re-scoring is triggered by a **discrete decision-point change**, never by continuous drift (ADR-0008 §2):

| Trigger | Re-score |
|---|---|
| KEV listing appears | Yes — and non-suppressible overlay applies immediately |
| EPSS crosses a policy threshold under a **pinned** model version | Yes |
| EPSS moves within a band | **No** |
| Advisory `affected_ranges` narrows or widens (DP3 flips) | Yes — and re-opens dependent suppressions (ADR-0013) |
| Reachability verdict changes | Yes |
| `internet_facing` or `criticality` changes in the registry | Yes |
| Ownership resolves | No — affects routing, not risk |
| Nightly refresh with no decision-point change | **No.** This is the difference between $215 and $1.46M/year (ADR-0008) |

### 7.4 EPSS model-version boundaries — measured, not assumed

An EPSS model-version bump re-scores everything **once**, as a tracked job with a band-transition matrix, because the feature's meaning changed even where its value did not. [`exp-001`](../evaluation/exp-001-epss-model-boundary.md) measured what "changed" means at the v4 → v5 boundary (2026-06-15), against a same-model control over an identical 10-day gap:

| | Across the boundary | Same model, 10 days |
|---|---:|---:|
| CVEs crossing 0.01 upward | **71,885** (27.4%) | 306 (0.15%) |
| Scores unchanged | **0.0%** | 90.6% |
| Mean absolute Δ | 0.0219 | 0.0001 |

**235× more threshold crossings than ten days of the world actually changing.** Three rules follow, and they are binding on `application/scoring/` and `application/relitigation/`:

| | Rule |
|---|---|
| **R1** | An EPSS comparison is valid **only between two observations under the same `model_version`.** Gated, not smoothed |
| **R2** | A bump produces a **one-time re-baseline and emits no `ReopenEvent`.** The correct response to "all the numbers changed" is to notify nobody — otherwise the product wakes 27% of a customer's below-threshold suppressions on the night of an upstream release |
| **R3** | Pin the **feed's own version string** (`v2026.06.15`), not the marketing version. Code matching on `"v5"` matches nothing |

**Percentile is not a mitigation** — mean absolute percentile Δ across the boundary is 0.1195, five times the raw-score Δ, because a new model reshuffles the ranking. Percentile is correct for *ordering* (§5.1) and wrong for *triggering*. Same number, different jobs.

---

## 8. Explainability contract

Every score must answer four questions without a model in the loop:

| Question | Answered by |
|---|---|
| Why this band? | `band_path` — the matched rule and the decision-point values that matched it |
| Why these decision points? | Each DP's derivation rule id plus the feature ids and their sources |
| Why this position in the queue? | `score_contributions`, per component |
| What would change it? | Computed counterfactual: the minimal decision-point change that moves the band, rendered as "this becomes `act_now` if a public exploit appears" |

The counterfactual is cheap — the tree is 576 rows, so the minimal-change set is a lookup — and it is the single most useful thing the UI can show an analyst who disagrees. It also doubles as the invalidation-condition suggester when a suppression is created (ADR-0016): the conditions that would flip the band are exactly the conditions the suppression should watch.

---

## 9. Evaluation hooks

| Property | Dataset | Gate |
|---|---|---|
| Decision-point derivations are correct | GS-PREF (400 findings), T0/T2 | Per-DP accuracy; κ ≥ 0.6 for any DP used as a gate |
| No true critical lands in `deprioritize_candidate` | **GS-FN (200 known-true criticals)** | **G1 — zero. Absolute** |
| Band stability under version change | Band-transition matrix vs prior version | Reviewed, not thresholded |
| Ordering quality | GS-DEC, analyst-ranked subsets | Monitored (Kendall τ), never a release gate |
| Deterministic-only ablation | GS-DEC | **Quarterly gate** (ADR-0008 / evaluation §3.4) — this table is the ablation's "deterministic path" |

The last row deserves emphasis: **this document is the baseline the LLM has to beat.** If deterministic + LLM does not measurably outperform this table on GS-DEC, the model belongs on `reasoning_summary` and nowhere near the decision path. That is not a hypothetical concession; it is the pre-registered outcome of experiment 2 in `evaluation-system.md` §10.

### 9.1 The coverage limit, measured

`exp-002` ran this model over `v4-corpus-v1.0`. The result is not a defect, it is the shape of the model, and it changes how every downstream claim must be read:

| Class | n | Band distribution |
|---|---:|---|
| **SCA** | 30 | act_now 10 · act_soon 4 · scheduled 3 · track 5 · deprioritize 8 |
| **SAST** | 14 | **track 14** |
| **Secret** | 4 | **track 4** |
| Container | 2 | act_now 2 |

**Every SAST and secret finding lands on `track`.** DP3 `applicability` is derived from advisory version ranges, scanner reachability and dependency scope — and a SAST finding has no version range, no package and no advisory. So applicability is `unknown`, and `unknown` routes to `track` whatever else is true.

Three consequences, and none is optional:

1. **ADR-0008's ~80% deterministic-disposition target is unreachable as stated.** This layer cannot dispose of *any* SAST or secret finding. If those are ~35% of a customer's volume, the ceiling is ~65% before a single judgment is made — and the ≤20% LLM-touch-rate target and the $750/month COGS ceiling both rest on that number.
2. **The standing ablation must be reported per finding class, never blended.** The LLM will show a large advantage on SAST because the deterministic path has no features there, not because it reasons worse. A blended number measures feature availability and reports it as reasoning.
3. **46% of the corpus resolves through a "we do not know" path** — 36% unknown applicability, 10% the catch-all. On a realistic corpus this model gives a confident answer for about half the findings and shrugs at the other half. That is the honest baseline. It is exactly the gap the evidence layer exists to close, and it had to be measured before it could be claimed.

---

## 10. Anti-patterns

| Anti-pattern | Why it fails | Instead |
|---|---|---|
| One score, one threshold, auto-deprioritize below it | Makes an invented weight the control | Tree for class, score for order |
| Averaging CVSS across sources | An editorial decision nobody made | `max` over tier-A + record the spread as a conflict |
| `criticality NOT NULL DEFAULT 'low'` | Suppresses findings on the least-understood assets | Nullable; unresolved ⇒ `critical` |
| Stale features keeping their last value | Silently converts "we knew this in March" into "this is true today" | Expire into `unknown`; lose eligibility |
| Model-supplied `contextual_risk_score` | Unenforceable range, no provenance, no reproducibility | Deterministic only (ADR-0007 §2) |
| Global rule-level FP rates | Pools two different detectors across a scanner major version | Segment by major version; IPW-weight (ADR-0010) |
| "We marked this rule FP elsewhere, so suppress here" | Not evidence about this repository | I23: `rule_id` **and** `repo_id` **and** same-or-newer fingerprint |
| Rendering the score as a probability | It is not one, and a calibrated-sounding number is the most persuasive form of wrong | Render the band + empirical agreement (ADR-0010 §2) |
| Tuning weights against analyst agreement | Converges on the customer's existing blind spots | Agreement is a diagnostic, not an objective |
| Changing scoring in a deploy | An unreviewed mass re-classification | `reprocessing_job` + band-transition matrix + explicit promotion |

---

## 11. Worked examples

**A — `log4j`-shaped.** CVE in a direct dependency, KEV-listed, internet-facing payments service.
`DP1=active` → rule 1 → **`act_now`**, `non_suppressible=true`. Ordering `0.94`. No model call: the pre-filter disposes of it deterministically, and an LLM adds nothing but cost to a finding whose answer is already unambiguous.

**B — the case the product is sold on.** Medium CVSS, EPSS `0.004`, transitive dev-only dependency, not shipped, advisory range excludes our version.
`DP3=not_applicable`, `DP1=none` → rule 14 → **`deprioritize_candidate`**. Blockers checked: no evidence gaps, no spread conflict, criticality resolved, features fresh. Surfaced to an analyst with a suggested suppression carrying `advisory_range_narrowed` and `kev_listed` as invalidation conditions. Fourteen months later the maintainer widens the affected range; DP3 flips to `applicable`; the suppression trips; a `ReopenEvent` lands with what was knowable in 2026 attached. **That sequence is the company.**

**C — the one that fails closed.** High CVSS, no exploit, service not in the asset registry, no CODEOWNERS entry.
`DP2=unknown`, `DP4=critical` (unresolved), `DP3=unknown` → rule 12 → **`track`**, `auto_deprioritize_eligible=false`, `ineligibility_reasons=["criticality_unresolved","exposure_unknown"]`. The finding is not urgent and is not suppressible. The correct product response is not a better score — it is to raise ownership resolution rate, which is why that is a monitored metric with a gate at 80% before auto-suppression is available to a tenant at all.

---

## 12. Open questions

| # | Question | Blocks | Resolve by |
|---|---|---|---|
| Q-RM-1 | Do the fifteen tree rows survive contact with three real analysts' judgment on 200 findings? | Nothing — but a large disagreement means the tree is wrong, not the analysts | Phase 0 item V2 |
| Q-RM-2 | Is scanner-supplied reachability trustworthy enough to be a tier-A input to `not_applicable`? | The 80% deterministic disposition rate, and therefore the cost model | Measure per scanner on GS-PREF before enabling |
| Q-RM-3 | Should `exposure=unknown` + `criticality=critical` escalate above `track`? | Alert volume at onboarding, when nearly everything is unknown | Pilot data; deliberately conservative until measured |
| Q-RM-4 | Per-tenant tree overrides — customer-specific rows — or one global tree? | The evaluation story (per-tenant trees need per-tenant gates) | After two pilots |

Q-RM-2 is the one with money attached. If scanner reachability is wrong 10% of the time in the `not_reachable` direction, rule 14 becomes the largest false-negative source in the product, and the pre-filter's economics (ADR-0008) rest on it being right.
