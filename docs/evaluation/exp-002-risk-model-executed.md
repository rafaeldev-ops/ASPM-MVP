# EXP-002 — The risk model, executed

**Run:** 2026-08-17 · **Type:** design verification by execution · **Cost:** ~2 hours, no external dependency
**Instrument:** [`phase0/v2_riskmodel.py`](../../phase0/v2_riskmodel.py) · **Input:** `v4-corpus-v1.0`
**Changes:** `risk-model.md` §3, §4.2 · `evaluation-system.md` §3.4 · ADR-0008
**Status:** three defects found and repaired; **one finding is unrepaired and is the important one**

---

## 0. Result in one line

> **The tree published in `risk-model.md` §4.2 leaves 19% of its own input space undefined, contains a rule that can never fire — and, on a realistic corpus, produces no discrimination whatsoever for 36% of findings.**

The first two are bugs and are fixed. The third is not a bug; it is the shape of the model, and it was invisible until the model was run.

---

## 1. Why execute a design document

`risk-model.md` is the deterministic baseline the entire product rests on. `evaluation-system.md` §3.4 makes it the standing quarterly ablation — the thing the LLM must beat. ADR-0008's economics assume it disposes of ~80% of findings without a model call.

None of that had ever been executed. Transcribing fifteen table rows into fifteen tuples takes twenty minutes, and the point of doing it is to find out where the document is not actually a design.

Three defects, all found within the first run.

---

## 2. D1 — the tree is not total

Enumerating the full decision-point space (4 × 4 × 3 × 4 × 3 = 576 combinations) and evaluating the published rules:

| Band | Combinations |
|---|---:|
| `act_now` | 104 |
| `act_soon` | 108 |
| `scheduled` | 12 |
| `track` | 144 |
| `deprioritize_candidate` | 96 |
| **UNMATCHED** | **112 (19.4%)** |

**112 of 576 inputs match no rule at all.** An unmatched finding has no band — not a wrong band, *no* band. That is undefined behaviour in the one component whose entire justification is that it can be exhaustively reviewed by a human.

The gaps clustered in ordinary places, not exotic ones:

| Pattern | Combinations |
|---|---:|
| `public` + any exposure + `not_applicable` | 48 |
| `poc` + internal/controlled/unknown + `applicable` | 27 |
| `public` + internal/controlled + `applicable` | 16 |
| `none` + unknown exposure + `applicable` | 12 |
| `none` + open + `applicable` (criticality outside high·medium) | 6 |

*"A finding with a public exploit that does not apply to us"* is not an edge case. It is a Tuesday.

**Repair:** four explicit rows plus a **conservative catch-all landing on `track`** — visible, not queued, and **not** deprioritizable. Per the document's own asymmetry, the default for "we did not think about this" must cost analyst hours, never silence.

---

## 3. D2 — a dead rule, and it was the interesting one

Row 15 (`none` · internal/controlled · applicable · `low` · `enforcing` → `deprioritize_candidate`) **matched zero combinations.** Row 13 (`none` · internal/controlled · applicable · `low|medium|high` → `track`) shadows it completely.

The consequence is not cosmetic. `risk-model.md` claims two grounds for deprioritization:

1. the finding does not apply (`not_applicable`), and
2. the finding is live but genuinely low-risk behind an enforcing control.

**The second was unreachable.** As published, the only path to `deprioritize_candidate` was `not_applicable`, and the product's second deprioritization ground existed only in prose.

**Repair:** drop V1's row 13 — the catch-all subsumes it with the same outcome — so the low+enforcing row becomes reachable. It now matches 2 of 720 combinations. Which is itself worth knowing: one deprioritization ground covers 96 combinations and the other covers 2. **They are not two grounds. They are one ground and a rounding error**, and any plan that leans on the second should stop.

---

## 4. D3 — a known negative discarded as an unknown

Running against the corpus surfaced NW-018: a KEV-listed glibc CVE in the `analytics-etl` staging image. The environment brief states plainly that `analytics-etl` is **not deployed to production**. The model banded it `act_now`.

The cause: DP2's published domain is `unknown · internal · controlled · open`, and `staging` matches none of them, so it fell to `unknown`. But `unknown` is reserved for *genuinely unmapped* assets. **"This service is not in production" is a fact we have, not a fact we lack.**

Discarding a known negative as an unknown is how an estate's least important findings crowd out its most important ones — and it does so while the metrics look healthy, because `unknown` is a respectable-looking value.

**Repair:** DP2 gains a fifth value, `not_deployed`, checked first. The decision-point space grows from 576 to **720**.

Note what did *not* change: NW-018 is still escalated, because it is KEV-listed and row 1 fires on `active` regardless of exposure. That is deliberate and it is the same reasoning as row 2 — *"it isn't deployed"* is a claim about our own estate, and estates are what organizations are most often wrong about.

---

## 5. Band-transition matrix

`risk-model.md` §7.2 forbids promoting a scoring change without one. Applying its own process to its own first change:

| Band | published | repaired | Δ |
|---|---:|---:|---:|
| `act_now` | 128 | 128 | **+0** |
| `act_soon` | 123 | 126 | +3 |
| `scheduled` | 12 | 55 | +43 |
| `track` | 180 | 268 | +88 |
| `deprioritize_candidate` | 120 | 143 | +23 |
| **UNMATCHED** | 157 | **0** | −157 |

159 of 720 combinations changed band. Every transition:

| From | To | n |
|---|---|---:|
| UNMATCHED | track | 90 |
| UNMATCHED | scheduled | 43 |
| UNMATCHED | deprioritize_candidate | 21 |
| UNMATCHED | act_soon | 3 |
| track | deprioritize_candidate | **2** |

**`act_now` is unchanged at +0.** No escalation path was weakened by the repair — the property that matters most, and the one a reviewer should check first.

Of the 23 combinations entering `deprioritize_candidate`, 21 are `not_deployed` cases that had no band at all before, and **2** are the low+enforcing pair that D2 unblocked. Both sets were enumerated and reviewed, which is what §7.2 step 3 demands and what makes this a change rather than a drift.

---

## 6. The finding that is not a defect

Running the repaired model over the 50-finding corpus:

| Class | n | Band distribution |
|---|---:|---|
| **SCA** | 30 | act_now 10 · act_soon 4 · scheduled 3 · track 5 · **deprioritize 8** |
| **SAST** | 14 | **track 14** |
| **Secret** | 4 | **track 4** |
| Container | 2 | act_now 2 |

> **Every SAST and every secret finding lands on `track`. All eighteen of them. The deterministic model has no opinion about 36% of a realistic corpus.**

The mechanism is straightforward once seen: DP3 `applicability` is derived from advisory version ranges, scanner reachability verdicts and dependency scope. A SAST finding has **no version range, no package, no advisory**. So `applicability` is `unknown`, and `unknown` routes to `track` regardless of anything else.

Nothing is broken. The model simply has no features for the class.

### 6.1 What this invalidates

| Claim | Status |
|---|---|
| **ADR-0008: the pre-filter disposes of ~80% of findings deterministically** | **At risk.** It cannot dispose of *any* SAST or secret finding. If those are 35% of a customer's volume, the ceiling is 65% before a single judgment is made. The ≤20% LLM-touch-rate target and the $750/month COGS ceiling both rest on this |
| **`evaluation-system.md` §3.4: the standing deterministic-only ablation** | **Would be misread.** The LLM will show a large advantage on SAST — because the deterministic path has no features there, not because it reasons worse. **The ablation must be reported per finding class or it measures feature availability and calls it reasoning** |
| **V2's experiment design** | Must stratify results by class. A blended accuracy number over this corpus is 60% a statement about SCA |

### 6.2 The other number

46% of the corpus resolves through a *"we do not know"* path — 36% via unknown applicability, 10% via the catch-all. The catch-all is **load-bearing on real data**, not a theoretical backstop: five ordinary findings (internal service, applicable, high criticality, no exploit evidence) reach a band only because it exists.

Stated plainly: **on a realistic corpus the deterministic model gives a confident answer for about half the findings and shrugs at the other half.** That is not a failure — it is the honest baseline, and it is precisely the gap the evidence layer and the model are supposed to close. But it has to be measured before it can be claimed, and until today it was assumed.

---

## 7. What still works

Worth recording, because a document that only lists defects is not a report:

- **S1 → 6/6 `act_now`.** The floor check passes cleanly. Disagreement there would have meant the instrument was broken.
- **The Tomcat pair behaves as designed.** NW-004 and NW-008 sit on the same service at the same Tomcat version, both KEV-listed, both near-maximum EPSS. The model independently derives `applicability=applicable` for one and `not_applicable` for the other, from the real advisory ranges — and still escalates NW-008 to `act_soon` rather than deprioritizing it, because KEV listing makes it an inventory claim. That is the intended behaviour arriving without being special-cased.
- **All three worked examples in `risk-model.md` §11 pass**, including the fail-closed case: unresolved criticality yields `track` and `auto_deprioritize_eligible = false` with `criticality_unresolved` recorded.
- **14 non-suppressible findings correctly flagged**; none reachable by any deprioritization path.

---

## 8. Follow-ups

| # | Item | Owner | Why |
|---|---|---|---|
| **F-1** | **Decide what the deterministic layer can say about SAST at all** — and if the answer is "nothing", say so in ADR-0008 and re-derive the 80% claim and the cost model from a 65% ceiling | policy | The economics depend on it |
| **F-2** | Report the standing ablation **per finding class**, never blended | analysis | Otherwise it measures feature availability and reports it as reasoning |
| **F-3** | Promote the repaired tree into `risk-model.md` §4.2 with its 720-row fixture | policy | The document currently publishes a tree that does not terminate |
| **F-4** | Add a CI assertion: **the tree must be total, and no row may be dead** | policy | Both defects are mechanically detectable and neither would survive a test |
| **F-5** | Reconsider whether the low+enforcing deprioritization ground is worth keeping at 2 of 720 | policy | Two grounds in prose, one in practice |
| **F-6** | Decide whether `not_deployed` should also gate auto-deprioritize eligibility separately from the band | policy | A staging finding that becomes production is exactly an ADR-0016 invalidation condition |

---

## 9. The general lesson

This is the third time in three days that executing a document has found a defect prose review did not: the corpus builder rejected two non-KEV entries and a Maven package on a Node service; the κ analyser found gate eligibility resting on shared ignorance; the risk model turned out not to terminate.

The pattern is consistent enough to be a rule:

> **A specification that has never been executed is a draft, however carefully it was reviewed.** The cost of executing it is hours. The cost of discovering the same defects after a schema is built on them is months.
