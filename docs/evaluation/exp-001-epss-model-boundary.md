# EXP-001 — EPSS model-version boundary: measured trigger inflation

**Run:** 2026-08-16 · **Type:** feasibility check, pre-Phase-0 · **Cost:** ~20 minutes, public data only
**Motivated by:** `phase-0-protocols.md` §1.3 — V1's historical evidence sources were asserted, not verified
**Confirms:** ADR-0013 §1 (*"a model-version change is a global evidence-invalidation event"*) — now with a number
**Changes:** `phase-0-protocols.md` §1.3 · `risk-model.md` §7.3 · `threat-model.md` §0.1 · ADR-0013 §1

---

## 0. Result in one line

> **Crossing an EPSS model-version boundary produces 235× more threshold crossings than ten days of the world actually changing.**

A re-litigation engine that treats an EPSS threshold crossing as a wake-up signal, without gating on model version, would wake **27% of a customer's below-threshold suppressions on a single night** — the night the EPSS model updates. That is a product-ending incident delivered by a routine upstream release.

---

## 1. Why this was run before Phase 0

`phase-0-protocols.md` §1.3 asserted that V1's backtest requires as-of evidence reconstruction, and listed EPSS daily snapshots as *"exact, with effort."* That was an assumption. Discovering it was wrong **after** a design partner hands over an export would waste the scarcest resource in the project (V0 partners), so it was checked first.

Two questions:

1. Are the historical sources actually retrievable?
2. If they are, is a naive as-of comparison valid?

The answer to (1) is yes. The answer to (2) is **no, and by a large margin.**

---

## 2. Sources verified

| Source | Result | Detail |
|---|---|---|
| **CISA KEV** | ✅ **Exact point-in-time reconstruction** | 1,665 entries, `dateAdded` per entry from **2021-11-03** to 2026-08-11. Catalog `2026.08.14`. 181 additions in 2026 YTD ≈ **~24/month** — the expected V1 yield for this trigger |
| **EPSS daily snapshots** | ✅ Retrievable back to at least 2023-06 | `epss_scores-YYYY-MM-DD.csv.gz`. **Each file carries its own `model_version` in a header comment** — the pin travels with the data, which is what makes the check below possible at all |
| Advisory ranges (GHSA/OSV) | ⚠️ Not tested here | Reconstructible from repository history for GHSA; weak for vendor PSIRTs. Carried forward |
| Reachability / exposure / ownership history | ❌ Not available | Customer-side history that does not exist in an export. **Excluded from V1** as the protocol predicted |

### 2.1 The EPSS model-version timeline, read off the data

Probed by fetching the header of nine daily files:

| Model version | In force | Corresponds to |
|---|---|---|
| `v2023.03.01` | ≤2023-06-01 → 2025-03-10 | EPSS v3 |
| `v2025.03.14` | 2025-03-20 → 2026-06-10 | EPSS v4 (ADR-0013: *"v4 shipped 2025-03-17"*) |
| **`v2026.06.15`** | **2026-06-20 → present** | EPSS v5 (ADR-0013: *"publishing since 2026-06-15"*) |

**ADR-0013's dates are confirmed against primary data.** That is worth stating: an inherited claim in this repository was checked and held.

> **New requirement:** pin the **model version string the feed emits** (`v2026.06.15`), not the marketing version (`v5`). Code that matches on "v5" matches nothing. ADR-0013 §1 says `epss_model_version` on every evidence record; this fixes its value domain.

---

## 3. The measurement

Two comparisons, both over a **10-day gap**, so elapsed time is held constant and only the model boundary differs.

| | Treatment | Control |
|---|---|---|
| Window | 2026-06-10 → 2026-06-20 | 2026-08-04 → 2026-08-14 |
| Models | `v2025.03.14` → **`v2026.06.15`** | `v2026.06.15` → `v2026.06.15` |
| CVEs compared | 339,488 | 355,076 |

### 3.1 Raw score crossings

| Threshold | Crossed **up** — boundary | Crossed **up** — control | Inflation |
|---|---:|---:|---:|
| 0.01 | **71,885** (27.36%) | 306 (0.145%) | **235×** |
| 0.05 | 7,637 (2.50%) | 44 (0.014%) | 174× |
| 0.10 | 3,826 (1.21%) | 38 (0.011%) | 101× |
| 0.20 | 2,196 (0.68%) | — | — |
| 0.50 | 1,010 (0.30%) | — | — |

| Distribution | Boundary | Control |
|---|---|---|
| Scores **unchanged** | **0.0%** | **90.6%** |
| Mean absolute Δ | 0.0219 | **0.0001** |
| Δ percentiles (p1 / median / p99) | −0.3398 / 0.0029 / 0.1179 | — |

Two things in that table matter more than the headline:

- **Not one CVE in 339,488 kept its score across the boundary.** A model change is not a partial update; it is a complete re-scoring of the corpus.
- **In the control, 90.6% of scores did not move at all in ten days.** EPSS is quiet within a model epoch. That quietness is what makes it a usable trigger — and exactly what makes the boundary catastrophic by contrast.

### 3.2 Percentile is not the mitigation

The obvious fix is to trigger on `epss_percentile` rather than the raw score, on the theory that a rank is model-relative and therefore stable. It is not:

| Percentile threshold | Crossed up | Crossed down | Spurious up-crossings |
|---|---:|---:|---:|
| p50 | 29,133 | 28,151 | **17.17%** |
| p80 | 17,055 | 16,642 | 6.28% |
| p90 | 9,998 | 9,790 | 3.27% |
| p95 | 5,408 | 5,304 | 1.68% |
| p99 | 1,301 | 1,280 | 0.39% |

Mean absolute percentile Δ across the boundary is **0.1195** — five times larger than the raw-score Δ. A new model reshuffles the whole ranking, so a rank-based trigger inherits the reshuffle. **Percentile is better for *ordering* (`risk-model.md` §5.1 is right to use it) and worse for *triggering*.** Those are different jobs and the same number does not serve both.

### 3.3 Direction

At thresholds ≥0.05, down-crossings exceed up-crossings (e.g. 9,819 down vs 3,826 up at 0.10). The new model is more conservative in the upper range and more generous at the very bottom. **The dangerous direction is the down-crossings**: a naive system would treat those as "risk decreased" and become *more* willing to suppress, silently, on the same night.

---

## 4. What this changes

### 4.1 In the product

| Rule | Statement |
|---|---|
| **R1** | An EPSS threshold comparison is valid **only between two observations under the same `model_version`.** Not smoothed, not tolerated — gated |
| **R2** | A model-version bump triggers a **one-time re-baseline**, not a wave of notifications. Every EPSS-derived feature is recomputed under the new model and the new value becomes the new baseline. **No `ReopenEvent` is emitted for a change attributable to the bump** |
| **R3** | The re-baseline is a `reprocessing_job` with a **band-transition matrix** (`risk-model.md` §7.2), reviewed before promotion, exactly like a scoring-model change — because that is what it is |
| **R4** | Findings whose *only* trigger is an EPSS crossing spanning a boundary are **suppressed from the re-open queue** and reported separately as "model-attributable" |
| **R5** | Pin the feed's own `model_version` string. Store it on every EPSS evidence record (ADR-0013 §1 already requires the field; this fixes its domain) |

R2 is the load-bearing one and it is counter-intuitive: **the correct response to "all the numbers changed" is to emit nothing.** A system that faithfully reports every change is precisely the alert-fatigue source `evaluation-system.md` §3.3 alarms on, and it would do it on day one of an upstream release with no warning.

### 4.2 In Phase 0

**The EPSS trigger cannot be used in V1 at all.** The current model epoch began ~2026-06-15, which is ~2 months of history. A 12-month backtest crosses one boundary; a 24-month backtest crosses two. Re-scoring history under a single model is impossible — we do not have the model.

V1's usable trigger set is therefore:

| Trigger | V1 status |
|---|---|
| **KEV listing** | ✅ Exact. ~24 additions/month, `dateAdded` per entry |
| **Advisory range narrowing** | ⚠️ Partial — GHSA reconstructible, PSIRT weak |
| Exploit published | ⚠️ Approximate — publication dates, not availability |
| EPSS threshold crossing | ❌ **Excluded. Model boundaries make it uncomputable over the window** |
| Reachability / exposure / ownership change | ❌ Not in an export |

This sharpens `phase-0-protocols.md` §1.3 from *"realistically 2–3 triggers"* to a specific, defensible list — **one exact trigger and one partial one.** State that to partners up front. If one exact trigger already surfaces a finding an AppSec director calls alarming, the full set can only do better; claiming seven on data that cannot support them turns a backtest into a demo.

---

## 5. Threats to this result

| Threat | Assessment |
|---|---|
| One boundary observed (v4→v5) | The v3→v4 boundary was not measured. **Assume the same order of magnitude; do not assume this one is worst-case** |
| 10-day windows may not represent typical inter-observation gaps | The control establishes the same-model rate at ~0.145%/10 days; longer gaps raise it roughly linearly, nowhere near 27% |
| Thresholds chosen by the analyst, not by policy | No SDIP EPSS policy threshold is set yet. Five were reported so the effect is visible at whatever value is eventually chosen |
| The corpus grew (339,504 → 341,602) between snapshots | Comparison restricted to the 339,488 CVEs present in both |

---

## 6. Reproduction

```
KEV      https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
EPSS     https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz
         (line 1 is "#model_version:...,score_date:..." — read it, do not skip it blindly)

Treatment: 2026-06-10 vs 2026-06-20   (v2025.03.14 -> v2026.06.15)
Control:   2026-08-04 vs 2026-08-14   (v2026.06.15 -> v2026.06.15)
Compare on the CVE intersection; count threshold crossings in both directions.
```

The control is not optional. Without it, 71,885 crossings is a large number with no meaning; against 306 it is a design decision.

---

## 7. Follow-ups

| # | Item | Owner | Why |
|---|---|---|---|
| F-1 | Measure the v3→v4 boundary (2025-03-10 vs 2025-03-20) | policy | Is 235× typical or is v5 unusual? |
| F-2 | Add a **model-boundary fixture** to the eval harness: two snapshots either side of a boundary; assert **zero** `ReopenEvent`s attributable to the bump | policy | R2 is a rule until it is a test |
| F-3 | Check whether the same discontinuity exists in **KEV** (schema changes) and **NVD CVSS** (rescoring) | retrieval | KEV is append-only so likely not; NVD's 2026-04-15 enrichment change is a candidate |
| F-4 | Decide the SDIP EPSS policy threshold **and** its model-epoch handling together | policy | They are one decision, and choosing the threshold first is how R1 gets forgotten |
