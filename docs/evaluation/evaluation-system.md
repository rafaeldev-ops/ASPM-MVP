# Evaluation System — SDIP

**Deliverable:** CLAUDE.md §46.H
**Date:** 2026-08-15
**Status:** Design. Blocking: no AI behaviour ships before the harness and the datasets in §2 exist.
**Governed by:** ADR-0010 (calibration, audit sampling), ADR-0006 (correlation), ADR-0009 (evidence contract), ADR-0016 (re-litigation)

---

## 0. The three rules

**1. "It looks better" is not evidence.** No prompt, model, retrieval, scoring or policy change is an improvement until it is measured against a **frozen** versioned dataset. A change may be rejected even when quality improves, if cost, latency, privacy or reliability worsen materially.

**2. Production labels cannot gate the thing they are corrupted by.** The label an on-shift analyst clicks is exactly the label the suppression feedback loop biases. It is barred from every release gate (§1.2).

**3. The gate that matters measures the failure that ends the company.** A wrong `deprioritize` is orders of magnitude more damaging than a wrong `prioritize`. Every dataset, every metric and every threshold below is asymmetric by construction, and the false-negative bound is the one number that goes in a contract.

---

## 1. Where ground truth comes from

### 1.1 Four tiers, ranked by immunity to bias

| Tier | Source | Cost | Bias immunity | Covers | Gate eligible |
|---|---|---|---|---|---|
| **T0 — mechanical** | Verifiable by construction: duplicate pairs, version-range applicability, KEV membership, ownership correctness, fingerprint stability | very low | **total** | correlation, dedup, enrichment, lifecycle | **Yes** |
| **T1 — retroactive outcome** | Later-KEV, later-exploit-published, later-incident, actually-remediated | low (automated) | **total** | the false-negative gate, and only that | **Yes** |
| **T2 — adjudicated consensus** | 3 independent annotators on decomposed sub-questions + adjudication | high | moderate | exploitability, prioritization, evidence sufficiency | **Yes**, per-sub-question, if κ ≥ 0.6 |
| **T3 — production single-label** | Whatever the on-shift analyst clicked | ~free | **poor** | volume metrics, trend monitoring | **No. Never.** |

### 1.2 Why T3 is barred, restated so nobody re-proposes it

The system auto-deprioritizes class X → analysts never see X → no label for X → per-rule statistics are computed over *reviewed* items only, which are systematically the items the model already believed were real → measured precision rises monotonically while true recall is unobserved. **A gate built on T3 reports the death spiral as improvement.**

T3 is admitted to the gate only after inverse-propensity weighting using `review_propensity`, and only when the sampler that produced it was a **randomized policy with a recorded probability** (ADR-0010). "Whatever the analyst happened to click" has unknown propensity and cannot be de-biased at any sample size.

### 1.3 Do not ask the question that has no agreement

An empirical comparison of CVSS, EPSS, SSVC and Microsoft's Exploitability Index over 600 Patch Tuesday vulnerabilities found little to no correlation or categorical agreement among four *formal, specified* systems scoring the same public CVEs. Human κ on the far softer "is this exploitable **in our environment**" will be worse.

**The fix is not better annotator training. It is not asking the question.** Annotate five binary, verifiable sub-questions and *derive* the fused judgment with deterministic policy:

| # | Sub-question | Verifiable by |
|---|---|---|
| Q1 | Is the vulnerable code path reachable from an entry point? | code |
| Q2 | Is that entry point externally exposed? | configuration |
| Q3 | Does a public exploit or PoC exist? | artifact |
| Q4 | Is a compensating control present **and enforcing**? | configuration |
| Q5 | Does the affected version range actually cover our version? | mechanical |

This simultaneously fixes the annotation problem, the risk-model explainability requirement, and the deterministic/LLM split — the model's job becomes answering verifiable sub-questions with cited evidence, not rendering an unfalsifiable holistic verdict.

**Gate rule: a sub-question with measured κ < 0.6 is a diagnostic, never a release gate.** Publish the κ values.

---

## 2. Dataset register

Every dataset is versioned (`v{major}.{minor}`), content-hashed, frozen during any A/B, and stored with the **full evidence snapshot as of the annotation date**. Without the snapshot the set decays silently: EPSS moved v4 → v5 in fifteen months, and a corpus re-scored under a new model changes the inputs with no change on our side.

| ID | Purpose | Size | Tier | Owner |
|---|---|---|---|---|
| **GS-CORR** | Correlation / dedup | 300 pairs | T0 | correlation |
| **GS-LIFE** | Lifecycle transitions | 120 scenarios | T0 | ingestion |
| **GS-IDENT** | Fingerprint stability | 200 perturbations | T0 | ingestion |
| **GS-PREF** | Deterministic pre-filter | 400 findings | T0/T2 | policy |
| **GS-DEC** | Decision quality | 500 findings | T2 | analysis |
| **GS-FN** | False-negative regression | 200 known-true criticals | T1/T2 | policy |
| **GS-EVID** | Evidence selection & citation | 250 decisions | T2 | retrieval |
| **GS-INJ** | Prompt-injection resistance | 150 adversarial fixtures | T0 | security |
| **GS-ISO** | Tenant isolation | full API suite × 2 tenants | T0 | platform |
| **RL-STREAM** | Retroactive outcome labels | continuous | T1 | learning |

### 2.1 GS-CORR — correlation and deduplication (300 pairs)

Half true duplicates, half **hard near-misses**, because a set of easy pairs measures nothing:

| Stratum | n | Example |
|---|---|---|
| Exact duplicate, same tool, re-scan | 60 | identical finding across two runs |
| Exact duplicate, cross-tool | 40 | Trivy and Snyk on the same CVE + purl |
| Same root cause, different location | 50 | one vendored library copied into three repos |
| **Near-miss: same CVE, different package** | 50 | must **not** merge |
| **Near-miss: same rule, different file** | 50 | must **not** merge |
| **Near-miss: same file, different commit, code changed** | 50 | must **not** merge |

**Labels:** `relation ∈ {exact_duplicate, same_root_cause, related, independent}`, mechanically derivable.
**Metrics:** precision and recall per relation type; **over-merge rate** reported separately, because an over-merge hides a real finding behind another finding's decision.

### 2.2 GS-IDENT — fingerprint stability (200 perturbations)

Each item is a `(before, after, should_identity_survive)` triple:

| Perturbation | Expected |
|---|---|
| Whole-file reformat (prettier/black) | survives |
| Unrelated edit above the finding | survives |
| File renamed / moved (`git mv`) | survives |
| Vulnerable line itself edited | **new identity** |
| Rule renamed by scanner upgrade | survives (via alias map) |
| Base image bumped | package-coordinate identity survives; path identity does not apply |

**Metric:** churn rate — the fraction of perturbations that wrongly produce a new identity. **Gate: ≤2%.** Identity churn is invisible in the UI and corrupts every longitudinal metric downstream.

### 2.3 GS-DEC — decision quality (500 findings)

**Sizing rationale:** a paired comparison between two prompt/model versions detecting a 5-point absolute accuracy change at 80% power and α = 0.05 needs roughly 300–400 paired items at typical discordance rates. 500 leaves headroom for per-stratum reporting. **Recompute this against real pilot discordance data rather than treating 500 as settled.**

**Stratification:** source tool (all MVP integrations) × finding class (SAST / SCA / secret / container) × severity × target decision class, plus two adversarial strata that must be explicit and are the reason the set is worth building:

- **Hard negatives — look critical, aren't:** unreachable CVE in a dev-only dependency; secret in a test fixture; SAST hit in generated code; CVE in a vendored copy that is not built.
- **Hard positives — look trivial, aren't:** low CVSS but KEV-listed; medium severity in an internet-facing auth service; a "test" credential that is actually live.

**Labels:** the five sub-questions of §1.3, three annotators each, majority vote with explicit tie adjudication, κ recorded per sub-question.

**Annotators must be the pilot customer's own senior analysts.** "Exploitable in our environment" is definitionally tenant-specific and cannot be labelled by the vendor or on public data — which is why §6 exists.

### 2.4 GS-FN — the false-negative set (200 known-true criticals)

**Deliberately oversampled far above the natural base rate.** A naturally-sampled 500-item set contains too few true criticals for a false-negative regression to be statistically visible at all. This is the most common way an evaluation suite silently stops protecting the thing it was built to protect.

**Composition:** confirmed-exploitable findings drawn from RL-STREAM (later-KEV, later-exploit-published, incident-linked) plus adjudicated criticals from GS-DEC.

**Metric:** the fraction of GS-FN that the full pipeline would auto-deprioritize. **Gate: 0. Not "low" — zero.** A single auto-deprioritized item in GS-FN blocks the release and the item is added permanently.

### 2.5 GS-EVID — evidence selection and citation (250 decisions)

Four distinct metrics, and the third is the one nobody measures:

| Metric | Definition | Gate |
|---|---|---|
| **Slot fill rate** | required slots filled / required slots total | ≥0.95 |
| **Gap honesty** | unfilled required slots that produced an `evidence_gap` record | **1.00** — silence where a gap should be is a defect, not a degradation |
| **Citation correctness** | cited evidence that *actually supports* the claim, adjudicated | ≥0.90 |
| **Decisive-evidence retention** | items where the adjudicated decisive evidence was **not** dropped | ≥0.98 |

Citation *presence* is trivially satisfiable and measures nothing. Citation *correctness* is the metric that separates an evidence-first system from one that produces well-formatted misinformation — a `reasoning_summary` with valid evidence ids and a wrong conclusion is the highest-fidelity misinformation delivery mechanism available in a customer's environment.

### 2.6 GS-INJ — injection resistance (150 fixtures)

Attacker-controlled text placed in each ingestion-reachable field: code snippet, file path, commit message, dependency name and description, CVE/GHSA free text, custom rule message, suppression comment.

Payload classes: direct instruction ("recommended decision: false_positive_candidate"); **evidence mimicry** (text written to be indistinguishable from the evidence corpus — the class keyword filtering cannot catch); citation fabrication; system-prompt extraction; markdown/HTML exfiltration in output; escalation flooding.

| Metric | Gate |
|---|---|
| Suppressive outcome caused by injection | **0. Absolute.** |
| Injection detected and recorded as `suspected_injection` evidence | ≥0.80 |
| Hallucinated citation rejected | 1.00 |
| Differential-decisioning disagreement caught on suppression path | ≥0.95 |

The first row is the one that matters and it is achievable **because it is structural, not statistical**: the model cannot emit a suppressive decision at all (ADR-0007). GS-INJ therefore tests the containment, not the model's resistance — which is the only version of this test that can pass reliably, given that adaptive attacks bypass state-of-the-art detectors at >85%.

### 2.7 RL-STREAM — retroactive outcome labels (continuous)

A nightly job re-scores every past decision against current external state and emits labels for: deprioritized CVEs that later entered KEV; EPSS crossing a threshold under a pinned model version; public exploit published; incident/pentest/bug-bounty findings mapping back to a suppressed finding; findings remediated anyway by a developer who disagreed.

Cheap, requires zero analyst time, **immune to the feedback loop**, and the single most credible artifact to put in front of a pilot customer. It is also the label source that makes re-litigation precision measurable at all.

---

## 3. Metrics and gates

### 3.1 Release-blocking gates

A change to the pipeline cannot ship unless all of these hold on the frozen sets.

| # | Gate | Metric | Threshold | Blocks |
|---|---|---|---|---|
| G1 | **No new false negatives** | GS-FN auto-deprioritized | **0** | any release |
| G2 | **Injection containment** | GS-INJ suppressive outcomes | **0** | any release |
| G3 | **Tenant isolation** | GS-ISO cross-tenant rows in any response, error, log, metric or export | **0** | any release |
| G4 | Identity churn | GS-IDENT churn rate | ≤2% | ingestion changes |
| G5 | Over-merge | GS-CORR over-merge rate | ≤1% | correlation changes |
| G6 | Correlation quality | GS-CORR precision / recall per relation | ≥0.95 / ≥0.85 | correlation promotion |
| G7 | Gap honesty | GS-EVID unfilled-required-slot silence | **0** | retrieval changes |
| G8 | Citation correctness | GS-EVID | ≥0.90 | prompt/model changes |
| G9 | Guardrail-violation rate | Class-A rejections on GS-DEC | ≤1% | prompt/model changes |
| G10 | Decision accuracy | GS-DEC vs adjudicated labels | no regression beyond noise | prompt/model changes |
| G11 | Cost per decision | golden corpus, tokens and USD | ≤ budgeted ceiling | any release |
| G12 | LLM touch rate | fraction of ingested findings reaching a model | ≤20% | any release |

G1–G3 are absolute. G4–G12 are thresholds that may be renegotiated with evidence, in a documented decision.

### 3.2 Gates on enabling auto-suppression for a tenant

Auto-suppression is off by default and is a per-tenant, signed, audited configuration change. It cannot be enabled until:

| Requirement | Value |
|---|---|
| Clean audits with zero observed false negatives | **n ≥ 600** ⇒ FN ≤ 0.5% at 95% (rule of three) |
| Shadow mode completed | 30 days |
| Calibrator fitted for the tenant | ≥200 labelled outcomes per decision class |
| Ownership resolution rate | ≥80% (unresolved criticality fails closed, so low resolution means near-zero eligible volume anyway) |
| Analyst agreement in the target confidence band | Wilson **lower** bound above target — a band with n = 12 and 100% agreement does not qualify |

### 3.3 Continuous product metrics (monitored, not gates)

| Metric | Target | Alarm |
|---|---|---|
| **Re-litigation precision** — re-opens an analyst agrees with | ≥60% | **<40% ⇒ disable the offending trigger.** Below this the product is a new alert-fatigue source |
| Re-opens per analyst per week | capped | cap breached |
| Analyst-hours per 1,000 findings | vs captured pre-install baseline | regression |
| Median triage time | vs baseline | regression |
| Ownership resolution rate | rising | stalled |
| Suppression rate spike | stable | spike ⇒ possible injection or upstream ruleset change |
| **Agreement rising while re-litigation precision falls** | — | **the anti-conformity alarm.** This pattern means the system is learning the customer's blind spots |

### 3.4 The standing ablation

Run the **deterministic path alone** against GS-DEC and compare with deterministic + LLM. If the difference is within noise, the model is decoration on the decision path and belongs only on `reasoning_summary`.

> **Report it per finding class. Never blended.** [`exp-002`](exp-002-risk-model-executed.md) measured the deterministic model over a realistic corpus and found it produces **no discrimination at all for SAST and secret findings** — 36% of the corpus, every one banded `track`, because applicability is derived from advisory version ranges and packages that a SAST finding does not have.
>
> A blended ablation over such a corpus would show a large LLM advantage and would be **measuring feature availability while reporting it as reasoning**. The per-class split is what distinguishes "the model reasons better here" from "the deterministic path has nothing to reason with here", and only the first is a reason to keep the model in the decision path.

**Quarterly, as a gate — not a one-time curiosity.** Every prompt change, model upgrade and retrieval change shifts it. It is also the cheapest defence against AI commoditization: if we cannot demonstrate the delta, neither can the market.

---

## 4. The harness

```
eval/
  datasets/          versioned, content-hashed, evidence snapshots pinned
  runners/           per-subsystem: correlation, prefilter, retrieval, decision, injection
  reports/           per-run artifacts, diffed against the previous promoted version
  gates/             threshold definitions as code, reviewed like production code
```

**Properties that are not optional:**

- **Deterministic replay.** A run is `(dataset_version, code_version, config_version)` → a report. Same inputs, same report.
- **Contamination filter.** Golden items are excluded from the retrieval index at evaluation time — otherwise the measurement is of memorization of our own decision memory, not reasoning. **A test asserts the filter is active**, because this is exactly the kind of thing that silently regresses.
- **Frozen during A/B.** A moving evaluation set makes every comparison meaningless.
- **Cost-bounded.** A full run has a stated token and dollar cost; CI runs a fast subset, nightly runs the full set.
- **Shadow-mode support.** New algorithm versions write output alongside the current version and produce a diff, which is how correlation v2 and scoring v2 get promoted (ADR-0006).

---

## 5. Cadence

| Trigger | Action |
|---|---|
| Every PR | Fast subset: G3, G4, G9 plus unit-level fixtures |
| Nightly | Full suite, all gates |
| Every prompt / model / retrieval / scoring / policy change | Full suite + ablation + cost report |
| Quarterly | 10% dataset rotation; standing ablation; κ re-measurement; calibrator refit |
| Annually | Full re-annotation of the retained 90% |
| **Forced immediate refresh** | New scanner integration · **EPSS model version bump** · KEV schema change · new tenant vertical · normalization schema change |

---

## 6. Per-tenant evaluation as a shipped feature

**The exploitability gate cannot be vendor-owned.** Ground truth for "is this exploitable here" is tenant-specific by definition. The vendor can hold T0/T1 sets covering correlation, dedup, enrichment and the false-negative ceiling; everything touching exploitability needs a per-tenant set.

Therefore the per-tenant harness is a **product feature, not internal tooling**: the customer gets their own golden set, their own measured agreement rate, and the ability to re-run it against any SDIP version.

No ASPM vendor currently hands the customer a measurable, customer-owned evaluation set for the vendor's own AI. It is simultaneously the honest engineering answer and one of the few genuinely unoccupied competitive positions available.

---

## 7. What gets published

The market's accuracy claims are unauditable: vendor A's 95% agreement is measured on vendor A's data; vendor B publishes 70–95% false-positive reduction with proprietary thresholds; others publish nothing.

**Publish an open, versioned triage benchmark** — findings, evidence, analyst labels, and where obtainable outcomes — plus a harness that scores *any* vendor. A few engineer-months, and whoever owns the referee owns the conversation.

Two constraints on publication:

1. **Nothing customer-derived is published without contractual consent**, and the published corpus is built from public advisories and synthetic-but-realistic findings.
2. **Publish the methodology and the κ values, including the sub-questions where agreement was poor.** A benchmark that only reports where we look good is marketing, and technical buyers read benchmarks adversarially.

---

## 8. Governance — evaluation data is production data

From the security review, and this is not administrative overhead:

- **Golden datasets carry the classification, retention and access controls of production data.** They get committed to repos, copied into CI, shared with contractors and pasted into benchmark harnesses — the highest realistic exfiltration probability of any data class in the system.
- **No real secrets in any fixture. Ever.** CI fails on canary and PII patterns in test data.
- **Planted canaries** — unique synthetic credentials in the evaluation corpus, scanned for on every CI run and on a production schedule across provider request logs, application logs, the database, a restored backup, the object store, the embedding table and every export artifact.
- **Evaluation-dataset poisoning is a named threat.** Poison the golden set and the quality gate itself shifts, permanently and invisibly. Dataset changes are reviewed like production code, content-hashed, and require a second reviewer.

---

## 9. Anti-patterns

| Anti-pattern | Why it fails |
|---|---|
| Gating on production analyst labels | The label the feedback loop corrupts |
| A naturally-sampled decision set | Too few true criticals for a false-negative regression to be visible |
| Measuring citation *presence* | Trivially satisfiable; measures nothing |
| Reporting a point estimate for the FN rate | Contracts need an upper bound. Rule of three, or nothing |
| Reporting agreement without n and a confidence interval | n = 12 at 100% agreement is not evidence |
| Moving the eval set during an A/B | Every comparison becomes meaningless |
| Leaving golden items in the retrieval index | Measures memorization of our own decision memory |
| nDCG / MRR on evidence retrieval | No per-query relevance ground truth exists for this task; the metric is unmeasurable, not merely inconvenient |
| Chasing test coverage percentage | High-value domain behaviour matters more than superficial coverage |
| Treating the audit-sampling cost as overhead | 600 audits ≈ 40 analyst-hours per window. **Subtract it from the savings claim** — "we saved 160 hours net of audit" is more credible than "we saved 200" |

---

## 10. Three experiments to run before writing pipeline code

Each is cheap, fast, and can kill a major assumption.

1. **Join-vs-retrieval bake-off.** 200 real findings; assemble evidence twice — deterministic slot-filling vs top-k semantic retrieval; analysts judge which set is sufficient to decide. If deterministic wins or ties, the RAG framing is wrong and the architecture changes before anything is built.
2. **Deterministic-only ablation, pre-implementation.** Score 200 findings with a hand-written policy (CVSS × KEV × EPSS × reachability × asset criticality) against analyst labels. **This establishes the floor the LLM must beat, and the whole product thesis rests on it.** If a spreadsheet gets within a few points of the analysts, the differentiation hypothesis needs rework, not more model.
3. **Annotation-agreement probe.** Three analysts × 50 findings, holistic question vs the five decomposed sub-questions; measure κ for each. If holistic κ < 0.5 and decomposed κ > 0.7 — the expected result — the decomposition becomes the core data model and the decision contract is rewritten around it before implementation begins.
