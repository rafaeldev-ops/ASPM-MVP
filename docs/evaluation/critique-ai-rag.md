# Critique: AI and Retrieval Design (SDIP)

**Scope:** CLAUDE.md §7, §11–17, §26–30
**Lens:** Applied AI / RAG / knowledge graphs / ML systems
**Date:** 2026-08-14
**Status:** Pre-implementation review. Nothing here is a request to write code.

---

## 0. Summary judgment

The brief is unusually disciplined about *what not to build* and unusually vague about *what the intelligence layer actually computes*. Every hard decision in the AI design is deferred behind a noun: "Evidence Ranking," "Context Compression," "deliberately search for contradictory evidence," "hybrid model." None of these name an algorithm, a cost, a latency, or a failure rate. As written, §11 is a box diagram, not a design.

Five findings are load-bearing:

1. **The Context Engine is misframed as a retrieval problem when it is mostly a join problem.** Roughly six of the eight evidence classes in §8 have deterministic join keys. Framing this as RAG will produce a vector-first pipeline where a SQL-first pipeline wins on latency, cost, determinism, and — critically — evaluability.
2. **The feedback loop in §15+§16+§17 is a suppression death spiral with positive gain.** This is the single most dangerous flaw in the design and the brief acknowledges it in one sentence ("Avoid leakage and circular reasoning") with no mechanism. It needs a randomized audit with logged propensities, and that costs real analyst hours that must appear in the product's cost model.
3. **Confidence (§27) has seven listed inputs and no combination function, and the two obvious calibration techniques are unavailable on the model family the brief will most likely pick.** Temperature is removed on Claude Opus 5 / Sonnet 5 / Opus 4.8+ (400 error), so temperature-based self-consistency ensembles do not work; the documented Messages API surface exposes no logprobs. The provider abstraction in §13 cannot abstract away a missing parameter.
4. **The moat thesis (§4) and the isolation rule (§19) are in direct contradiction, and the cold-start math favors §19 destroying the moat.** Per-tenant decision history takes thousands of labels to beat a cross-tenant prior. Either you build a cross-tenant statistical layer with contractual opt-in, or every customer starts from zero forever and the "data network effect" is actually just per-tenant switching cost.
5. **The evaluation gate (§30) has no ground-truth source, and the one thing it must measure — catastrophic false negatives — is precisely the thing production labels cannot measure.** Retroactive outcome labeling (later-KEV, later-incident, later-exploit) is the only bias-free label source and is missing from the brief entirely.

Positioning note before the technical body: the brief tells us not to claim a differentiator without naming the competitor capability it beats. Endor Labs' AURI already ships "deterministic static reachability analysis layered with specialized agentic triage that converts probabilistic flags into verifiable findings" — which is, almost word for word, SDIP's §7 hybrid thesis. Apiiro and Snyk ship reachability filtering that reduces SCA finding volume by a reported 70–90%. **Deterministic-features-plus-LLM-reasoning is not a differentiator in 2026; it is table stakes.** What is *not* commoditized is the auditable decision record with calibrated confidence bounds and a measured false-negative ceiling. That is the only thing in this document worth positioning around, and it is an evaluation-and-statistics capability, not an AI capability.

---

## 1. The Hybrid Context Engine: there is no fusion algorithm

### 1.1 What §11 actually specifies

Six parallel retrieval branches (external knowledge, organizational, historical decisions, relationships, statistical features, exposure/ownership/business) converge on a box labeled "Evidence Ranking," then a box labeled "Context Compression," then the Decision Engine. The retrieval policy is a preference ordering with six entries and no weights, no scoring function, and no tie-break. §12 requires "reranking" without saying rerank-by-what.

An ordering preference is not a fusion function. "Prefer high-authority sources, then fresh sources, then organization-specific evidence" is lexicographic on three incomparable dimensions; applied literally it means a stale NVD record always outranks a fresh internal decision, which is the opposite of the product thesis.

### 1.2 Name the candidates, with cost

| Algorithm | What it does | Cost / latency | Why it fits or doesn't |
|---|---|---|---|
| **Reciprocal Rank Fusion** (`score = Σ 1/(k+rank_i)`, k=60) | Fuses ranked lists without needing comparable scores | Free; executes in the same Postgres query as the retrieval. Sub-10 ms at the corpus sizes in play (~10⁵–10⁶ chunks) | Solves the score-incompatibility problem that makes naïve weighted averaging fail. **But it is rank-only: it structurally discards the reliability, authority, and freshness scores §8 mandates.** RRF cannot express "NVD outranks a vendor blog." |
| **Weighted score fusion** | Normalize each source's score, weighted sum | Free | Requires per-source score normalization that is unstable across corpora; weights have no principled source until you have labels. Brittle in exactly the way the brief warns against. |
| **Cross-encoder reranker** (Cohere Rerank 4 Pro/Fast, Voyage rerank-2.5) | Jointly scores (query, doc) pairs | ~$2 per 1K searches (1 search = 1 query × ≤100 docs) at Rerank 3.5 pricing; **P50 ≈ 220 ms** per search. 10,000 findings ≈ $20 and ~37 minutes of serial added latency | **Wrong task.** A general-purpose reranker scores *topical relevance to a query*. "Is this finding exploitable in our environment" is not a query it was trained on. You would be paying 220 ms to sort evidence by semantic similarity to a question that semantic similarity does not answer. |
| **Learned reranker** (LambdaMART / gradient-boosted over typed features) | Learns the ranking from relevance labels | Training: hours. Inference: <5 ms | Correct in principle, **impossible on day one**: it needs per-tenant relevance labels that do not exist until the system has been running (see §6, cold start). Chicken-and-egg. |

Reported hybrid-search gains for RRF over pure vector search in Postgres land around 62% → 84% retrieval precision on general corpora. That number is worth knowing and worth *not* citing as a product claim — it is measured on document QA, not on security-decision evidence assembly.

### 1.3 The reframe that matters

Take a concrete SCA finding and enumerate the evidence the decision actually needs:

| Evidence | How you get it |
|---|---|
| CVE record | join on `cve_id` |
| EPSS score + percentile | join on `cve_id` (pin the EPSS model version — see §7.4) |
| CISA KEV membership | join on `cve_id` |
| Affected version range applicability | deterministic comparison against `package@version` |
| Service criticality | join on `service_id` |
| Owner | join on `service_id` / CODEOWNERS |
| Prior decisions on the same rule + repo | join on `(rule_id, repo_id)`, ordered by recency |
| Reachability | computed, not retrieved |
| Compensating controls | join on `service_id` |
| Free-text vendor advisory nuance | **semantic retrieval** |
| Similar-but-not-identical past decisions | **semantic retrieval** |

Nine of eleven are joins or computations. Two need embeddings. **The Context Engine is a structured feature assembly problem with two free-text slots, not an open-domain RAG problem.**

This is not pedantry. Framing drives architecture, and the RAG framing will produce:

- a top-k retrieval step where a typed-slot-filler is correct, so evidence is *ranked* when it should be *required* (a decision missing its KEV lookup should be an error, not a low-ranked chunk);
- retrieval quality metrics (nDCG, MRR) that are unmeasurable on this task because there is no per-query relevance ground truth;
- a latency and cost profile dominated by an embedding round-trip that the majority of evidence never needed.

**Recommendation — two-stage, typed:**

- **Stage A — Evidence Contract (deterministic).** Each finding class (SAST / SCA / secrets / container) declares a *required slot set* and an *optional slot set*. Slots are filled by keyed lookup. A required slot that cannot be filled produces a typed `evidence_gap` record, not silence. `evidence_gap` is then a first-class input to confidence (§3) and a hard blocker for auto-deprioritize (§8).
- **Stage B — Semantic fill (narrow).** Only for the two free-text slots. Hybrid retrieval (pgvector + Postgres FTS) fused with RRF at k=60, top-8 per slot, hard-filtered by `org_id` and `as_of` timestamp *before* ranking, never after.
- **No cross-encoder in the decision path** for the MVP. Revisit only if slot-B precision measured on the golden set is the binding constraint — and measure that before spending 220 ms per finding.

### 1.4 Where "eliminate noise" becomes hand-waving

§11's "Do not retrieve everything / Retrieve what is relevant to the actual decision" and §11's "Context Compression" box are unfalsifiable as written. There is no budget, no drop policy, and no record of what was dropped. Make it concrete:

- **Fixed evidence budget** expressed in tokens, e.g. 8,000, with per-slot quotas so one chatty advisory cannot crowd out the KEV lookup.
- **Drop log:** every dropped evidence ID, its slot, its score, and the reason (`over_budget` / `below_threshold` / `stale` / `duplicate`) persisted with the decision. Without this, the eval question "was the decisive evidence dropped before the model saw it?" is unanswerable, and every retrieval regression will be misattributed to the prompt.
- **Compression must be extractive, not abstractive, in the MVP.** An LLM summarizing evidence before another LLM reasons over it is a second hallucination surface directly upstream of the decision, and it destroys the §8 content-hash provenance chain. Compress by field selection and truncation with explicit markers, not by paraphrase.

---

## 2. Contradiction retrieval (§11) is currently undefined

§11 ends with: "The system must deliberately search for contradictory evidence to reduce confirmation bias." That sentence has no implementation behind it and conflates two different operations.

### 2.1 Retrieval vs. detection

- **Retrieving contradictory evidence** — issuing a query designed to surface disconfirming documents.
- **Detecting contradiction among retrieved evidence** — deciding that two records cannot both be true.

The brief means the first and needs the second. Worse, **the first does not work with dense retrieval.** Embedding models are well documented as insensitive to negation; a query for "evidence that CVE-X is *not* exploitable here" retrieves substantially the same neighbourhood as "evidence that CVE-X is exploitable here." Negation-based query expansion is not a mechanism, it is a hope.

### 2.2 What contradictions actually look like in this domain

They are overwhelmingly **structured field conflicts**, not textual entailment failures:

| Conflict | Detection |
|---|---|
| Vendor advisory says "not affected"; NVD says affected | field comparison |
| CVSS 9.8 but EPSS 0.0003 / percentile < 0.5 | numeric rule |
| KEV-listed but reachability analysis says unreachable | field comparison |
| Analyst marked this rule FP 3× in this repo, but this instance has a different code fingerprint | join + fingerprint compare |
| Scanner A says fixed-in 2.4.1; scanner B still reports on 2.4.3 | version-range comparison |
| Asset registry says internal-only; deployment metadata shows a public ingress | field comparison |

Every one of these is a deterministic rule over typed fields. A table of ~20 such rules covers, by inspection of the evidence classes in §8, the large majority of contradictions this system will ever see — at zero inference cost, with perfect explainability, and with a false-contradiction rate you can drive to near zero by writing the rule correctly.

### 2.3 If you want an NLI model anyway

- **Model:** a DeBERTa-class NLI cross-encoder (~0.4B params) at roughly 15–40 ms per pair on a GPU.
- **Cost shape:** contradiction is pairwise, so it is O(n²) in evidence count. Ten evidence chunks = 45 pairs ≈ 0.7–1.8 s of GPU per finding. At 10,000 findings that is 2–5 GPU-hours per import, plus the operational burden of hosting a model the brief's stack (§21) currently has no place for.
- **False-contradiction rate:** this is the disqualifier. NLI models are documented as brittle, prone to spurious correlations, and weak on nuanced reasoning; on out-of-domain security prose expect contradiction-class precision meaningfully below 0.7. **Now trace the consequence through the brief's own rules:** §27 says low confidence should prefer `needs_review`, and §7 has a `contradicting_evidence_ids` field feeding confidence. A contradiction detector with 30–40% false positives therefore routes a large fraction of findings to human review — which directly destroys the §31 north-star metric ("Verified Risk Decisions per Analyst Hour"). **A miscalibrated contradiction detector is worse than no contradiction detector**, because it converts a silent bias into a loud, quantified workload.
- **LLM-as-judge for contradiction:** richer reasoning, but it is a second model call per evidence pair. At 45 pairs × even Haiku-tier pricing this is more expensive than the decision call itself, and it introduces a self-referential problem — the same model class that may be confirmation-biased is being asked to police confirmation bias.

**Recommendation:**

1. Ship the deterministic conflict-rule table. Version it. Each rule emits a typed `conflict` record with both evidence IDs and a rule ID.
2. Measure the rule table's recall against the golden set's adjudicated conflicts. Publish that number.
3. Only if measured recall is inadequate **and** you have ≥300 human-labeled conflict pairs to measure precision against, introduce an NLI model — and gate it behind a precision floor (e.g. ≥0.85 on the contradiction class) before it is allowed to influence confidence.
4. Never let a detected contradiction directly flip a decision. It adjusts confidence and appears in the evidence record. The decision belongs to the policy engine.

**Verdict: as written, contradiction retrieval is undefined. Do not build an NLI stage yet.**

---

## 3. Confidence (§27): seven inputs, no function, and two dead-end calibration paths

§27 correctly separates confidence from risk and then lists seven contributing factors with no aggregation rule. Meanwhile §7's contract asks the model to emit `"confidence": 0.0` directly. That is the failure mode the section was written to prevent.

### 3.1 The baseline problem

LLM verbalized confidence is documented as pervasively overconfident, clustering in the 80–100% band largely independent of actual accuracy, with post-training/RLHF exacerbating it. Recent mechanistic work locates a stable confidence-inflation circuit in middle-to-late layers writing at the final token position, and finds verbalized confidence *dissociates from log-probabilities*. Two consequences:

- A raw `confidence` float from the model is not a probability and must never be surfaced or thresholded.
- Even if you had logprobs, they would not agree with the verbalized number.

### 3.2 Two techniques the brief assumes are available and are not

**Logprob-based calibration is unavailable on Anthropic.** The documented Messages API surface exposes no `logprobs` / `top_logprobs` parameter. If the design intends token-probability-based confidence, that choice constrains the provider — and §13's "AI Provider abstraction" cannot abstract in a capability the vendor does not expose.

**Temperature-based self-consistency is unavailable on the current Claude frontier.** `temperature`, `top_p`, and `top_k` are removed on Claude Opus 5, Sonnet 5, Opus 4.8, Opus 4.7, and Fable 5 — sending them returns a 400. The standard "sample k times at T=0.8 and measure answer entropy" ensemble therefore does not run at all on those models. If you want ensemble disagreement as a confidence signal you must generate variance structurally instead:

- **evidence-subset bagging** — run the decision k times on k random 80% subsets of the evidence set, measure decision stability. This is arguably *better* for this domain because instability under evidence perturbation is exactly the uncertainty you care about, and it doubles as a sensitivity analysis ("which evidence flipped the decision"). Cost: ×k.
- **prompt-order permutation** — shuffle evidence ordering. Cheaper signal, weaker.

This constraint is not in the brief's model-selection criteria (§13) and should be.

### 3.3 The calibration ladder, with data requirements

| Stage | Technique | Labels needed before it works | What it buys |
|---|---|---|---|
| **0 (day one)** | **Deterministic evidence-completeness score.** A closed-form function of: required slots filled / required slots total, source authority tier, max evidence age vs. per-source validity window, conflict count, ownership resolved (bool). | **Zero.** | Fully explainable, auditable, ships immediately, and is *honest* — it measures what the system knows, not what a model feels. |
| **1** | **Platt scaling / logistic calibration** mapping raw score → P(analyst agrees), fit per decision class. Two parameters. | **~200–500** labeled outcomes *per decision class*, stratified. Below ~200 the fit is unstable. | Turns a score into a probability with an empirical meaning. |
| **2** | **Isotonic regression.** Non-parametric, handles non-monotone miscalibration, overfits badly on small n. | **~1,000–2,000** per class. | Better fit where the miscalibration is not sigmoid-shaped. Do not use it before the volume exists. |
| **3** | **Conformal risk control on the auto-deprioritize gate only.** Distribution-free guarantee: among auto-deprioritized findings, true-critical rate ≤ α with probability ≥ 1−δ. | **~1,000** exchangeable calibration examples for a usable bound at α = 0.05; **~5,000–10,000** for α = 0.01. | The only technique here that produces a *guarantee* rather than an estimate — and the only one that speaks directly to the §33 catastrophic-FN risk. |

**Conformal's fine print, stated plainly:** it assumes exchangeability between the calibration set and production. A new scanner version, a new tenant, a new language ecosystem, or an EPSS model bump all break that assumption. In practice you must re-calibrate per tenant *and* per scanner-rule family, which multiplies the data requirement by the number of strata. Budget for it or scope the guarantee narrowly (e.g. conformal bound published only for the SCA/CVE route, where volume is highest and features are most stable).

### 3.4 What to actually show a human

Never render a model confidence. Render an empirical statement:

> "Of the last 217 findings scored in this band for this organization, analysts agreed with 94% (95% CI 90–97%)."

That is defensible in an audit, requires no belief in model introspection, degrades gracefully (when n is small the CI is wide and *says so*), and is exactly the "defensible security decision" the mission statement asks for. It is also, notably, something no competitor currently puts on screen.

---

## 4. The deterministic / LLM split (§7): design it, don't assert it

§7 says "the LLM explains and synthesizes; it must not become the sole source of truth" and then presents a single JSON object in which every field is produced by the LLM. The instruction and the contract contradict each other.

### 4.1 The actual split

| Field | Owner | Mechanism / gate |
|---|---|---|
| `contextual_risk_score` | **Deterministic only** | Versioned scoring function over typed features (§26). The LLM never emits this field. Remove it from the schema. |
| `severity` | **Deterministic**, LLM may propose an override | Base = scanner/CVSS. An override requires a reason code from a closed enum **and** ≥1 evidence ID that the gate can verify supports it. Overrides never auto-apply below `needs_review`. |
| `exploitability` | **LLM-proposed, evidence-gated** | `confirmed` requires a KEV membership record or an exploit-artifact evidence ID. `unlikely` requires a reachability record or ≥N corroborating prior decisions on the same rule+repo. A proposal without its required evidence is rejected, not downgraded. |
| `business_impact` | **Deterministic lookup** | From the asset/service registry. If the registry is null, the field is `unknown` and the finding is ineligible for auto-deprioritize (§8, guardrail 4). The LLM may propose a value, flagged `provisional`, which never feeds the score. |
| `confidence` | **Deterministic + calibrator** | §3 ladder. The LLM never emits it. Remove it from the schema. |
| `decision` | **Policy engine** | A deterministic, versioned, unit-tested rule set consuming score + exploitability + confidence + guardrails. The LLM's output is an *input* to the policy, never the decision. |
| `recommended_action` | LLM | Free text, no authority. |
| `reasoning_summary` | LLM | Free text, no authority. Must cite only IDs present in `evidence_ids`. |
| `evidence_ids` | LLM-selected, **hard-validated** | Any ID not in the retrieved set for this decision ⇒ reject the entire response. No repair, no retry with the same prompt. |
| `contradicting_evidence_ids` | LLM + rule table | Union of rule-detected conflicts and LLM-cited ones, same ID validation. |
| `uncertainty_reasons` | LLM, closed enum | Enums only; free text here becomes unanalyzable within a month. |
| `accepted_risk` (decision value) | **Remove from the model's enum entirely** | Accepting risk is a human authority act with liability attached. A model must not be able to emit it. |
| `decision_version` | System | Composite of scoring version + policy version + prompt version + retrieval config version + model ID. |

### 4.2 Disagreement handling

Define three classes and act differently on each:

- **Class A — guardrail violation.** LLM proposes a value the deterministic layer forbids (e.g. `exploitability: unlikely` when KEV = true; a score outside [0,1]; an evidence ID that was never retrieved). **Action:** reject the response, do not retry with the same prompt, fall back to the deterministic-only decision path, emit `needs_review`, log as `guardrail_violation` keyed to the prompt version. **Track the Class A rate as a release gate.** Above ~1% the prompt/model is not production-fit. If it is exactly 0% across a large sample, run the ablation in §4.3 — the guardrails may be redundant because the LLM is contributing nothing.
- **Class B — in-tolerance disagreement.** LLM proposes severity one notch off, or a different but permissible exploitability. **Action:** accept as a proposal, route to `needs_review`, and *record the disagreement as a labeled instance*. These are the highest-value training and calibration examples the system will ever produce, and the brief currently discards them.
- **Class C — unsupported citation.** The cited evidence exists but does not support the claim. **Action:** treat as Class A. Detection is either the evidence gate (for typed claims) or a cheap verification pass (for free-text claims) — but note that a verification pass is another model call and must be justified against the ablation.

### 4.3 The ablation nobody has scheduled

Run the deterministic path **alone** against the golden set and compare to deterministic + LLM. If the difference is within noise, the LLM is decoration on the decision path and belongs only on `reasoning_summary`. This should be a **standing quarterly gate**, not a one-time curiosity — every prompt change, model upgrade, and retrieval change shifts it. It is also the single cheapest defense against the §33 "AI commoditization" risk: if you cannot demonstrate the delta, neither can the market.

### 4.4 A concrete schema constraint the brief has not accounted for

Anthropic structured outputs enforce the schema but **do not support numeric constraints (`minimum`, `maximum`, `multipleOf`), string-length constraints, or recursive schemas.** So `"contextual_risk_score": 0.0` cannot be schema-constrained to [0,1] — a model can legally emit `7.3` or `-1`. Application-side validation is mandatory regardless of provider. This is one more reason the score must never come from the model at all.

Two related facts worth designing around: structured outputs are **incompatible with citations** (returns 400), so the "citation" mechanism must be your own evidence-ID validation, not the provider's; and a new schema pays a one-time compilation cost with a 24-hour cache, so a schema that varies per tenant pays that repeatedly.

---

## 5. The suppression death spiral (§15 + §16 + §17)

This is the most dangerous flaw in the design.

### 5.1 The mechanism, stated precisely

1. The system auto-deprioritizes finding class X.
2. Analysts never see X, so no label is produced for X.
3. §16's per-rule false-positive statistic is computed over *reviewed* items only — which are systematically the items the model already believed were real.
4. Measured precision therefore rises monotonically while true recall is unobserved and can fall toward zero.
5. §11 retrieves that statistic as "historical organizational evidence" for the next decision on the same rule.
6. §17 mines patterns from the same biased label distribution and promotes them.

This is textbook **selection bias under missing-not-at-random** — structurally identical to reject inference in credit scoring, where a model that denies a loan never learns whether it would have been repaid. Steps 3→5 form a **positive feedback loop with gain > 1**: a rule that draws three unlucky FP labels in its first week can be permanently suppressed, and the system's own metrics will report this as improving accuracy.

Note the timing: the loop closes fastest on **high-volume, low-severity rules** — exactly where the product's volume-reduction value proposition lives. The failure will look like success.

### 5.2 Mitigation, with the sampling math

**(a) Randomized stratified audit quota — the core mechanism.**

Sample a fixed fraction ε of auto-deprioritized findings into a mandatory human review queue, stratified by `(scanner, rule_family, confidence_band, service_criticality)` so rare strata are not starved by volume-dominant ones.

Sizing, honestly:

- To *estimate* a true-FN rate of p = 1% with absolute half-width ±0.5% at 95% confidence: `n = 1.96²·p(1−p)/w² ≈ 1,522` audited items **per stratum per window**. Infeasible per-stratum for most tenants.
- To estimate p = 5% with half-width ±2.5%: `n ≈ 292`. Feasible.
- **Better framing — the rule of three.** If you audit `n` items and observe **zero** false negatives, the 95% upper bound on the FN rate is ≈ `3/n`. So to claim "FN ≤ 0.5%" with zero observed failures you need **n ≥ 600** audited auto-deprioritized findings. That is the number to put in the contract, and it is a number a pilot customer can check.

Cost, stated as a line item and not a footnote: 600 audits × 4 minutes ≈ **40 analyst-hours ≈ one analyst-week per measurement window**. At 10,000 findings/month with 60% auto-deprioritized, a 10% audit rate yields exactly those 600 items. **This cost must be subtracted from the north-star metric.** A product that saves 200 hours and spends 40 on audit has saved 160, and saying so is more credible than saying 200.

For *detecting a change* rather than estimating a level, a sequential test (SPRT) reaches a decision in materially fewer samples — use SPRT for the continuous monitor and fixed-n estimation for the quarterly report.

**(b) Propensity logging — the enabling requirement.**

Every finding must carry `review_propensity`: the exact probability, known at decision time, that it would be routed to a human. All §16 statistics are then computed with Horvitz–Thompson inverse-propensity weighting. **This only works if the audit sampler is a randomized policy with a recorded probability** — "whatever the analyst happened to click" has an unknown propensity and cannot be de-biased. Concretely, this adds a mandatory column to the findings table and a mandatory field to every statistic query. It is cheap to add on day one and effectively impossible to backfill.

**(c) Do not build a bandit.**

Thompson sampling / UCB optimize *cumulative reward*. We are not optimizing reward; we are estimating the rate of a rare harmful event and want an unbiased estimate with a bound. A bandit will allocate exploration away from arms that look safe — which is precisely where the undiscovered false negatives are. **Stratified randomized audit + propensity weighting, not bandits.**

**(d) Retroactive outcome labels — the only bias-free source.**

The one class of label immune to the loop is external and time-delayed:

- a CVE we deprioritized later enters CISA KEV;
- its EPSS score crosses a threshold under a new model version;
- a public exploit is published;
- an incident, pentest finding, or bug-bounty report maps back to a suppressed finding;
- the finding was remediated anyway by a developer who disagreed with us.

Build a nightly `retroactive_label` job that re-scores every past decision against current external state and reports **"we deprioritized N findings that later entered KEV."** This is cheap, requires no analyst time, is immune to the feedback loop, and is the single most credible artifact you could put in front of a pilot customer. **It is missing from the brief entirely and belongs in the MVP Must list.**

**(e) Shadow mode at onboarding.**

For the first 30 days per tenant, run in shadow: the system decides, analysts decide independently, and the system's answer is hidden until the analyst submits. This produces (i) an unbiased calibration set for §3, (ii) a clean baseline for the §31 north-star, and (iii) a measured analyst-agreement rate you can quote in the sales motion. It costs the customer nothing extra — they were going to triage anyway.

**(f) Temporal leakage.**

A finding's own prior decision must never be a feature for its own re-decision without a time split. Enforce `evidence.created_at < decision.requested_at` **in the retrieval query itself**, not in application code, and write a test that injects a future-dated decision and asserts it is not retrieved. This is the leakage bug that will otherwise ship, because it looks like a feature ("the system remembers what we decided!").

---

## 6. Cold start: the moat thesis does not survive contact with the math

### 6.1 How many labels before organizational memory beats public enrichment?

Model per-rule false-positive propensity as Beta–Bernoulli. Starting from a prior `Beta(α, β)`, the posterior mean is `(α + k)/(α + β + n)`. **Organizational data dominates the prior once `n > α + β`** — i.e. once you have more observations than the prior's effective sample size.

- Against a *weak* prior (uninformative, α+β ≈ 2), a handful of labels moves the estimate. But a weak prior means your day-one behavior is essentially the scanner's raw output, which is worthless.
- Against a *strong* cross-tenant prior (effective sample size 20–50, which is what you would get from pooling this rule across customers), you need **20–50 labeled instances per rule** before the org-specific signal is meaningfully better.

Scale that up: a typical org running Semgrep + Trivy + Gitleaks triggers on the order of **50–200 distinct high-volume rules**. At 30 labels per rule, that is **1,500–6,000 labeled decisions** before rule-level organizational memory beats a good generic prior. At ~20 triages/analyst-hour, that is **75–300 analyst-hours ≈ 2–8 analyst-weeks per tenant** — before the moat asset exists.

For a pilot lasting six weeks, this is fatal to the moat narrative and irrelevant to the pilot's success. Which points at the real finding:

### 6.2 The asymmetry the brief has backwards

Not all "organizational knowledge" accrues at the same rate:

| Knowledge type | How it is acquired | Volume needed | Time to value |
|---|---|---|---|
| Service criticality, ownership, exposure, compensating controls, exception policy | **Configuration + integration** (CMDB, CODEOWNERS, cloud tags, IaC) | dozens to hundreds of records, entered once | **days** |
| Rule-level FP propensity | Triage labels | 20–50 per rule × 50–200 rules | **months** |
| Fix-efficacy and remediation-time history | Observed remediation outcomes | one per closed finding, needs closure lag | **quarters** |

**The fast-accruing, high-value organizational context is configuration, not decision history.** What makes SDIP useful on day 30 is a populated context graph — who owns this, is it internet-facing, is it in scope for PCI, is there a WAF rule — not the decision log. The decision log starts to matter at month 6.

This has three consequences the brief should absorb:

1. **The near-term differentiator is a data-modeling and integration problem, not an AI problem.** Time-to-populated-context-graph is the metric that determines whether a pilot succeeds. It should be a first-class product metric (§31 has "percentage of findings with resolved ownership" — promote it to near-north-star for the pilot phase).
2. **The moat as stated is mis-specified.** "Accumulated decision evidence" is a month-6 asset being sold as a day-1 differentiator.
3. **§4 and §19 are in direct contradiction and one of them must give.**

### 6.3 The §4 / §19 contradiction

§4 wants a compounding data advantage. §19 forbids cross-organization retrieval, embeddings, decision memory, **and analytics**. Read literally, §19 means every customer starts from zero forever and there is no network effect — only per-tenant switching cost. That is a real business but it is not a moat, and it should not be described as one.

The alternative is a **cross-tenant statistical layer** carrying *only* aggregate, non-content-derived priors — e.g. "across N≥10 tenants, Semgrep rule `X` has an FP rate of 0.72 ± 0.06" — with explicit contractual opt-in, a k-anonymity floor on N, no raw finding content, no code, no tenant-identifiable signal, and a documented differential-privacy or aggregation-threshold mechanism. That *is* a compounding advantage and it is the only version of the moat that works on day one.

**This requires an ADR and a decision. You cannot have both.** Note also the interaction with §44: if you offer full data export (and enterprise buyers will demand it), a competitor can ingest the exported decision log. The durable asset is therefore the *derived* artifacts you do not export — calibrators, the correlation graph, the evaluation set, the cross-tenant priors. Say that plainly in the moat section rather than pointing at the decision log.

---

## 7. The evaluation gate (§30): where does ground truth come from?

§30 lists ten metrics and zero sources of truth. §29 asks for golden datasets for six tasks with no construction protocol. This is the gap that will make every subsequent AI decision unfalsifiable.

### 7.1 Four tiers of truth, ranked by immunity to bias

| Tier | Source | Cost | Bias immunity | Covers |
|---|---|---|---|---|
| **T0 — mechanical** | Verifiable by construction: duplicate pairs, version-range applicability, KEV membership, ownership resolution correctness | very low | total | correlation, dedup, enrichment, ownership — **not** exploitability |
| **T1 — retroactive outcome** | Later-KEV, later-exploit-published, later-incident, actually-remediated | low (automated) | total | the FN gate, and only the FN gate |
| **T2 — adjudicated consensus** | 3 independent annotators + adjudication | high | moderate | exploitability, prioritization, evidence sufficiency |
| **T3 — production single-label** | Whatever the on-shift analyst clicked | ~free | **poor** — this is the label the feedback loop corrupts | volume metrics, trend monitoring — **never the release gate** |

The brief implicitly assumes T3 everywhere. T3 must be explicitly barred from the gate.

### 7.2 The inter-annotator problem is worse than assumed

A large-scale empirical comparison of CVSS, EPSS, SSVC, and Microsoft's Exploitability Index across 600 Patch Tuesday vulnerabilities found **considerable and systemic disagreement — little to no correlation or categorical agreement** among the four systems scoring the same CVEs. If four *formal, specified* scoring systems disagree that badly on public CVEs with full documentation, human κ on the far softer question "is this exploitable **in our environment**" will land in the moderate range at best (0.4–0.6), and lower on SAST findings where the ground truth requires reading code.

**The fix is not better annotator training. It is not asking the question.**

Decompose "exploitable" into sub-questions that each have materially higher agreement:

- (a) Is the vulnerable code path reachable from an entry point? *(binary, code-verifiable)*
- (b) Is that entry point externally exposed? *(binary, config-verifiable)*
- (c) Does a public exploit or PoC exist? *(binary, artifact-verifiable)*
- (d) Is a compensating control present **and enforcing**? *(binary, config-verifiable)*
- (e) Does the affected version range actually cover our version? *(binary, mechanical)*

Annotate the sub-questions; **derive** the fused judgment with deterministic policy. This simultaneously fixes the annotation problem, the §26 risk-model explainability requirement, and the §4.1 split — because now the LLM's job on exploitability is to answer verifiable sub-questions with cited evidence, not to render an unfalsifiable holistic verdict.

**Gate rule:** any sub-question whose measured κ < 0.6 is not eligible to be a release-gate metric. It can be a diagnostic. Publish the κ values.

### 7.3 Golden-set construction protocol

**Size.**
- **Decision set: 500 findings.** Rationale: for a paired comparison between two prompt/model versions detecting a 5-point absolute accuracy change at 80% power and α = 0.05, roughly 300–400 paired items are needed at typical discordance rates; 500 leaves headroom for per-stratum reporting. Recompute this properly against pilot discordance data rather than treating 500 as settled.
- **FN set: separate, and deliberately oversampled.** At least **200 known-true-positive criticals**, oversampled far above their natural base rate. A naturally-sampled 500-item set contains too few true criticals for an FN regression to be statistically visible at all — this is the most common way an eval suite silently stops protecting the thing it was built to protect.
- **Correlation/dedup set: 300 pairs**, half true duplicates, half hard near-misses (same CVE different package; same rule different file; same file different commit).

**Composition — stratify by:** source tool (all 5 MVP integrations), finding class (SAST / SCA / secrets / container), severity, target decision class, and two adversarial strata that must be explicit:
- **Hard negatives** — look critical, aren't: unreachable CVE in a dev-only dependency, secret in a test fixture, SAST hit in generated code, CVE in a vendored copy that isn't built.
- **Hard positives** — look trivial, aren't: low-CVSS but KEV-listed, medium severity in an internet-facing auth service, a "test" credential that is actually live.

**Annotation.** Three annotators per item on the decomposed sub-questions (§7.2), majority vote with explicit adjudication of ties, κ recorded per sub-question. Annotators must be the pilot customer's own senior analysts — "exploitable in our environment" is definitionally tenant-specific and cannot be labeled by the vendor or on public data.

**Provenance and replayability.** Every item stores the **full evidence snapshot as of the annotation date**, content-hashed. Without this the set decays into noise, because the external inputs move under you: EPSS shipped v4 in March 2025 and **v5 in May 2026** (recalibrated probabilities, improved exploit-code classifier, a reported jump from 0.514 to 0.633 on their headline metric). A corpus re-scored under a new EPSS model changes the model's inputs without any change on your side. **Pin `epss_model_version` in every evidence record** and treat a version bump as a forced eval-set refresh event.

**Refresh cadence.**
- 10% rotation per quarter (retire items whose ground truth aged out, add newly adjudicated items).
- **Forced immediate refresh** on any of: new scanner integration, EPSS model version bump, KEV schema change, new tenant vertical, or a change to the finding-normalization schema.
- Full re-annotation of the retained 90% annually.
- **Freeze the set for the duration of any A/B.** A moving eval set makes every comparison meaningless.

**Contamination control.** Golden items must be excluded from the retrieval index at eval time, or you are measuring memorization of your own decision memory rather than reasoning. Implement as an eval-time filter on `finding_id ∈ golden_set` and **write a test that asserts the filter is active** — this is the kind of thing that silently regresses.

### 7.4 The uncomfortable consequence

Because exploitability ground truth is tenant-specific, **the AI evaluation gate cannot be fully vendor-owned.** The vendor can hold a T0/T1 set (mechanical + retroactive) covering correlation, dedup, enrichment, and the FN ceiling. Everything touching "is this exploitable here" needs a per-tenant eval set. Budget for a **per-tenant evaluation harness as a shipped product feature**, not internal tooling — and note that this is itself a defensible differentiator: no ASPM vendor currently hands the customer a measurable, customer-owned evaluation set for the vendor's own AI.

---

## 8. False negatives: asymmetric loss needs structure, not a threshold

§33 correctly names "a wrong deprioritize can be far more damaging than a false positive" as a top risk and then provides no mechanism.

### 8.1 There is no single acceptable FN rate

The cost of a false negative varies by orders of magnitude across assets. Set it per tier:

| Tier | Definition | Policy |
|---|---|---|
| **Tier 0** | Internet-facing service holding regulated or credential data | **No auto-deprioritize at all.** Everything routes to `needs_review` with a ranked recommendation. The product value here is ordering and evidence, not suppression. |
| **Tier 1** | Internet-facing, non-regulated | Auto-deprioritize allowed; target FN ≤ 0.5% with a **published upper bound**, not a point estimate (rule of three: ≥600 clean audits per window — §5.2a). |
| **Tier 2** | Internal-only, non-critical | Auto-deprioritize allowed; target FN ≤ 2%. |
| **Unknown** | Criticality unresolved | **Fails closed** — treated as Tier 0. |

That last row is not a detail. Ownership and criticality resolution will be incomplete for months (§6.2). Without an explicit fail-closed rule, the system silently suppresses findings on precisely the assets it knows least about — which is exactly backwards, and is how this design produces its first incident.

### 8.2 Structural guardrails — evaluated before the LLM output is consulted

These are hard rules in the policy engine. No confidence score overrides them.

1. **Never auto-deprioritize if CVE ∈ CISA KEV.** No exceptions.
2. **Never auto-deprioritize if EPSS ≥ 0.10 or EPSS percentile ≥ 0.95.** (EPSS v5's improved calibration makes an absolute-probability threshold more defensible than it was under v3; still pin the model version and re-validate the threshold on each bump.)
3. **Never auto-deprioritize an unverified secret.** Secrets have near-zero exploitation latency; the loss asymmetry is extreme. A secret is eligible for closure only after verified revocation, which is a mechanical check, not a judgment.
4. **Never auto-deprioritize when asset criticality or ownership is `unknown`.** Missing context fails closed.
5. **Require ≥2 *structurally independent* corroborating evidence records**, where independence is defined by `source_type`, not by count. Three chunks from the same NVD record is **one** piece of evidence. This is the guardrail an evidence-ranking pipeline will silently violate if independence isn't modeled.
6. **Prior-decision evidence must match on rule_id AND repo_id AND same-or-newer code fingerprint.** "We marked this rule FP in another repository" is not evidence about this repository.
7. **Calibrated confidence floor with a lower bound.** Auto-deprioritize only above a threshold set so the *empirical* disagreement rate in that band is below target using a Wilson or Clopper–Pearson **lower confidence bound**, not a point estimate. A band with n = 12 and 100% agreement does not qualify.
8. **Volume circuit breaker.** Cap auto-deprioritize at a fraction of ingested volume per window. A sudden spike almost always means an upstream change (new scanner version, new ruleset, a broken normalizer) rather than a genuine improvement. Trip and require human release.
9. **Suppression is perishable.** Auto-deprioritize writes a **suppression with an expiry** (e.g. 90 days), not a permanent close, and is re-evaluated immediately on any change to KEV membership, EPSS band, vendor advisory, reachability, or asset exposure. §25's "do not merge findings irreversibly" should be generalized: **do not suppress irreversibly.**
10. **Provider failure and refusal fail closed.** If the model errors, times out, or refuses (see §9.4), the decision is `needs_review`. Never `deprioritize`. This needs to be an explicit path in the decision engine, not an exception handler.

### 8.3 The decision vocabulary is unsafe as written

§7's enum mixes states with wildly different liability profiles behind one model call: `deprioritize`, `false_positive_candidate`, and `accepted_risk` are not peers. `accepted_risk` is a human authority act — **remove it from the model's output enum entirely** and make it reachable only through an authenticated analyst action with an attributable identity and an expiry. `false_positive_candidate` should be a *hypothesis* that routes to review, never a terminal state.

---

## 9. Model selection (§13): the criteria list is missing the criteria that matter

The brief's model-selection criteria are reasonable and incomplete. Current landscape, then what it implies.

### 9.1 The 2026 field

| Model | Input / output per MTok | Context | Notes for this workload |
|---|---|---|---|
| **Claude Opus 5** | $5 / $25 | 1M | Structured outputs; full `effort` ladder (low→max); **thinking on by default**; prompt-cache minimum drops to 512 tokens; elevated cybersecurity classifiers (see §9.4) |
| **Claude Sonnet 5** | $3 / $15 (intro $2 / $10 through 2026-08-31) | 1M | Structured outputs; adaptive thinking on by default; **new tokenizer produces ~30% more tokens for the same text** than Sonnet 4.6 |
| **Claude Haiku 4.5** | $1 / $5 | 200K | Structured outputs; the obvious candidate for high-volume extraction/classification sub-tasks |
| **Claude Fable 5** | $10 / $50 | 1M | **Requires 30-day data retention — not available under ZDR** |
| **GPT-5.5** | $5 / $30 | — | Flagship pricing parity with Opus-tier |
| **Gemini 3.1 Pro** | $2 / $12 | — | Cheapest frontier-tier input price in the comparison |
| **Gemini 3.5 Flash** | $1.50 / $9 (cached input $0.15) | — | Aggressive cached-input pricing |

*(Anthropic figures from the current SDK/model reference, cached 2026-06-24; competitor figures from public 2026 pricing summaries — re-verify before committing to a benchmark budget.)*

### 9.2 This workload's cost shape is input-heavy and output-light

Assume ~6,000 tokens of assembled evidence in and ~400 tokens of structured decision out:

| Model | Per finding | Per 10,000-finding import |
|---|---|---|
| Haiku 4.5 | $0.008 | **$80** |
| Sonnet 5 (list) | $0.024 | **$240** |
| Opus 5 | $0.040 | **$400** |

Three multipliers the brief has not modeled:

- **Batch API halves it.** 50% discount, results within 24 hours. The §34 wedge is literally "a customer imports 10,000 findings" — that is a batch workload, not an interactive one. Interactive latency matters for re-analysis of a single finding, not for the initial import. **Design ingestion as batch-first.**
- **Prompt caching cuts the shared prefix ~90% on reads**, but only the *shared* prefix (system prompt, policy text, tool definitions). The per-finding evidence block is uncached. If 3K of the 6K is shared, caching saves roughly $0.008/finding on Sonnet 5 — real money at volume. **It requires a byte-stable prefix**, which forbids the common pattern of interpolating the current date, tenant name, or a request ID into the system prompt. That is an architectural constraint on the prompt builder, not a tuning knob.
- **Thinking-on-by-default roughly doubles the naive estimate.** Adaptive thinking is on by default on Opus 5 and Sonnet 5 (a change from 4.8/4.6, where omitting the field meant no thinking), and thinking tokens bill as output. At default effort `high`, 1,000–3,000 thinking tokens per decision is unremarkable — on Sonnet 5 that is $0.015–0.045 of additional output cost, i.e. more than the entire naive per-finding estimate. **`effort` must be an explicit, versioned, per-route config value swept on the golden set**, not left at its default. Low and medium effort are documented as unusually strong on the current generation; for a structured triage decision over pre-assembled evidence, `low` or `medium` is the likely answer and the sweep is cheap to run.

Also note: the Sonnet 5 tokenizer emits ~30% more tokens for the same text than Sonnet 4.6, so any cost model calibrated on the prior generation undercounts input by roughly that much.

### 9.3 Structured-output reliability, concretely

Structured outputs are supported on Fable 5, Opus 5, Opus 4.8, Sonnet 5, and Haiku 4.5 and are schema-enforced. The constraints that matter for the §7 contract:

- **No `minimum`/`maximum`/`multipleOf`, no string-length constraints, no recursive schemas.** Numeric ranges must be validated in application code (§4.4).
- **Incompatible with citations** (400 error) — your provenance mechanism must be your own evidence-ID validation.
- First request on a new schema pays a one-time compilation cost, cached 24 hours — so avoid per-tenant schema variation.
- Express everything you can as `enum` / `const` / `anyOf` with `additionalProperties: false`. Enums are the enforcement mechanism you actually get.

### 9.4 Two provider-specific facts that are architecture, not trivia

**Refusals are a first-class operational risk here.** Opus 5 and Fable 5 run cybersecurity safety classifiers and can return **HTTP 200** with `stop_reason: "refusal"` and a `stop_details.category` such as `"cyber"`. For a product whose entire input corpus is vulnerability descriptions, exploit references, and occasionally leaked credentials, this is not an edge case — it is a recurring production event. Consequences:

- Any code path that reads `content[0]` unconditionally breaks. Check `stop_reason` first.
- A refusal must fail closed to `needs_review` (§8.2 guardrail 10).
- The Claude API's server-side `fallbacks` parameter (`fallbacks: "default"`, beta header `server-side-fallback-2026-07-01`) routes cyber-category refusals to Opus 4.8 within the same call — use it, and log every fallback event as an observability metric.
- **Add "refusal rate on our own corpus" to the §13 benchmark criteria.** It is currently absent, and it may be the criterion that decides the provider.

**Fable 5 requires 30-day data retention and is unavailable under ZDR.** §35 names private/VPC deployment and dedicated retention policies as premium enterprise features. Whichever model wins the benchmark, **the enterprise SKU must be servable by a model available under zero data retention.** Benchmark accordingly — do not select a model the paying segment cannot use.

**Prompt injection is structural, not a model choice.** The evidence block is 100% untrusted input: scanner output, advisory text, repository content, commit messages, and (for secrets scanning) attacker-controlled strings. §39 and §43 name this correctly. The mitigations that matter are architectural — the decision model gets **no tool access**, its output is schema-constrained, and every returned ID is validated against the retrieved set. One API-level mitigation is worth adopting on Opus 5 / Opus 4.8: operator instructions delivered mid-conversation as `{"role": "system"}` messages inside `messages[]` are a non-spoofable operator channel, unlike instruction text embedded in a user turn that untrusted content can imitate.

### 9.5 Recommendation

- **Benchmark Sonnet 5, Haiku 4.5, and Gemini 3.1 Pro / 3.5 Flash** for the per-finding decision. This is a structured judgment over pre-assembled evidence with a constrained output — a mid-tier task, not a frontier-reasoning task, and the ablation in §4.3 may show it barely needs a model at all.
- **Reserve Opus 5 for a low-volume escalation route** (`needs_review` adjudication, correlation ambiguity, conflicting-evidence synthesis) behind an explicit router. Measure what fraction of findings take that route; if it exceeds ~5%, the deterministic layer is under-built.
- **Do not benchmark Fable 5** for anything intended to serve the enterprise SKU.
- **Do not put an LLM on the correlation/deduplication path at all in the MVP.** §25's signals are all structural (identifiers, versions, fingerprints, locations) and belong in deterministic code with a measurable golden set. An LLM there adds cost, latency, non-determinism, and a prompt-injection surface to a problem that has an exact answer.
- Add to the §13 criteria: **refusal rate on our corpus**, **ZDR availability**, **structured-output constraint expressiveness**, **logprob availability** (if any calibration design depends on it), and **sampling-parameter availability** (if any ensemble design depends on it).

---

## 10. Do not build yet

| Thing | Why not | Trigger that would change the answer |
|---|---|---|
| **NLI contradiction model** | Deterministic conflict rules cover the large majority of real conflicts at zero cost; NLI's false-contradiction rate would flood `needs_review` and destroy the north-star metric | Rule-table recall measured inadequate on the golden set **and** ≥300 labeled conflict pairs exist to measure precision against |
| **Cross-encoder reranker in the decision path** | Wrong task (topical relevance ≠ decision relevance); 220 ms and real money for a signal that does not answer the question | Slot-B semantic precision is proven the binding constraint on decision accuracy |
| **Learned reranker (LambdaMART etc.)** | No relevance labels exist and none will for months | ≥5,000 labeled evidence-relevance judgments |
| **Bandit-style exploration** | Optimizes cumulative reward; we need an unbiased rare-event estimate. It will explore *away* from where the false negatives hide | Never, for this purpose. Use stratified randomized audit |
| **Multi-agent / critic-model pipeline (§14 stage 2–3)** | The brief already defers it; add the gate — it must beat the single-model baseline **and** the deterministic-only ablation | Measured improvement on the frozen golden set at acceptable cost/latency |
| **Abstractive context compression** | A summarizing LLM upstream of the deciding LLM is a second hallucination surface and breaks the content-hash provenance chain | Extractive compression is proven to be the binding constraint |
| **GraphRAG / native graph database** | §10 already defers it correctly; the join patterns here are 1–2 hops and Postgres handles them | A measured query pattern requiring ≥4-hop traversal at latency Postgres cannot meet |
| **Fine-tuning or custom embeddings** | No data, and it would fossilize the cold-start problem into model weights | ≥50,000 labeled decisions and a demonstrated retrieval ceiling |
| **LLM on the correlation/dedup path** | Deterministic problem with an exact answer; adds cost, nondeterminism, and injection surface | Deterministic correlation measured below target recall on the 300-pair golden set |
| **Per-tenant embedding models or indexes-per-model** | Operational cost with no measured benefit; also multiplies the eval burden by tenant count | Measured cross-tenant retrieval quality gap |
| **Attack-path analysis, autonomous remediation, automated pentesting** | Already deferred in §5; reaffirmed — each adds an FN surface the evaluation system cannot yet measure | Post-MVP, and only after the FN ceiling is measurable |

---

## 11. Missing components (add to the domain model and the backlog)

1. **`review_propensity` on every finding** — the recorded probability that it would be routed to a human. Without it, §16's statistics are permanently biased and §30's metrics are uninterpretable. Cheap on day one, impossible to backfill.
2. **Retroactive outcome labeling job** — nightly re-score of past decisions against current KEV / EPSS / advisory / incident state. The only bias-free label source and the most credible pilot artifact. **MVP Must.**
3. **Perishable suppressions** — auto-deprioritize writes an expiring suppression with re-evaluation triggers, not a terminal close.
4. **A Policy / Decision Engine as a distinct, versioned, unit-tested module.** §7 implies it; §20's module list does not contain it. Today the "decision" is implicitly the LLM's output field, which is exactly what §7 forbids. It belongs under `application/` beside `analysis/`.
5. **Evidence Contract + evidence-gap records + drop log** — required/optional slots per finding class, typed gaps, and a persisted record of what was dropped and why.
6. **Deterministic conflict-rule table**, versioned, with per-rule recall measured on the golden set.
7. **Refusal / provider-failure decision path** — an explicit fail-closed route to `needs_review`, plus a refusal-rate metric in §28's AI observability list.
8. **LLM ablation harness** — deterministic-only vs deterministic+LLM on the frozen golden set, run as a standing quarterly gate.
9. **Shadow-mode onboarding (30 days per tenant)** — produces the unbiased calibration set, the north-star baseline, and the analyst-agreement number you will want in the sales motion.
10. **As-of / time-travel enforcement in retrieval**, enforced in the query and covered by a leakage test that injects a future-dated decision and asserts non-retrieval.
11. **Per-tenant evaluation harness as a shipped product feature** — the exploitability gate cannot be vendor-owned, and handing the customer a measurable eval set for the vendor's own AI is itself differentiating.
12. **`epss_model_version` (and equivalent source-version pins) on every evidence record**, with a forced eval-set refresh on version bumps. EPSS moved v4 → v5 within the last fifteen months; treating external scores as stable is a silent-corruption bug.
13. **An ADR resolving §4 vs §19** — cross-tenant aggregate priors with contractual opt-in and a k-anonymity floor, or an explicit acceptance that there is no data network effect and the moat is per-tenant switching cost.
14. **Calibration store** — versioned calibrator artifacts (Platt/isotonic parameters, conformal thresholds) keyed by tenant, decision class, and scanner-rule family, with their own fit date, sample size, and validity window. Calibrators are models; they need the same versioning discipline as prompts.

---

## 12. Contradictions to resolve before implementation

| # | Contradiction | Sections |
|---|---|---|
| 1 | Moat requires accumulated cross-organizational learning; isolation rule forbids all cross-organization analytics | §4 vs §19 |
| 2 | "LLM must not be the sole source of truth" vs. a decision contract in which the LLM emits every field including the score and the confidence | §7 internal |
| 3 | "Do not retrieve everything" vs. an evidence model with no budget, no drop policy, and no drop log | §11 vs §8 |
| 4 | Low confidence should prefer `needs_review` vs. a north-star metric that penalizes exactly that routing — with no specified operating point on the trade-off | §27 vs §31 |
| 5 | Retrieval must find contradictory evidence vs. dense retrieval's documented insensitivity to negation | §11 vs §12 |
| 6 | §16 warns against leakage and circular reasoning; §11 retrieves §16's statistics as evidence for the next decision on the same rule | §16 vs §11 |
| 7 | Provider abstraction is meant to keep the domain vendor-neutral, but sampling parameters, logprobs, refusal behavior, and retention requirements differ materially and are not abstractable | §13 vs §3/§9 of this document |
| 8 | Full data export is promised while the moat is located in exportable decision history | §44 vs §4 |

---

## 13. Suggested first three experiments

Cheap, fast, and each one can kill a major assumption before code is written.

1. **The join-vs-retrieval bake-off.** Take 200 real findings. Assemble evidence twice: once via deterministic slot-filling, once via top-k semantic retrieval. Have analysts judge which evidence set is sufficient to decide. If the deterministic set wins or ties, the RAG framing in §11 is wrong and the architecture should change before anything is built.
2. **The deterministic-only ablation, pre-implementation.** Score 200 findings with a hand-written deterministic policy (CVSS × KEV × EPSS × reachability × asset criticality). Compare against analyst labels. This establishes the floor the LLM must beat, and it is the number the whole product thesis rests on. If a spreadsheet gets within a few points of the analysts, the differentiation hypothesis needs rework, not more model.
3. **The annotation-agreement probe.** Give three analysts the same 50 findings and ask both the holistic question ("is this exploitable here?") and the decomposed sub-questions from §7.2. Measure κ for each. If holistic κ is below 0.5 and decomposed κ is above 0.7 — the expected result — the decomposition becomes the product's core data model, and §7's contract should be rewritten around it before implementation begins.

---

## Sources

- [Empirical Security — EPSS V5 Is Here](https://research.empiricalsecurity.com/research/epss-v5-is-here)
- [Empirical Security Releases EPSS V5 (press release)](https://www.einpresswire.com/article/901281649/empirical-security-releases-epss-v5)
- [Introducing EPSS version 4 — Empirical Security](https://research.empiricalsecurity.com/research/introducing-epss-version-4)
- [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/) — v5.0.0, May 2025 (pin this version per §18)
- [Conflicting Scores, Confusing Signals: An Empirical Study of Vulnerability Scoring Systems](https://arxiv.org/html/2508.13644)
- [Large Language Models Are Overconfident in Their Own Responses](https://arxiv.org/pdf/2606.03437)
- [Calibrating Verbalized Confidence with Self-Generated Distractors (ICLR 2026)](https://proceedings.iclr.cc/paper_files/paper/2026/file/c50bf8e50041545841e28c0b052f76d0-Paper-Conference.pdf)
- [When Can Conformal Risk Control Certify LLM Outputs?](https://arxiv.org/pdf/2606.29054)
- [Selective Conformal Risk Control](https://arxiv.org/pdf/2512.12844)
- [Contradiction Detection in RAG Systems: Evaluating LLMs as Context Validators](https://arxiv.org/pdf/2504.00180)
- [Does RAG Know When Retrieval Is Wrong? Diagnosing Context Compliance under Knowledge Conflict](https://arxiv.org/html/2605.14473v4)
- [Hybrid Search in PostgreSQL: The Missing Manual — ParadeDB](https://www.paradedb.com/blog/hybrid-search-in-postgresql-the-missing-manual)
- [Yes, You Can Do Hybrid Search in Postgres — Tiger Data](https://www.tigerdata.com/blog/hybrid-search-postgres-you-probably-should)
- [Reranker Models Compared: Cohere vs Voyage vs Jina vs BGE](https://particula.tech/blog/reranker-models-compared-cohere-voyage-jina-bge-latency-ndcg)
- [Best Rerankers for RAG in 2026](https://futureagi.com/blog/best-rerankers-for-rag-2026/)
- [Top 8 Application Security Platforms — Endor Labs](https://www.endorlabs.com/learn/best-application-security-platforms)
- [Endor Labs AURI — security AI in coding workflows](https://www.insightswire.com/news/19283/endor-labs-auri-embed-security-ai-coding-workflows)
- [Top 5 ASPM Platforms for 2026: Apiiro vs ArmorCode vs Cycode vs OX vs Snyk AppRisk](https://guptadeepak.com/tools/top-5-aspm-platforms-2026/)
- [OpenAI API Pricing 2026 — Morph](https://www.morphllm.com/openai-api-pricing)
- [AI API Pricing Comparison 2026 — IntuitionLabs](https://intuitionlabs.ai/articles/ai-api-pricing-comparison-grok-gemini-openai-claude)
- Anthropic model IDs, pricing, structured-output constraints, thinking/effort semantics, refusal and fallback behavior, and prompt-caching minimums: current Claude API SDK reference (cached 2026-06-24).
