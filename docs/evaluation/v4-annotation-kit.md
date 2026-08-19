# V4 Annotation Kit — the agreement probe

**Deliverable:** makes V4 in `phase-0-protocols.md` §4 executable
**Date:** 2026-08-16
**Runs:** in-house. No design partner, no customer data, no model.
**Decides:** whether the decision contract is built around one holistic judgment or five decomposed sub-questions — **before** the schema is written
**Cost:** 3 annotators × ~4 hours each, plus ~1 day to assemble the corpus

---

## 0. Two corrections to the protocol as written

`phase-0-protocols.md` §4 specifies the experiment correctly in outline and gets two things wrong in detail. Both would have produced an uninterpretable result.

### 0.1 The comparison is not κ(holistic) vs κ(sub-question)

Those measure different tasks. Holistic κ is over a 3-category decision; a sub-question κ is over one binary fact. A sub-question will score higher almost by construction — *"does a public exploit exist"* is nearly mechanical — and concluding "decomposition wins" from that would be measuring the difficulty of the question, not the value of decomposing.

**The comparison that answers the question:**

| | Both are 3-category judgments over the same 50 findings |
|---|---|
| **κ_holistic** | Agreement on the decision when the analyst is asked for it directly |
| **κ_derived** | Agreement on the decision **derived deterministically from each analyst's own sub-question answers**, using one fixed fusion rule (§6.3) |

Same output space, same findings, same raters. The **only** difference is the route the analyst took to get there. That is the experiment.

Per-sub-question κ remains a **secondary output** with a different job: deciding which sub-questions are eligible to be a release gate (`evaluation-system.md` §1.3 — anything below 0.6 is a diagnostic, never a gate).

### 0.2 Without an environment, three of the five sub-questions are unanswerable

Q1 (reachable), Q2 (externally exposed) and Q4 (compensating control present and enforcing) are questions about **an environment**, not about a CVE. Hand a stranger a public advisory and all three answers are `unknown` — the probe would measure nothing but the absence of context, and would do it in the direction that flatters decomposition.

**V4 therefore requires a fixed, concrete, fictional environment given to all three annotators (§2).** Building it is the majority of the setup cost and it is not optional.

---

## 1. Pre-registered outcomes

Unchanged from `phase-0-protocols.md` §4.2, restated against the corrected comparison:

| Outcome | Action |
|---|---|
| κ_holistic < 0.5 **and** κ_derived > 0.7 | **Expected.** The decomposition becomes the core data model; the decision contract is rewritten around the five sub-questions before implementation |
| Both > 0.7 | Holistic questions are usable. Simplify the annotation protocol and save the cost across every future golden set |
| **Both < 0.5** | **The dangerous outcome.** T2 adjudicated consensus cannot support a gate at all, and the false-negative gate must rest entirely on T1 retroactive outcomes (`evaluation-system.md` §1.1) |
| κ_derived > κ_holistic but both middling | Decomposition helps and is not sufficient. Report the delta; revisit sub-question wording, not the design |
| Any sub-question κ < 0.6 | That sub-question is a diagnostic, never a gate. **Publish the value** |

---

## 2. The environment brief

Given to all three annotators, identical, before they see any finding. One page. They may re-read it at any time.

> ### Northwind Retail — architecture, as of 2026-08
>
> Mid-size online retailer. ~140 engineers. Findings below come from scanners run against this estate.
>
> | Service | Stack | Exposure | Criticality | Notes |
> |---|---|---|---|---|
> | `checkout-api` | Java 17 / Spring Boot 3.2 | **Internet-facing** | **Critical** | In PCI scope. Handles card tokens, never PANs |
> | `catalog-web` | Next.js 14 / Node 20 | **Internet-facing** | High | Public product catalog. No authentication on most routes |
> | `inventory-sync` | Python 3.11 | Internal only | Medium | Nightly batch. Reachable only from the service subnet |
> | `admin-console` | Django 4.2 | Internal, **behind VPN + SSO/MFA** | High | Full order and refund control |
> | `analytics-etl` | Python 3.11 | **Not deployed to production** | Low | Runs in staging only. Dev dependencies included in its lockfile |
>
> **Controls in place**
>
> - **WAF** (ModSecurity + OWASP CRS 4.x) in **blocking** mode in front of `checkout-api` and `catalog-web`. Tuned; the team has disabled 6 rules that caused false positives on the checkout flow.
> - **Egress filtering** from the production subnet: outbound HTTP allowed only to a documented allowlist.
> - No direct database access from the internet. Databases are in a private subnet.
> - Container images rebuilt weekly; base image `debian:12-slim`.
> - SSO with MFA enforced on `admin-console` and on all cloud consoles.
> - No RASP, no EDR on application containers.
>
> **Deployment facts**
>
> - `checkout-api` and `catalog-web` deploy on merge to main, ~15×/week.
> - `inventory-sync` deploys monthly.
> - Dependency versions for each service are given per finding.

### 2.1 Why this brief and not a simpler one

Three properties are load-bearing and each was chosen to create *real* disagreement rather than confusion:

| Property | Creates |
|---|---|
| **A WAF in blocking mode, with 6 rules disabled** | The sharpest Q4 disagreement available. Is a tuned-but-holed WAF a compensating control that is *enforcing*? Reasonable senior analysts split on this, and that split is exactly what V4 exists to measure |
| **`analytics-etl` staging-only, with dev deps** | A clean Q1/Q2 negative that is not a trick — the correct answer is knowable |
| **`admin-console` internal but high-criticality** | Separates "exposed" from "important", which a holistic question fuses and a decomposed one does not |

**Do not add ambiguity the brief does not resolve.** If an annotator cannot answer a sub-question from the brief plus the finding, the correct answer is `unknown` and that is a legitimate, recorded outcome — not a defect in the brief.

---

## 3. The finding corpus

50 findings. Assembled once, versioned, content-hashed, and reused for V2 and V3 so the three experiments share a substrate.

### 3.1 Strata

Balance matters more than realism here. A naturally-sampled set is ~85% low-severity noise, and **κ collapses under skewed marginals even at high agreement** (§6.4) — so a realistic set would produce an uninterpretable κ regardless of the true agreement.

| # | Stratum | n | Purpose |
|---|---|---:|---|
| S1 | Clear act-now: KEV-listed CVE in a direct dependency of `checkout-api` | 6 | Floor check. Disagreement here means the instrument is broken |
| S2 | Clear no-action: CVE whose affected range excludes the deployed version | 6 | Q5 mechanical |
| S3 | **Not deployed**: finding in `analytics-etl` only | 6 | Q1/Q2 negative |
| S4 | **WAF-mediated**: injection/deserialization class in an internet-facing service where CRS plausibly mitigates | **8** | **The Q4 battleground.** Largest stratum on purpose |
| S5 | Transitive dependency, unclear whether the vulnerable path is called | 6 | Q1 genuine uncertainty |
| S6 | Low CVSS, **KEV-listed** | 5 | Hard positive — looks trivial, is not |
| S7 | High CVSS, no exploit, internal-only service | 5 | Hard negative — looks critical, is not |
| S8 | SAST finding in test fixtures or generated code | 4 | The classic false-positive shape |
| S9 | Secret-shaped finding in a test file | 4 | Is a "test" credential live? |

Class mix across the 50: ~40% SCA, ~35% SAST, ~15% container, ~10% secret — approximating a real estate's shape while keeping the decision distribution balanced.

### 3.2 Built: `v4-corpus-v1.0`

Built 2026-08-16 by [`phase0/v4_corpus.py`](../../phase0/v4_corpus.py).
`sha256:1694f27f1c8ce21c90acfd1691eef8419dc1412099aafb8152ed536ee3076998`
Frozen against **KEV catalog `2026.08.14`** and **EPSS `v2026.06.15`** as of `2026-08-14`.
All 32 CVE identifiers resolve in OSV; **all 18 rule ids verified against upstream** (the `semgrep-rules` tree and `gitleaks.toml`).

The split that makes it trustworthy: **the design is authored, the evidence is fetched.** Which CVE sits in which stratum, on which service, at which deployed version, is a design decision in the seed table. KEV membership and `dateAdded`, EPSS score and percentile with model version, CVSS vectors, advisory ids and affected ranges all come from CISA, FIRST and OSV — never from the author.

The builder then **validates and refuses to emit** if a stratum's property does not hold: S1 must be KEV-listed *and* the deployed version inside the affected range; S2 must be outside it, and an undeterminable range is a hard failure there because the whole point of S2 is a mechanically checkable Q5.

**It caught two classes of authoring error on the first run**, both of which would have quietly degraded the experiment:

| Caught | Why it mattered |
|---|---|
| Two S1 entries whose CVEs are **not** KEV-listed (CVE-2022-42889, CVE-2016-1000027) | S1 is the floor check. Disagreement there is supposed to mean the instrument is broken — with non-KEV entries it would have meant the corpus was |
| **Maven packages on Node services** (and a Tomcat artifact on a Django service) | The error class a sharp annotator notices, after which they discount every other finding in the packet. Now asserted against the environment brief by `SERVICE_ECOSYSTEM` |

#### The pair worth knowing about

Fixing the first error produced the corpus's sharpest item, and it is built entirely from real ranges:

| | NW-004 | NW-008 |
|---|---|---|
| Service | `checkout-api` | `checkout-api` |
| Tomcat version deployed | **10.1.53** | **10.1.53** |
| CVE | CVE-2026-34486 (`tomcat-tribes`) | CVE-2025-24813 (`tomcat-embed-core`) |
| CISA KEV | listed 2026-08-04 | listed 2025-04-01 |
| EPSS | 0.829 | **0.999** |
| Affected range | `10.1.53 → 10.1.54` | `10.1.0-M1 → 10.1.35` |
| **Applies?** | **Yes** | **No** |

Same service, same Tomcat version, both KEV-listed, both near-maximum EPSS — and one applies while the other does not. An annotator who pattern-matches on the severity signals gets NW-008 wrong; one who reads the range gets it right. **That is the cleanest possible test of Q5**, and no part of it is invented.

#### Rule ids — checked by the tool, not carried as a note

18 of the 50 findings are rule-based (SAST and secrets). A plausible-looking rule id that does not exist is exactly the detail a senior practitioner spots, after which they discount the whole packet — so the builder now fetches the upstream `semgrep-rules` tree (2,191 rule files) and `gitleaks.toml` (222 rule ids) and **fails the build on any id that is not there.**

Its first run rejected four of my own:

| Written | Actual upstream id |
|---|---|
| `javascript.lang.security.audit.path-traversal` | `…path-traversal.path-join-resolve-traversal` |
| `python.lang.security.audit.dangerous-yaml-load` | `python.lang.security.deserialization.avoid-pyyaml-load` |
| `java.lang.security.audit.crypto.weak-hash.use-of-md5` | `java.lang.security.audit.crypto.use-of-md5` |
| `python.lang.security.audit.dangerous-subprocess-use` | `…dangerous-subprocess-use-audit` |

All four were plausible, none existed. **18/18 now verify.** The general lesson is the one this repository keeps re-learning: a caveat recorded in prose is a caveat that ships; the same caveat expressed as an assertion in the tool is one that cannot.

### 3.3 Selection rules

1. **Real CVEs, real rule ids, real advisories.** Synthetic vulnerabilities produce synthetic disagreement.
2. **Freeze the evidence.** Snapshot KEV membership, EPSS score **with its `model_version`** (currently `v2026.06.15`), and the advisory's affected ranges as of the assembly date, and store them with the corpus. Per `exp-001`, a corpus that reads live EPSS changes its own inputs between annotators — and after a model bump, changes all of them.
3. **No finding whose answer depends on reading the actual source.** Annotators do not have the codebase. Where a code detail matters, state it in the finding.
4. **Content-hash and version the corpus** (`v4-corpus-v1.0`). It is reused by V2 and V3; a silent edit invalidates comparisons across all three.

### 3.3 Per-finding record

```
finding_id, class, service, tool, rule_id,
cve_ids[], purl + deployed_version, fixed_version,
cvss_triples[] (source, vector, score),
epss (score, percentile, model_version), kev (listed, date_added),
advisory_affected_ranges (as-of snapshot + content hash),
location (file, line) or image + layer,
scanner_message (verbatim),
reachability_verdict_from_scanner (if the tool emits one),
dependency_scope (direct | transitive | dev_only)
```

Everything an annotator is allowed to know. Nothing else.

---

## 4. Form A — holistic

One question per finding. Presented with the finding record and the environment brief, nothing more.

> **Given Northwind's environment, what should happen to this finding?**
>
> ☐ **Prioritize** — act on this now
> ☐ **Deprioritize** — this does not warrant action now
> ☐ **Needs review** — I cannot decide from what I have
>
> *Confidence in your answer:* ☐ low ☐ medium ☐ high
> *(optional) One line on why:* ___________

Confidence is collected but is **not** an outcome. It is a diagnostic against ADR-0010 §1's claim that self-reported confidence is a poor signal — this is a free, incidental test of it.

---

## 5. Form B — decomposed

Five questions per finding. Same record, same brief. **Presented in this fixed order**, because Q5 is mechanical and answering it first anchors the rest.

> **Q1 — Is the vulnerable code path reachable from an entry point in this service?**
> ☐ Yes ☐ No ☐ Unknown from the information given
>
> **Q2 — Is that entry point reachable from outside Northwind's network?**
> ☐ Yes ☐ No ☐ Unknown from the information given
>
> **Q3 — Does a public exploit or proof-of-concept exist for this vulnerability?**
> ☐ Yes ☐ No ☐ Unknown from the information given
>
> **Q4 — Is a compensating control present *and enforcing* for this specific vulnerability?**
> ☐ Yes ☐ No ☐ Unknown from the information given
> *"Enforcing" means it would actually block exploitation of this issue, not that it exists.*
>
> **Q5 — Does the advisory's affected version range cover the version deployed here?**
> ☐ Yes ☐ No ☐ Unknown from the information given
>
> *(optional) Anything the questions did not let you say:* ___________

Three wording decisions that are doing work:

- **"Unknown from the information given"**, not "unknown". It makes clear that `unknown` is a statement about the evidence, not an admission by the annotator — otherwise `unknown` is under-used out of professional pride, and the `evidence_gap` design loses its empirical basis.
- **Q4's italicized clarification** is the entire Q4 battleground made explicit. Without it, "is there a WAF?" and "would the WAF stop this?" get answered interchangeably.
- **The free-text box** is the most valuable field in the whole experiment: it is the empirical source for whether five sub-questions are the right five. If four annotators independently write "I need to know whether the endpoint requires authentication," that is a sixth sub-question discovered rather than invented.

---

## 6. Method

### 6.1 Design

3 annotators × 50 findings × 2 forms = **300 annotations**, ~4 hours per annotator.

**Counterbalanced, with a washout.** Each annotator sees each finding in both forms, and never within 48 hours, so the second answer is a judgment and not a memory.

| | Session 1 (day 0) | Session 2 (day 3+) |
|---|---|---|
| **Annotator 1** | Findings 1–25 Form A · 26–50 Form B | 1–25 Form B · 26–50 Form A |
| **Annotator 2** | 1–25 Form B · 26–50 Form A | 1–25 Form A · 26–50 Form B |
| **Annotator 3** | 1–25 Form A · 26–50 Form B | 1–25 Form B · 26–50 Form A |

Finding order is randomized independently per annotator per session. Every finding therefore receives 3 Form-A and 3 Form-B judgments, with form-order balanced across annotators.

### 6.2 Annotators

Three **senior** AppSec practitioners. Not three people from the same team, and not the founder plus two juniors — correlated background inflates agreement and the experiment then measures shared training.

Realistically at pre-product stage: the founder plus two contracted senior AppSec engineers, ~4 hours each. **Budget it and pay properly** — this is the cheapest decision-quality input the project will ever buy, and unpaid favours produce rushed annotation.

**No discussion between annotators until both sessions are complete.** A single calibration conversation destroys the measurement.

### 6.3 The fusion rule — fixed in advance

Applied to each annotator's own Form-B answers to produce their derived decision. **Deterministic, published before annotation begins**, so it cannot be tuned to produce the desired κ.

```
if Q5 == No                       -> deprioritize     # range excludes our version
elif Q1 == No                     -> deprioritize     # not reachable
elif Q2 == Yes and Q3 == Yes
     and Q4 != Yes                -> prioritize       # exposed, exploit exists, unmitigated
elif Q1 == Yes and Q3 == Yes      -> prioritize
elif any(Q1,Q2,Q3,Q5) == Unknown  -> needs_review
else                              -> needs_review
```

This is deliberately simpler than `risk-model.md` §4.2's fifteen-row tree. V4 tests **whether decomposition raises agreement**, not whether the production tree is correct — that is V2. Using the full tree here would confound the two.

### 6.4 Statistics

| Statistic | Why |
|---|---|
| **Fleiss' κ**, 3 raters | κ_holistic, κ_derived, and one per sub-question |
| **Bootstrap 95% CI**, 10,000 resamples over findings | At n=50 the point estimate is not the result. **Report the interval or report nothing** |
| **Percent agreement** (all-3 and majority) | κ is unintuitive under skewed marginals and a reviewer will ask for it |
| **Prevalence index** per task | The kappa paradox: 95% agreement on a 45/5 split can yield κ ≈ 0.2. Without prevalence reported, that looks like disagreement and is not |
| **κ excluding all-`unknown` items**, reported alongside | Three annotators all answering `unknown` agree in the κ sense. That is agreement about the evidence, not about the finding, and it inflates κ_derived specifically |
| **`unknown` rate per sub-question** | Direct empirical input to the `evidence_gap` design in ADR-0009 |
| Self-reported confidence vs correctness-proxy | Free incidental test of ADR-0010 §1 |

### 6.5 The analysis instrument, and what dry-running it already found

[`phase0/v4_kappa.py`](../../phase0/v4_kappa.py) — single file, standard library only, no install step. It carries the fusion rule of §6.3 in code, so the rule cannot drift between the document and the analysis.

```
python v4_kappa.py --demo            # dry-run the whole pipeline on synthetic data
python v4_kappa.py annotations.csv   # the real thing
```

**Dry-run it before booking annotators.** Twelve annotator-hours is the most expensive input in Phase 0, and discovering that the analysis is wrong afterwards wastes all of it.

That is not hypothetical — the first dry-run (2026-08-16, 5.8s) found a defect in this kit's own logic:

> In the synthetic data, Q4 scored **κ = 0.749** but **κ ex-unknown = 0.593** — because 15 of 50 findings had all three annotators answering `unknown`. Raw κ counts that as agreement. It is agreement about the *evidence*, not about the finding. Under raw κ, Q4 was "gate-eligible"; under the honest figure it is not.

**Rule, fixed here:** gate eligibility uses **κ excluding all-`unknown` items**, whenever such items exist. Otherwise a sub-question that nobody can answer looks like the most reliable one in the set — and would be promoted to a release gate on the strength of shared ignorance.

The demo also confirms this kit's stated precision claim rather than asserting it: the bootstrap CI at n=50 with 3 raters came out at roughly ±0.15, matching §6.5.

### 6.6 Honest limit on n

At n=50 with 3 raters, the bootstrap CI on κ is roughly **±0.10–0.15**. That is enough to separate 0.4 from 0.75 — the effect this experiment is looking for — and **not** enough to publish "κ = 0.71" as a measurement.

**V4 is a directional probe that picks a data model.** Anyone quoting its κ as a headline number is misusing it, and the report should say so on its first page.

---

## 7. How this experiment fails

| Failure | Symptom | Prevention |
|---|---|---|
| **Everything is `unknown`** | Sub-question κ high but meaningless; `unknown` rate >50% | The environment brief (§2). If it still happens, the brief is under-specified — fix it and re-run, do not interpret |
| **Skewed marginals** | κ near 0 with 90%+ agreement | Balanced strata (§3.1) + prevalence index reported |
| **Memory, not judgment** | κ_derived ≈ κ_holistic suspiciously exactly | 48-hour washout, randomized order |
| **Correlated annotators** | Both κ high, both forms | Three different backgrounds; no discussion until complete |
| **Fusion rule tuned after the fact** | The result is whatever was wanted | §6.3 published before annotation; commit hash in the report |
| **Corpus drift** | V2/V3 not comparable | Content-hash, frozen evidence snapshot, pinned `epss model_version` |
| **The founder annotates and analyses** | Unfalsifiable | Founder may annotate; someone else runs the analysis blind to which form is which |

---

## 8. Outputs

1. **`v4-corpus-v1.0`** — 50 findings with frozen evidence. Reused by V2 and V3.
2. **The environment brief**, versioned with the corpus.
3. **Raw annotations**, 300 rows, with annotator id, form, session, and order position.
4. **The report:** κ_holistic and κ_derived with CIs, per-sub-question κ, `unknown` rates, prevalence, percent agreement, and the pre-registration commit hash.
5. **The free-text corpus** — every "anything the questions did not let you say" answer. **Read this before reading the κ values.** It is where a sixth sub-question comes from, and it is the only part of the experiment that can surface something nobody thought to ask.
6. **A decision**, written the same day, against §1's table.

---

## 9. What V4 cannot tell us

- **Whether the answers are right.** It measures agreement, not accuracy. Three analysts can agree and be wrong — and `evaluation-system.md` §3.3 already alarms on exactly that pattern in production.
- **Whether these five sub-questions are the right five.** Output 5 is the only evidence on that, and it is qualitative.
- **Anything about a real tenant.** Northwind is fictional. Real environments have unresolved ownership, undocumented services and stale asset registries — all of which raise the `unknown` rate. **Treat V4's `unknown` rate as a floor.**
- **Whether analysts would use the decomposed form willingly.** Five questions per finding is five times the clicks. If decomposition wins on κ and loses on adoption, the answer is to have the *system* answer the sub-questions with cited evidence and have the analyst confirm — which is the product, and is the reason this result matters.
