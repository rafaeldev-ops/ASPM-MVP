# Competitive Positioning — SDIP

**Deliverable:** CLAUDE.md §46.C
**Lens:** Competitive intelligence. Where the product concept collides with shipping 2026 platforms, what is already free, and what ground is actually open.
**Date:** 2026-08-14
**Status:** Analysis. Supersedes the differentiation ranking in `docs/product/critique-product.md` §9 on two points of fact.
**Inputs:** the four SDIP critiques (architecture, product, security, AI/RAG) plus primary-source verification performed for this document.

---

## 0. Verdict

The product critique bet the company on **H1 — decision expiry and event-triggered re-litigation** and asserted that DefectDojo's `risk_accepted` is a terminal status with nothing re-evaluating it. **That assertion is wrong**, and the error matters, because the wrong version of the claim is refuted by a free tool in the first technical call.

What verification against vendor documentation actually shows:

> **Expiry is commodity. Every serious platform expires exceptions on a calendar and re-opens them. Not one documents a mechanism that re-opens a closed decision because the *world* changed.**

DefectDojo Full Risk Acceptances carry an expiration date and set findings back to Active when it passes. Snyk ignores expire *and* resurface when a fix becomes available. Vulcan Cyber (now Tenable) and Rapid7 InsightVM both ship approval workflows with calendar expiry and document no threat-triggered revocation. Nucleus ships structured exception management with approvals and expiration dates.

So the differentiator is not expiry. Stated correctly it is narrower, harder to copy, and survives the first meeting:

> **Every vendor instruments the clock. None instruments the world.**

Three further corrections and refinements follow from the verification and from reconciling all four critiques:

1. **The unit of value is the closed pile, and the closed pile is mostly not risk acceptances.** Formal risk acceptance is the small, governed, already-instrumented minority. The large majority of closed findings are *false-positive dismissals* — `false_p` in DefectDojo, "dismiss as false positive" in GitHub, Semgrep memories, AI auto-dismissals — and **no vendor expires those at all**. A dismissal is forever, everywhere, by default. That is the actual unowned territory.
2. **The differentiation is not one hypothesis but one product with three faces.** Re-litigation (D1) is the mechanism, the audit-grade decision record (D2) is what makes it expensive, and measured decision quality (D3) is what makes it *believable*. Ranking them as competing bets, as the product critique did, mis-frames them: D1 without D3 is an unfalsifiable claim from an unknown vendor, and D1 without D2 caps ACV at ~$45k.
3. **Five of the seven genuinely open capabilities come from the security and AI/RAG critiques, not the product critique** — advisory range-narrowing detection, `evidence_availability` in the decision record, published false-negative upper bounds, customer-owned evaluation harnesses, empirical agreement bands in place of model confidence. The positioning has been looking in the wrong document.

---

## 1. Evidence standard used here

The critiques in this repository are dense with vendor claims. Vendor claims decay and marketing copy overstates. Every capability assertion below carries a provenance marker, and the ledger in §3 is only as good as these markers:

| Marker | Meaning |
|---|---|
| **[V]** | Verified 2026-08-14 against vendor documentation or a primary source, quoted in §4 or cited in Sources |
| **[I]** | Inherited from an earlier SDIP critique document; sourced there, not re-verified here |
| **[U]** | Unverified — marketing-level claim, or secondary source only. **Must not be used to justify a build/skip decision until checked.** |

**Rule for this document and its successors:** a capability may be classified *commodity* on **[I]** or **[V]**. A capability may be classified *open* — i.e. we intend to build there — **only on [V], and only against the vendor's own documentation**, never against a comparison site or a listicle. Claiming open ground on a **[U]** is how a team spends nine months building something a competitor demos in month three.

---

## 2. The market map

SDIP does not have one competitive set. It has five, and it is priced against the cheapest.

| Segment | Who | What they own | Why SDIP loses head-on | Why they are not the real threat |
|---|---|---|---|---|
| **1. Scanner-native triage** | Semgrep, Endor Labs, Snyk, Checkmarx, GitHub Code Security, GitLab | The call graph. Reachability is deterministic, cheap, explainable, and cuts SCA volume ~92% / high-crit FPs up to 98% **[I]** | SDIP consumes scanner output and never sees code deeply enough to compute reachability **[I]** | They suppress at the source and do not instrument what happens to a dismissal afterwards |
| **2. ASPM aggregators** | ArmorCode, Cycode, Apiiro, OX, Phoenix Security, Torq+Jit | Connector breadth (100–200+), risk/context graphs, agentic triage, remediation workflow **[I]** | Feature-matrix comparison in round one; SDIP has 3–5 connectors | Their graph points at the *open* queue; nobody's roadmap points at the closed one |
| **3. VM / exposure management** | Nucleus, Brinqa, Tenable (+Vulcan), Rapid7, Seemplicity, Wiz+Dazz (Google) | Exception governance, SLA clocks, 200+ connectors, enterprise distribution **[V]** for exception mechanics | They already own the exception workflow and the buyer relationship | Their exception model is calendar-driven; extending it to evidence triggers requires the evidence layer they do not have |
| **4. The free floor** | **DefectDojo**, Jira, GitHub code scanning | Ingestion, normalization, dedup, SLA, risk acceptance with expiry — at **$0** **[V]** | Six of the eight steps in CLAUDE.md §2's pipeline are free here **[I]** | It is a system of record, not a system of watching. Nothing in it looks outward after a decision is made |
| **5. Adjacent GRC** | Vanta, AuditBoard, LogicGate, Sprinto | Exception workflow, evidence collection, auditor-facing artifacts **[I]** | They own the compliance buyer | They have no idea what a reachable SQL injection is |

**The strategic read.** Segment 1 has the mechanism SDIP cannot build. Segment 2 has the features SDIP cannot match on breadth. Segment 3 has the buyer. Segment 4 sets the price of everything SDIP was planning to build first. **The only unclaimed ground is the seam between 3 and 5** — security semantics applied to the governance of decisions already made — and it is unclaimed because it requires both halves and each segment has only one.

---

## 3. Capability ledger

Read this as a build/skip instrument. "Open" is not "good idea"; it means no vendor documentation found describing a shipped mechanism, verified today.

### 3.1 Commodity — do not build, do not pitch

| Capability | Who ships it | Marker |
|---|---|---|
| Scanner parsers / normalization (200+ tools) | DefectDojo, free | [I] |
| Deduplication | DefectDojo, every ASPM | [I] |
| CVE/NVD/OSV/KEV/EPSS enrichment | Everyone; feeds are free | [I] |
| Reachability analysis | Endor, Semgrep, Snyk, Cycode | [I] |
| AI triage / FP filtering | Semgrep (60% of triage, 95% agreement), Pixee, Checkmarx, Corgea, Orca | [I] |
| **Organizational triage memory** | **Semgrep Autotriage Memories, Checkmarx Triage Agent** | [I] |
| Context/risk graph | ArmorCode, Cycode, Apiiro, Torq+Jit | [I] |
| Risk scoring with business context | Nucleus, Brinqa, every ASPM | [I] |
| **Exception expiry + approval workflow** | **DefectDojo, Snyk, Vulcan/Tenable, Rapid7, Nucleus, Sysdig** | **[V]** |
| SLA tracking and breach reporting | DefectDojo (free), Nucleus, ArmorCode | [I] |
| Autofix / PR generation | Apiiro, Snyk, GitLab, GitHub Copilot Autofix, Pixee | [I] |
| Remediation workflow / Jira write-back | Jira itself; Nucleus; ArmorCode | [I] |
| SSO/SAML, RBAC, audit logging | Table stakes; buy WorkOS-class | [I] |
| LLM provider abstraction | Not a feature; a tax | [I] |

**The line that must appear in the internal strategy doc:** CLAUDE.md §4's primary differentiation hypothesis — organizational decision memory — is **commodity as of 2026** and is retired. The row above is not a partial overlap; it is the same feature with a vendor's name on it.

### 3.2 Contested — winnable only with a named mechanism, never on quality claims

| Capability | State of the art | What winning requires |
|---|---|---|
| Cross-tool same-root-cause correlation | Everyone claims it; quality varies and nobody publishes numbers | A published benchmark with a golden set (§5, D3). Claiming "better dedup" without one is noise |
| Ownership resolution | Claimed broadly; measured nowhere | Publish the resolution rate. CLAUDE.md §31 already makes it a metric — promote it and prove it |
| Evidence provenance / citation correctness | Claimed as "evidence-backed"; citation *correctness* measured by nobody | Measure whether the cited evidence supports the claim, not that a citation exists (AI/RAG critique §4.4) |
| Decision audit trail | Nucleus and ArmorCode both say "defensible" **[I]** | Neither ships a record designed for an incident reviewer. The delta is `evidence_availability` (§3.3) |
| Cost-controlled AI | ArmorCode shipped agents explicitly aimed at capping AI spend (Aug 2026); DefectDojo Sensei previews before spending **[I]** | The market has already hit this wall. Cost control is now table stakes, not a differentiator — but failing it is disqualifying |

### 3.3 Open — no vendor documentation found describing a shipped mechanism

| # | Capability | Verification status | Source critique |
|---|---|---|---|
| **O1** | **Evidence-triggered re-opening of closed dispositions** (KEV listing, EPSS band crossing, exploit publication, reachability change, exposure change, ownership change) | **[V]** — five platforms checked, all calendar-only; one marketing claim outstanding (§4.3) | product |
| **O2** | **Re-litigation of false-positive dismissals**, not just formal risk acceptances | **[V]** — no vendor expires an FP dismissal at all | product |
| **O3** | **`evidence_availability` in the decision record** — what was *not* knowable at decision time (KEV status then, EPSS then, advisory versions then) | [I] | security §5.3 |
| **O4** | **Advisory range-narrowing detection** — diff affected-version ranges on every advisory refresh; a narrowing re-opens every finding suppressed on that basis | [I] | security §4.3 |
| **O5** | **Published false-negative upper bound** via randomized stratified audit (rule of three: ≥600 clean audits ⇒ FN ≤ 0.5%) | [I] | AI/RAG §5.2 |
| **O6** | **Customer-owned evaluation harness** for the vendor's own AI, shipped as a product feature | [I] | AI/RAG §7.4 |
| **O7** | **Empirical agreement bands** shown instead of model confidence ("of the last 217 findings in this band, analysts agreed with 94%, CI 90–97%") | [I] | AI/RAG §3.4 |

O1 and O2 are the mechanism. O3 and O4 are what make the mechanism credible to an auditor. O5–O7 are what make it credible to a skeptical buyer. **They are one product.**

---

## 4. The closed pile: what every vendor actually does

This is the section that earns the positioning. Everything here was checked against vendor documentation on 2026-08-14.

### 4.1 The table

| Platform | Closed dispositions | Expiry | Auto-reopen triggers | Covers FP dismissals? |
|---|---|---|---|---|
| **DefectDojo** (free, the real incumbent) | Simple Risk Acceptance; **Full** Risk Acceptance; `false_p`; `out_of_scope`; `mitigated` | Full RA only: expiration date, system default if unset | **Calendar only.** On expiry, findings "will be set to Active again"; optional SLA restart. Simple RA has no expiry at all | **No.** `false_p` never expires |
| **Snyk** | Ignores (won't fix / temporary / not vulnerable) | Optional expiry | **Calendar, plus one evidence trigger**: ignored "until either the ignore period expires, or the vulnerability becomes fixable" — resurfaces when a fix exists | No |
| **Vulcan Cyber / Tenable** | Exception requests with mandatory approvals | Admin-set default; per-request override gated by permission | **Calendar only.** On expiry "the SLA of the vulnerability resumes counting." No threat-triggered revocation documented | No |
| **Rapid7 InsightVM** | Vulnerability exceptions; submit/review permission split; global exceptions need Global Admin | Calendar (`Expires` date picker) | **Calendar only.** Expired exceptions require manual resubmission | No |
| **Nucleus Security** | Structured exception management, documented approvals | Expiration dates | Product page: exceptions "remain active and fully tracked as new scan data is ingested and updated." Marketing elsewhere claims *continuous risk re-evaluation / automated reassessment when threat conditions change* — **[U]**, mechanism not documented (§4.3) | Not documented |
| **GitHub code scanning** | Dismissal with reason (false positive / won't fix / used in tests) | None | **None.** Permanent until a human reverses it | It *is* the FP path — and it never re-opens |
| **Semgrep** | Autotriage Memories | None | **None** — memories exist to make suppression *stickier* across future findings | It is the FP path |
| **Orca** | AI agent auto-dismissal | None | **Manual only** — users may "override the agent's verdict, or roll back an automatic dismissal" **[U]**, secondary source | It is the FP path |
| **Jira** (where most of this actually lives) | Closed ticket | None | None | n/a |

### 4.2 What the table says

1. **Calendar expiry is universal in the VM/exposure segment and free in the OSS floor.** Pitching "we expire risk acceptances" is pitching a 2018 feature. Anyone selling against DefectDojo who claims it does not expire risk acceptances will be corrected in the room and lose the call.
2. **Snyk is the only vendor with a genuine evidence trigger, and it has exactly one: fix availability.** That is the *good* news direction — a fix appearing is not a threat change. Nobody watches the bad direction.
3. **The FP pile is universally uninstrumented.** Every platform that lets an AI or a human dismiss a finding as a false positive treats that dismissal as permanent. This is the largest volume of closed decisions in any organization, it is where AI triage is actively *increasing* the volume, and it has no expiry, no review, and no watchman anywhere in the market.
4. **The direction of the market's investment is opposite.** Semgrep memories, Checkmarx triage learning, and every AI auto-dismissal feature exist to make suppression stickier and more automatic. Volume in the closed pile is growing, monitored by nothing. That is a widening gap, not a static one — which is what makes it worth a company rather than a feature.

### 4.3 The one claim that could kill this — and how to check it

**Nucleus markets "Continuous Risk Re-evaluation — automated reassessment when threat conditions change" [U].** If that means what SDIP intends to build, D1 is occupied by a funded incumbent with 200+ connectors and a $20M Series C.

The reading most consistent with their own product page — "exceptions remain active and fully tracked as new scan data is ingested" — is **re-evaluation on rescan**, i.e. the finding's state refreshes when the scanner reports again, not that an exception is revoked because a CVE entered KEV. Those are very different products. But the distinction is not established by inference.

**This is the single highest-priority verification task in the whole positioning, and it is a one-hour job, not a research project.** Do it before any roadmap is committed:

- Request a demo or trial and ask one question: *"A CVE we accepted risk on 60 days ago is added to CISA KEV tomorrow, and no new scan has run. What happens, and where do I see it?"*
- Ask the same question about a **false positive** dismissal, not a risk acceptance.
- Ask what the audit record shows about what was known at the time of the original decision.
- Record the answers, with dates, in the living competitive teardown (product critique §13.9).

If the answer is "the exception is automatically revoked and the finding re-opened with a notification": D1 is contested rather than open, and the position shifts to O2+O3+O4 (FP pile, `evidence_availability`, range-narrowing) which remain unoccupied regardless. **Nothing in this document collapses on that answer — but the pitch does, and it should be discovered by us, not by a prospect.**

---

## 5. Differentiation hypotheses, ranked

Three, ordered by defensibility. They are sequenced, not alternative: D1 is the wedge, D3 is what makes D1 trustworthy, D2 is what makes D1 expensive.

---

### D1 — Evidence-triggered re-litigation of closed decisions

**Rank 1. This is the product.**

**Claim.** No closed disposition in this platform is permanent. Every deprioritization, dismissal and acceptance is stored with the evidence that justified it and the **conditions under which that justification becomes invalid**. The platform watches those conditions continuously and wakes the decision up — with the original evidence, the original approver, and what has changed since.

**Mechanism.** A delta-detector over KEV membership, EPSS band (pinned to model version), exploit-artifact publication, advisory range narrowing (O4), reachability verdict change, asset exposure change, and ownership change. **It is SQL and cron, not inference.** The model is invoked only when a decision actually wakes up — which is what keeps it inside the ~$750/customer/month COGS ceiling the product critique derived.

**Competitor delta, precisely stated (from §4.1):**

- vs **DefectDojo** — DefectDojo expires Full Risk Acceptances on a calendar and never touches `false_p`. SDIP re-opens on evidence, and covers dismissals.
- vs **Snyk** — one trigger, in the benign direction (a fix appeared). SDIP watches the adversarial direction.
- vs **Vulcan/Tenable, Rapid7** — calendar only, documented.
- vs **Nucleus** — re-evaluation on rescan, pending §4.3 verification.
- vs **GitHub, Semgrep, Orca, Checkmarx** — dismissals and memories are permanent by design and getting stickier.

**Why it is defensible for more than a quarter.** Not the idea — the idea is one sentence and copyable. The *prerequisites* are the moat, and each is a quarter of work an incumbent must do inside an architecture built for the open queue:

1. Storing the **evidence state at decision time**, not just the decision (the append-only observation model from the architecture critique §5.3 — irreversible, and impossible to backfill).
2. **Version-pinned external knowledge** (EPSS model version, advisory snapshots with content hashes) or the deltas are noise. EPSS v4→v5 already breaks naive comparisons.
3. **Advisory range-narrowing detection** (O4) — requires snapshotting every advisory version, which nobody does because nobody needs it until they need this.
4. A **false-positive rate on re-opens** low enough that analysts do not mute it — which requires D3.

An incumbent bolting "re-open on KEV" onto a mutable finding table can ship the trigger in a sprint and cannot ship the *record of what was known then*, because they overwrote it.

**What kills D1:**

- The §4.3 verification comes back "Nucleus already does this." → Fall back to O2/O3/O4; re-scope.
- The falsification test below returns "those were still fine." → **The company as briefed is dead.** Run this test first.
- Re-litigation precision lands below ~40%. → SDIP becomes a new alert-fatigue source, which is the failure mode the product exists to fix. Guardrail metric: re-opens per analyst per week, capped (product critique §11/§31).

**Falsification test — one week, no product.** Take three prospects' historical closed-finding exports (DefectDojo, Jira, or GitHub CSV). Compute how many would have re-opened in the last 12 months under D1's triggers. Show an AppSec director and ask: *"would you have wanted to know about these?"* Pre-register the threshold: **≥3 of 5 partners say yes, and ≥1 names a specific finding that alarms them.** Deadline: before any schema is written.

---

### D2 — Audit-grade decision evidence, with the CRA clock as the hook

**Rank 2. The ACV multiplier, not a separate product.**

**Claim.** SDIP produces a decision record designed to be read by an incident reviewer, an auditor, or a regulator — including the field nobody else has: **what was not knowable at the time**.

**The mechanism that is actually unowned (O3).** Competitors' audit trails record the conclusion. `evidence_availability` records the epistemic state: *CVE-X was not in KEV until day 197; EPSS was 0.008 on day 4; advisory v3 was the current version and did not list our package.* A log of conclusions is a liability in a negligence claim. A log of epistemic state is a defence. That distinction is the entire pitch, and it is one JSON block in the schema — provided it is designed in from the first migration (security critique §5.3).

**The dated hook.** EU CRA reporting obligations begin **2026-09-11 — 28 days from this document**: 24-hour early warning to ENISA/CSIRTs for actively exploited vulnerabilities, 72-hour full notification, 14-day final report **[I]**. A 24-hour clock on *actively exploited* vulnerabilities is mechanically the same query as D1's KEV trigger. The engine that re-opens a stale dismissal also produces the regulator's evidence pack.

**Why it multiplies ACV.** Efficiency pitches cap at ~$45k blended (product critique §7). Compliance changes the buyer from "director with an efficiency problem" to "director with a September deadline" and is the only path in this brief above $100k ACV.

**Constraint that must be honoured.** Per the security critique §5.6: KEV listing and confirmed active exploitation must be a **hard, non-suppressible escalation path** outside the risk score — no policy predicate, no analyst action, no model recommendation may suppress it. Selling a compliance clock while retaining the ability to silence it is indefensible. Add the contractual line: *SDIP does not determine regulatory reportability.*

**What kills D2:** a GRC platform (Vanta, AuditBoard) ships security-finding decision records, or an ASPM ships a CRA evidence pack. Watch both. Neither has the other's half today.

---

### D3 — Measured decision quality: the published FN bound and the customer-owned harness

**Rank 3 by revenue, rank 1 by trust. Without it, D1 is an unfalsifiable claim from an unknown vendor.**

**Claim.** SDIP is the only platform that tells you how often it is wrong, in the direction that matters, with a number the customer can verify themselves.

**Three mechanisms, all currently unowned:**

- **O5 — a published false-negative upper bound.** Randomized stratified audit of auto-deprioritized findings with logged propensities; rule of three: ≥600 clean audits ⇒ FN ≤ 0.5% at 95%. Costs ~40 analyst-hours per window — **subtract it from the savings claim**. "We saved 160 hours net of audit" is more credible than "we saved 200."
- **O6 — a customer-owned evaluation harness.** Exploitability ground truth is tenant-specific, so the AI quality gate *cannot* be vendor-owned. Ship the harness. No ASPM vendor hands the customer a measurable eval set for the vendor's own AI.
- **O7 — empirical agreement bands instead of model confidence.** Never render a model's `confidence` float. Render: *"of the last 217 findings scored in this band for your organization, analysts agreed with 94% (95% CI 90–97%)."*

**Why this is competitive and not just hygiene.** Every accuracy claim in this market is unauditable: Semgrep's 95% agreement is measured on Semgrep's data; Pixee publishes 70–95% FP reduction with proprietary thresholds; Checkmarx and ArmorCode publish no triage numbers **[I]**. **Publishing an open, versioned triage benchmark plus a harness that scores any vendor is the cheapest credible distribution move available** — a few engineer-months, and whoever owns the referee owns the conversation.

**What kills D3:** a well-funded vendor publishes first and defines the metric to suit their architecture. This is a first-mover asset with a decaying window.

---

### 5.1 Explicitly rejected

| Hypothesis | Why rejected |
|---|---|
| **Organizational decision memory** (CLAUDE.md §4's own primary hypothesis) | Shipped by Semgrep, Checkmarx, ArmorCode, Nucleus; category essay already published by Pixee. Also: the moat refills in a fortnight and is contractually portable **[I]** |
| **Noise reduction / "we cut 10,000 findings to 1,000"** | It is the DefectDojo demo, and scanner-layer reachability already claims 92% with a stronger mechanism **[I]** |
| **Context/risk graph** | Marketing term owned four ways over |
| **AI triage / FP filtering** | Commodity; Semgrep handles 60% of triage |
| **"Defensible prioritization"** | Two competitors use the exact word in headline copy. Delete it from all external material |
| **Security Decision Intelligence as a new category** | Category creation needs analyst-relations budget and 2–3 years. Use it as an internal north star only |

---

## 6. Positioning

### 6.1 Category placement — the two-channel rule

**Channel A (discovery: metadata, RFPs, marketplaces, comparison pages, listicles):** list as **ASPM / vulnerability management**. CLAUDE.md §3's prohibition on the category words, applied literally, removes SDIP from every shortlist mechanism mid-market buyers actually use. That is invisibility, not differentiation.

**Channel B (the sales conversation):** lead with the mechanism, never the category.

### 6.2 The line

> **"Your closed findings are not closed. Every risk you accept comes with an expiry, a watchman, and a record of what you knew. When the world changes, the decision comes back."**

Three words to avoid in all external copy: **defensible** (Nucleus, ArmorCode), **context graph** (ArmorCode, Cycode, Apiiro, Torq), **decision intelligence** (unowned, but requires a category budget SDIP does not have).

Term worth claiming: **decision debt** — the accumulated pile of closed findings whose justification has silently expired. Unclaimed in the searches performed for this document; verify before investing in it.

### 6.3 The demo

Not a dashboard. Import their existing closed pile — DefectDojo export, Jira CSV, GitHub dismissals — and show the diagnosis:

> *"Of the 3,412 findings you closed last year: 46 are now on CISA KEV, 12 became internet-reachable, 7 had their advisory's affected-range narrowed after you dismissed them, and 9 are in services that changed owners. Here they are, with what you knew at the time and who signed off."*

Runs locally, sends nothing anywhere, no repo credentials (security critique §6.2). It routes around the security review that kills seed-stage security vendors, and it is verifiable by the customer against their own data.

### 6.4 Objection handling

| Objection | Answer |
|---|---|
| *"DefectDojo does this for free."* | "It expires risk acceptances on a calendar — correctly, and we'd keep using it. It never touches your false-positive pile, and a calendar doesn't know a CVE hit KEV. Which of your closed findings is a date going to catch?" |
| *"Nucleus says it continuously re-evaluates."* | Pending §4.3. Until verified: "Ask them what happens when no new scan has run and the CVE enters KEV, and ask what their record shows about what you knew at the time." Never assert they lack it |
| *"Semgrep already remembers our triage decisions."* | "Memories make suppression stickier — that's the right feature pointed the opposite way. What wakes a memory up when it becomes wrong?" |
| *"GitHub bundles this at $30/committer."* | "GitHub dismissals never re-open. Ours do, and we watch GitHub's too." |
| *"If your AI says ignore it and we get breached, who's accountable?"* | Refuse the premise architecturally: the model can escalate but never suppress (security critique M1); every suppression carries a named human; then D3's published FN bound; then the process guarantee — automatic re-open within 24 hours of KEV listing, EPSS threshold crossing, exploit publication, reachability or exposure change, with SLA credits |
| *"We'd have to replace our stack."* | "You wouldn't. We sit on top of DefectDojo/Jira/GitHub, read-only, and hold no credential that authenticates into you." |

### 6.5 Qualifying question

> *"Do you have an open or recently denied AppSec headcount requisition?"*

A team that saves 0.5 FTE without a req absorbs more work and releases no cash; the ROI story evaporates at renewal **[I]**. This predicts close rate better than company size, industry or scanner stack.

---

## 7. Assumption register

Positioning claims that are not yet facts. Each needs an owner, a date, and a kill criterion.

| # | Assumption | Test | Deadline | If false |
|---|---|---|---|---|
| A1 | Nucleus's "continuous re-evaluation" is rescan-driven, not threat-driven | Demo + the four questions in §4.3 | **2026-08-21** | D1 contested; fall back to O2/O3/O4 |
| A2 | Directors want the re-opens | 3 prospect closed-pile exports; ≥3 of 5 say yes | 2026-09-30 | **Stop. The thesis is dead** |
| A3 | Re-litigation precision ≥50% on partner data | Backtest against 12 months of history | 2026-10-31 | Re-tune triggers or stop |
| A4 | The FP pile is genuinely larger than the risk-acceptance pile | Count both in the three exports | 2026-09-30 | O2 loses force; lean on O1+O3 |
| A5 | Compliance buyers will pay >$100k for the CRA evidence pack | 5 interviews with directors at EU-market manufacturers | 2026-10-31 | ACV stays ~$45k; venture case weakens |
| A6 | Nobody publishes an open triage benchmark first | Monitor Semgrep, Pixee, Endor, OWASP | Continuous | D3's window closes; ship faster |
| A7 | Calendar expiry really is universal (i.e. §4.1 has no vendor we missed) | Re-check Brinqa, Seemplicity, Phoenix, Cycode, Apiiro, OX docs | 2026-09-15 | Adjust the ledger |

---

## 8. Competitive monitoring

The product critique asked for a living teardown. Concretely:

**Watchlist and what would hurt:**

| Vendor | The feature that would hurt | Where it appears first |
|---|---|---|
| Nucleus | Threat-triggered exception revocation | Product page, release notes |
| DefectDojo | Expiry on `false_p`, or evidence triggers in Sensei | GitHub commits, Pro changelog |
| Semgrep | Memory expiry / memory invalidation on new evidence | Engineering blog |
| GitHub | Dismissed-alert re-opening on advisory change | Changelog |
| Snyk | A second evidence trigger in the adversarial direction | Docs diff |
| ArmorCode / Cycode | CRA evidence pack, or exception auto-revocation | Press releases |
| Vanta / AuditBoard | Security-finding decision records | Product launches |

**Cadence:** monthly diff of the seven documentation sources in §4.1, quarterly full teardown, immediate review on any competitor funding or acquisition announcement. Log every check with a date, including the negatives — *"checked 2026-08-14, still calendar-only"* is the evidence that supports the pitch, and its value is entirely in being dated.

---

## 9. What this changes in CLAUDE.md

| Section | Change |
|---|---|
| §3 Positioning rule | Replace the prohibition list with the two-channel rule (§6.1). Delete "defensible" from external copy |
| §4 Competitive reality | Add: *"The primary differentiation hypothesis as originally written — organizational decision memory — is shipped by Semgrep, Checkmarx, ArmorCode and Nucleus as of 2026 and is retired."* Add calendar-based exception expiry to the not-sufficient list |
| §5 MVP wedge | Narrow to: import existing findings **and existing decisions** → compute decision debt → re-litigate on evidence change |
| §7 Decision contract | `accepted_risk` and `false_positive_candidate` are not terminal states. Replace with `deprioritized_until(conditions[])`. Add `evidence_availability` |
| §34 Wedge story | Retire "10,000 findings → 2,500 duplicates" (it is the DefectDojo demo). Replace with the decision-debt story (§6.3) |
| §42 Artifacts | Add `docs/product/competitive-teardown.md` as a living, dated document |

---

## 10. Open verification items

1. **A1 — the Nucleus question (§4.3).** Highest priority. One hour of work.
2. Re-check Brinqa, Seemplicity, Phoenix Security, Cycode, Apiiro and OX exception documentation; §4.1 covers the five most likely, not all.
3. Confirm the ArmorCode exceptions position — their blog returned HTTP 403 to automated fetch; retrieve manually.
4. Confirm Orca's dismissal-rollback behaviour against Orca's own documentation (currently **[U]**, secondary source).
5. Check whether "decision debt" is claimed by any vendor or trademarked before investing in the term.
6. Verify the EU CRA reporting obligations directly against the ENISA/Commission text before any marketing copy cites the dates, and obtain legal review of the decision-support positioning (security critique §11).

---

## Sources

Verified 2026-08-14 for this document:

- [DefectDojo — Risk Acceptances (expiration, findings set Active again, SLA restart)](https://docs.defectdojo.com/en/working_with_findings/findings_workflows/risk_acceptances/)
- [DefectDojo — Finding Status Definitions](https://docs.defectdojo.com/triage_findings/findings_workflows/finding_status_definitions/)
- [Snyk — Ignore issues (ignored until the period expires or the vulnerability becomes fixable)](https://docs.snyk.io/manage-risk/prioritize-issues-for-fixing/ignore-issues)
- [Snyk — CISA KEV filter](https://updates.snyk.io/identify-cisa-kev-vulnerabilities-for-compliance/)
- [Vulcan Cyber ExposureOS — Exception Requests (approvals, expiration, SLA resumes)](https://help.vulcancyber.com/en/articles/6141419-exception-requests)
- [Rapid7 InsightVM — Working with vulnerability exceptions (calendar expiry, manual resubmission)](https://docs.rapid7.com/insightvm/working-with-vulnerability-exceptions/)
- [Nucleus Security — Remediation workflows ("exceptions remain active and fully tracked as new scan data is ingested")](https://nucleussec.com/platform/remediation-workflows/)
- [Nucleus Security — Platform](https://nucleussec.com/platform/)
- [Orca Security — AppSec triage agent (override or roll back an automatic dismissal)](https://orca.security/resources/blog/application-security-prioritization-remediation-triage/) — secondary, **[U]**
- [CISA — Reducing the significant risk of Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog/reducing-significant-risk-known-exploited-vulnerabilities)

Inherited (sourced in the referenced documents): `docs/product/critique-product.md` for market consolidation, vendor capability claims, pricing bands, ACV arithmetic and the EU CRA dates; `docs/architecture/critique-architecture.md` for reachability numbers and the append-only observation model; `docs/threat-model/critique-security.md` for the decision-record schema, range-narrowing detection, escalate-only model authority and credential posture; `docs/evaluation/critique-ai-rag.md` for the FN-bound methodology, agreement bands and the per-tenant evaluation harness.
