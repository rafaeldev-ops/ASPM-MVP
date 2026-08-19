# Competitive Teardown — SDIP

**Type:** Living document. Every claim carries a check date, including the negatives.
**Deliverable:** `competitive-positioning.md` §8 · CLAUDE.md §42 (added by positioning §9)
**Created:** 2026-08-16 · **Last round:** 2026-08-16 · **Next scheduled round:** 2026-09-16
**Relationship to `competitive-positioning.md`:** that document is the analysis and is versioned; **this one is the instrument and is appended to.** Where they disagree, this document is newer and wins, and the correction is logged in §5.

---

## 0. Why the dated negative is the asset

The pitch rests on a claim about what competitors *do not* do. That kind of claim has a half-life measured in weeks and cannot be supported by memory, by a comparison site, or by a listicle.

> **"Checked 2026-08-16, Brinqa risk acceptances still do not expire"** is worth more than any amount of analysis, and it is worth exactly nothing without the date.

So this file is append-only in spirit: rounds are added, never rewritten. A superseded finding stays visible with its original date next to the finding that replaced it. That is how a reader six months from now can tell the difference between "we verified this" and "we believed this."

### 0.1 Evidence markers (inherited from positioning §1)

| Marker | Meaning |
|---|---|
| **[V]** | Verified against the vendor's own documentation on the stated date, with the sentence quoted |
| **[I]** | Inherited from an SDIP critique document; sourced there, not re-verified |
| **[U]** | Marketing-level or secondary source only. **May not justify a build/skip decision** |
| **[N]** | **Not checkable from public sources.** Distinct from [U] and from "absent" — see §0.2 |

### 0.2 The rule that keeps this document honest

**"No public documentation found" is not "the vendor does not do it."**

Several vendors in this market publish no product documentation outside a customer portal. Recording those as gaps would manufacture open ground that does not exist, and the error would only surface in a sales call. They are marked **[N]** and they stay open until someone gets into the product.

A capability may be classified **open** — meaning we intend to build there — **only on [V]**.

---

## 1. The standing question set

Ask these of every platform, in this order. They are designed so that a marketing answer and a mechanism answer sound different.

| # | Question | What a real mechanism sounds like | What marketing sounds like |
|---|---|---|---|
| **Q1** | "A CVE we accepted risk on 60 days ago is added to CISA KEV tomorrow. **No new scan has run.** What happens, and where do I see it?" | "The exception is revoked automatically and the finding re-opens with a notification naming the trigger" | "It's continuously re-evaluated as data comes in" |
| **Q2** | "Same question, but it was dismissed as a **false positive**, not a risk acceptance." | Any answer that is not "nothing" | Silence, or a redirect to risk acceptances |
| **Q3** | "The advisory's affected version range is **narrowed** so it no longer covers our version — and then widened again six months later. What happens at each step?" | "We snapshot advisories and diff the ranges" | "We pull from NVD and OSV" |
| **Q4** | "Show me the audit record for that original decision. **What does it say about what was knowable at the time** — was the CVE in KEV then? What was EPSS then, under which model version?" | A record of epistemic state | A record of the conclusion, a timestamp, and a username |
| **Q5** | "Can an exception be created with **no expiry**?" | "No" | "Yes, if you have the permission" |
| **Q6** | "How often is your AI triage wrong in the **deprioritize** direction, and how would I check that myself?" | A published bound with an n | An agreement percentage measured on their own data |

Q2 and Q4 are the ones that separate SDIP. Q5 was added in this round because two platforms answered it in the direction that helps us (§3).

---

## 2. Check log

### Round 2 — 2026-08-16

Scope: assumption **A7** from positioning §7 (re-check Brinqa, Seemplicity, Phoenix, Cycode, Apiiro, OX), plus open items 3, 4 and 5 from positioning §10, plus a re-check of **A1** (Nucleus) and of Semgrep memory lifecycle. Method: vendor documentation only.

| Vendor | Finding | Marker |
|---|---|---|
| **Brinqa** | **Risk acceptance requests do not expire at all.** Verbatim: *"Risk acceptance requests do not expire but they can be canceled, whereupon the findings' status are reverted."* Exception requests **do** expire: *"If the associated findings are not resolved by the extended due date, and the exception request has been approved, the request becomes expired and the status of the findings are reverted."* **No threat-triggered revocation documented** — expiry is due-date-driven, revocation is manual | **[V]** |
| **Nucleus** | **A1 unresolved, and documentation cannot resolve it.** The remediation-workflows page still says exceptions *"remain active and fully tracked as new scan data is ingested and updated"* and *"Set time limits and document approvals."* "Continuous Risk Re-evaluation / automated reassessment when threat conditions change" remains **FAQ-level phrasing with no documented mechanism**, and is not stated in the exception-management context. **The ambiguity is unchanged since 2026-08-14.** Q1 must be asked in a demo | **[U]** on the claim; **[V]** that the documentation does not describe the mechanism |
| **Phoenix Security** | Exception/risk-acceptance engine with an approval queue (Security Champion or admin). Expiry is configurable — and **"no expiry date" is a selectable option** (a tick box). Partial mitigation with an expiration date is supported. No threat-triggered revocation found. **KB returned HTTP 403 to automated fetch; findings are search-snippet level and need manual confirmation** | **[U]** — retrieve manually |
| **Cycode** | Agentic workflows analyze an exception request for exploitability with AI and route a recommendation to human review; the workflows *"escalate exploitable findings and suppress those that are not."* **No exception expiry or revocation mechanism documented.** Note the direction: this is a feature that **increases** the closed pile | **[U]** — product page, not documentation |
| **Seemplicity** | No public exception-lifecycle documentation. Developer docs are API/query-level; GRC material discusses *"SLA exception logs with formal risk acceptance sign-off"* as a customer obligation, not a platform mechanism | **[N]** |
| **Apiiro** | No public exception-lifecycle documentation. Their own guidance advises documenting *"the business justification, risk owner, and review date"* when remediation is deferred — a **review date is a calendar**, but this is advice to the reader, not a described product mechanism | **[N]** |
| **OX Security** | No public documentation found on exception/waiver lifecycle | **[N]** |
| **Semgrep** | **Memories re-verified: no expiration, no review date, no invalidation, no automatic revocation. Manual deletion only.** Verbatim: *"A saved memory only affects future guidance for findings triggered by the same rule in the same project."* Confirmed against the current docs and the March 2026 release notes | **[V]** |
| **ArmorCode** | Exceptions blog returned **HTTP 403 to automated fetch for the second consecutive round.** Carry forward as a manual task | **[N]** — blocked, not absent |
| **"decision debt"** (term) | **Not clean.** See §4 — this is the most consequential finding of the round | **[V]** |

### Round 1 — 2026-08-14

Recorded in `competitive-positioning.md` §4.1 and its Sources. Covered DefectDojo, Snyk, Vulcan/Tenable, Rapid7, Nucleus, GitHub, Semgrep, Orca. Summary carried forward into §3 below.

---

## 3. The closed-pile ledger — current state

The one table this document exists to maintain. **"Auto-reopen triggers" means: without a human, and without a new scan.**

| Platform | Can a closed decision be permanent? | Expiry | Auto-reopen on evidence change | Covers FP dismissals | Checked |
|---|---|---|---|---|---|
| **Brinqa** | **Yes — risk acceptances never expire** | Exception requests only, due-date driven | **None** | Not documented | 2026-08-16 **[V]** |
| **DefectDojo** (free) | Yes — Simple RA has no expiry; `false_p` never expires | Full RA only | **None (calendar)** | **No** | 2026-08-14 **[V]** |
| **Phoenix Security** | **Yes — "no expiry" is a tick box** | Configurable | None found | Not documented | 2026-08-16 **[U]** |
| **Snyk** | No — ignores can carry expiry | Optional | **One, benign direction**: resurfaces when a fix becomes available | No | 2026-08-14 **[V]** |
| **Vulcan / Tenable** | No | Admin default + per-request | **None (calendar)** | No | 2026-08-14 **[V]** |
| **Rapid7 InsightVM** | No | Calendar | **None (calendar)** | No | 2026-08-14 **[V]** |
| **Nucleus** | Unknown | Expiration dates | **Undocumented — Q1 pending** | Not documented | 2026-08-16 **[U]** |
| **GitHub code scanning** | **Yes — dismissals are permanent** | None | **None** | **It is the FP path** | 2026-08-14 **[V]** |
| **Semgrep** | **Yes — memories persist until deleted** | None | **None** | **It is the FP path** | 2026-08-16 **[V]** |
| **Cycode** | Not documented | Not documented | None found | AI suppression **increases** the pile | 2026-08-16 **[U]** |
| **Orca** | Yes — AI auto-dismissal, manual rollback | None | **None (manual only)** | It is the FP path | 2026-08-14 **[U]** |
| **Seemplicity / Apiiro / OX / ArmorCode** | — | — | — | — | **[N] unchecked** |

### 3.1 What the ledger says after two rounds

1. **The FP pile remains uninstrumented everywhere it was checked.** Two rounds, eleven platforms, one evidence trigger found in total — Snyk's, and it fires in the benign direction. **O1 and O2 are still open ground.**
2. **The market is moving the wrong way, and this round added a data point.** Cycode's agentic workflows *"suppress those that are not [exploitable]"*, Semgrep memories make suppression stickier by design and still have no lifecycle, and Orca auto-dismisses. **The closed pile is growing, generated increasingly by AI, and watched by nothing.** That is a widening gap, which is what makes it worth a company rather than a feature.
3. **Terminal suppression is not an edge case — it is offered by name.** Brinqa risk acceptances never expire; Phoenix lets a user tick "no expiry"; DefectDojo Simple Risk Acceptance has no expiry; GitHub dismissals and Semgrep memories are permanent by construction. ADR-0016's "no terminal suppression" is therefore not a refinement of market practice; **it is a direct contradiction of it**, which is a stronger position to sell from and a harder one to be copied into.
4. **Four vendors cannot be assessed from public sources.** That is a real limit on the ledger's coverage and it is stated rather than papered over.

---

## 4. The naming problem — the round's most consequential finding

Positioning §6.2 proposed claiming the term **"decision debt"** and flagged it as needing verification. Verified this round, and the ground is **more crowded than assumed**:

| Term | Status | Owner |
|---|---|---|
| **"security debt"** | Widely established. Veracode's 2026 State of Software Security reports 82% of organizations carrying it, 60% carrying critical debt. Board-level metric language | The industry |
| **"vulnerability debt"** | **Claimed by Nucleus**, in a blog defining it as *"the accumulation of unfixed vulnerabilities that organizations choose not to remediate today"* | Nucleus |
| **"decision debt"** | No vendor product claim found. But it sits inside a discourse where "debt" already means something adjacent | Unclaimed, **adjacent territory occupied** |

**The referent is different, and the difference is the entire product:**

> Nucleus's vulnerability debt is the **open** pile — findings you have not fixed.
> SDIP's decision debt is the **closed** pile — findings you decided about, whose justification has since expired.

That distinction is sharp, defensible and genuinely unoccupied. But a buyer who hears "debt" will pattern-match to the open backlog, because that is what the word already means in this market, and the pitch will be heard as a re-run of a message they have already been sold.

**Recommendation:** keep the term, and never ship it undefined. Always the contrast, in one sentence:

> *"Not the findings you haven't fixed — the findings you decided you didn't need to."*

Do not invest in the term as a category or a trademark. It is a teaching device, not an asset, and it is not worth the analyst-relations budget that positioning §5.1 already ruled out.

---

## 5. Corrections to `competitive-positioning.md`

Logged rather than silently edited, per §0.

| # | Where | Said (2026-08-14) | Correction (2026-08-16) | Impact |
|---|---|---|---|---|
| **C-1** | §0 verdict | *"Every serious platform expires exceptions on a calendar and re-opens them."* | **False as an absolute.** Brinqa risk acceptances never expire; Phoenix offers a "no expiry" option. Correct statement: *"Calendar expiry is widely available, and permanent suppression is widely permitted."* | **Strengthens O1/O2.** But the original sentence would have been corrected in the room — exactly the failure mode §0 of the positioning document was written to avoid. Fix the pitch deck |
| **C-2** | §6.2, §10 item 5 | *"'decision debt' — unclaimed in the searches performed for this document"* | Unclaimed as a product term; **adjacent territory occupied** by "vulnerability debt" (Nucleus) and "security debt" (industry-wide) | Keep the term, always define by contrast (§4). Do not build a category on it |
| **C-3** | §7 A7 | Deadline 2026-09-15 | **Partially discharged 2026-08-16.** Brinqa, Phoenix, Cycode checked; Seemplicity, Apiiro, OX are **[N]** and cannot be closed from public sources | A7 stays open, with its scope narrowed to three vendors and a changed method (product access, not documentation) |
| **C-4** | §4.3, §7 A1 | Deadline 2026-08-21 | Re-checked; **documentation cannot resolve it.** Only Q1 in a live demo will | **A1 is now the only item blocking the pitch.** It is a conversation, not research |

---

## 6. Watchlist

Ordered by how much damage the feature would do, not by vendor size. A hit here triggers an immediate round.

| Vendor | The feature that would hurt | Damage | Where it appears first |
|---|---|---|---|
| **Nucleus** | Threat-triggered exception revocation, documented | **D1 contested.** Funded incumbent, 200+ connectors | Product page, release notes |
| **Semgrep** | **Memory expiry or invalidation on new evidence** | O2 contested at the source, by the vendor generating the most FP dismissals | Engineering blog, release notes |
| **GitHub** | Dismissed-alert re-opening on advisory change | O2 contested at the largest possible distribution | Changelog |
| **DefectDojo** | Expiry on `false_p`, or evidence triggers in Sensei | O2 contested **at $0** — the worst case commercially | GitHub commits, Pro changelog |
| **Snyk** | A second evidence trigger, in the adversarial direction | O1 narrows | Docs diff |
| **Brinqa** | Expiry on risk acceptances **plus** evidence triggers | Two steps behind, but they own the buyer | Docs release notes |
| **Cycode / ArmorCode** | CRA evidence pack, or exception auto-revocation | D2 contested | Press releases |
| **Vanta / AuditBoard** | Security-finding decision records with epistemic state | D2 contested from the GRC side | Product launches |
| **Anyone** | A published open triage benchmark with a harness | **D3's window closes.** First-mover asset with a decaying value | Blog, GitHub |

---

## 7. Open items

| # | Item | Method | Owner | Due | If unresolved |
|---|---|---|---|---|---|
| **T-1** | **Nucleus Q1–Q4 in a live demo or trial** | Conversation. **Not research — documentation has been exhausted** | founder | **2026-08-22** | The pitch ships on an unverified competitive claim. Do not let this happen |
| T-2 | Phoenix Security KB — manual retrieval (403 to automated fetch) | Browser | founder | 2026-09-16 | Row stays **[U]** |
| T-3 | ArmorCode exceptions blog — manual retrieval (403, second round) | Browser | founder | 2026-09-16 | Row stays **[N]** |
| T-4 | Seemplicity, Apiiro, OX — exception lifecycle | Demo, trial, or a customer who uses them | founder | 2026-10-15 | Ledger coverage stays at 8 of 11; **state the gap in any competitive claim** |
| T-5 | Orca dismissal-rollback against Orca's own documentation | Docs | founder | 2026-09-16 | Row stays **[U]** |
| T-6 | Cycode agentic-workflow suppression: is there any review or expiry on an AI suppression? | Demo | founder | 2026-10-15 | Supports §3.1 point 2 either way — **a "no" makes the argument stronger** |
| T-7 | Monitor for a competing published triage benchmark | Standing | founder | Continuous | D3 window |

**T-1 is the only item on the critical path.** Everything else refines a ledger; T-1 determines whether D1 is open ground or contested, and it is a one-hour conversation that has now been deferred through two rounds of research that could never have answered it.

---

## 8. How to run a round

30–60 minutes, monthly, plus an immediate round on any watchlist hit or competitor funding/acquisition announcement.

1. Re-fetch the documentation URLs in §9 and diff against the previous round.
2. Ask the §1 question set of any vendor newly accessible via demo or trial.
3. Append a dated block to §2. **Record the negatives** — "still calendar-only, checked <date>" is the finding that supports the pitch.
4. Update §3, marking any changed row with its new date and leaving the superseded finding visible.
5. Log any contradiction with `competitive-positioning.md` in §5. **Never silently edit the sibling document.**
6. Re-rank §6 if the direction of the market moved.
7. Update the assumption register in `competitive-positioning.md` §7 with dates only.

**Two rules.** Round 2 was mostly research when the highest-value item (T-1) has never been answerable by research: **if a question can only be answered by product access, book the product access instead of searching again.** And never let a [U] or an [N] be spoken as a [V] in a sales call — "we haven't been able to verify that" is a credible sentence, and a competitor correction in the room is not survivable twice.

---

## Sources

Checked 2026-08-16 for round 2:

- [Brinqa — Remediation Requests (risk acceptances do not expire; exception requests expire on the extended due date)](https://docs.brinqa.com/docs/remediation-requests/) **[V]**
- [Nucleus Security — Remediation workflows ("exceptions remain active and fully tracked as new scan data is ingested"; "set time limits and document approvals")](https://nucleussec.com/platform/remediation-workflows/) **[V]** on the absence of a documented mechanism
- [Nucleus Security — It's Time to Understand and Manage Vulnerability Debt (defines vulnerability debt as the *unfixed* backlog)](https://nucleussec.com/blog/its-time-to-understand-and-manage-vulnerability-debt/) **[V]**
- [Semgrep — Customize Assistant (memories: no expiry, manual removal only)](https://docs.semgrep.dev/semgrep-assistant/customize) **[V]**
- [Semgrep — March 2026 release notes](https://semgrep.dev/docs/release-notes/march-2026) **[V]**
- [Phoenix Security — Context Engine and Exception Engine KB](https://kb.phoenix.security/?ht_kb=context-engine-and-exception-engine) **[U]** — 403 to automated fetch; snippet-level only
- [Phoenix Security — October 2023 feature release (exception expiration options)](https://phoenix.security/phoenix-security-features-oct-2023/) **[U]**
- [Cycode — Agentic Workflows ("escalate exploitable findings and suppress those that are not")](https://cycode.com/agentic-workflows/) **[U]** — product page
- [Seemplicity — GRC & Compliance](https://seemplicity.ai/grc-compliance/) **[N]**
- [Seemplicity — developer documentation](https://developers.seemplicity.io/query/remediation_queues) **[N]**
- [Apiiro — Application Security Risk Assessment checklist ("document the business justification, risk owner, and review date")](https://apiiro.com/blog/application-security-risk-assessment-checklist/) **[N]**
- [ArmorCode — Vulnerability Exceptions Management](https://www.armorcode.com/blog/vulnerability-exceptions-management-why-the-goal-isnt-zero-exceptions) **[N]** — HTTP 403, two rounds running
- [Security debt as a board-level risk metric (Veracode SoSS 2026 figures cited)](https://nhimg.org/articles/security-debt-is-becoming-a-board-level-risk-metric/) **[U]** — secondary

Round 1 (2026-08-14) sources are listed in `competitive-positioning.md` § Sources and are not repeated here.
