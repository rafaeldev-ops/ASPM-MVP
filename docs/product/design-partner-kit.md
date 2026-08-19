# Design Partner Kit — V0

**Deliverable:** makes V0 in `phase-0-protocols.md` §0.1 executable
**Date:** 2026-08-16
**Goal:** 5 design partners who will (a) run the decision-debt backtest on their own closed findings and (b) sit for a 60-minute review
**Blocks:** V1, V2, V6 — and therefore R0-1 and everything after it
**Lead time:** 2–3 weeks calendar. **Start before anything else.**

---

## 0. The decision that makes this ask answerable

There are two ways to run V1:

| | Mode A — **they run it** | Mode B — they send us the export |
|---|---|---|
| Where the data goes | **Nowhere. Stays on their machine** | To us, under an NDA and a DPA |
| What we see | The aggregate report, and whatever findings they choose to discuss | Everything |
| Their approval path | An engineer runs a script | Legal, security review, procurement |
| Realistic time to first result | **Days** | Weeks, often never |

**Mode A, always.** Not as a concession — as the default, stated in the first sentence of the ask.

Three reasons, in order of importance:

1. **It is the only version that closes at pre-product stage.** An AppSec director cannot send a year of closed security findings to a company with no customers without a process that takes longer than the experiment.
2. **It dogfoods the product's own architecture.** Ring 0 is specified to run locally and hold no inbound credential (`mvp-backlog.md` §2.1). If the *validation* of that architecture requires violating it, the claim was never real.
3. **It converts the ask from "trust us with your data" to "check our claim against your data."** Those are different conversations, and only one of them is winnable by a stranger.

**The constraint this imposes:** the backtest must be a **single file, standard library only, no install step**. Anything requiring a virtualenv, a Docker daemon or a package index is a script that does not get run. This is a hard requirement on the V1 tooling, not a preference.

> **Built: [`phase0/v1_backtest.py`](../../phase0/v1_backtest.py).** One file, standard library only, one network call (the CISA KEV catalog), one local HTML file out. `python v1_backtest.py --demo` produces a full report on synthetic data — **run that before the first outreach**, so the thing being described in §2.1 can be shown rather than promised.
>
> It auto-detects the id, close-date and reason columns from whatever the tool emits — verified against a flat CSV and against GitHub's nested dismissed-alerts JSON — and prints which columns it chose, so a wrong guess is visible instead of silent.
>
> **It reports two numbers, not one.** The second was not in the plan and is the one likely to land hardest in a session:
>
> | | |
> |---|---|
> | **Decision debt** | entered CISA KEV **after** the finding was closed — the thesis |
> | **Closed despite** | already in KEV **on the day** it was closed |
>
> The second needs no re-litigation engine at all. It is a check nobody ran, it is free, and it is computed from the same feed in the same pass.

---

## 1. Who to ask

### 1.1 Qualification, in order

| # | Signal | Why it predicts |
|---|---|---|
| **Q1** | **"Do you have an open or recently denied AppSec headcount requisition?"** | A team that saves 0.5 FTE without a req absorbs the slack and releases no cash. The ROI story evaporates at renewal. Predicts close rate better than company size, industry or scanner stack (`competitive-positioning.md` §6.5) |
| **Q2** | Do they have a **closed pile** — i.e. do they actually dismiss and accept findings, in a system, with reasons? | If everything is either fixed or ignored-in-place, there is nothing to backtest |
| **Q3** | Is there **a named person** who owns triage decisions? | The 60-minute session needs someone who can say "I closed that" |
| **Q4** | 12+ months of history in one system | Below that the window is too short for a trigger to have fired |
| **Q5** | Do they use DefectDojo, Jira, GitHub code scanning, or a scanner with an exportable suppression list? | Export feasibility |

**Disqualifiers:** no closed pile; history spread across three systems with no common id; the only available contact is a CISO who has never triaged a finding.

### 1.2 Where they come from

Ranked by conversion, not by volume: warm introductions from the founder's own AppSec network → practitioners met at OWASP chapters and security conferences → active participants in AppSec communities who post about triage volume → DefectDojo's user community, since they are pre-qualified on Q2 and Q5.

**Cold outbound is not in scope for V0.** Five partners at pre-product stage come from a network or they do not come.

---

## 2. The ask

### 2.1 Outreach — first contact

Short, one question, no deck. The measure of this message is whether it earns a reply, not whether it explains the product.

> **Subject: a question about the findings you closed last year**
>
> I'm building something in AppSec triage and I'm trying to find out whether one specific idea is real before I build it.
>
> The idea: of the findings your team closed last year — dismissed as false positives, accepted, won't-fix — some number of them acquired new evidence afterwards that would have changed the decision. A CVE that entered CISA KEV. An advisory whose affected range was widened to include the version you're running. Nobody re-opens those, anywhere, as far as I can tell.
>
> I have a script that measures this. **It runs on your machine, needs no credentials, and sends nothing anywhere** — you run it against an export of your own closed findings and you keep the output. I'd like 45 minutes afterwards to walk through what it found and hear whether any of it would have mattered to you.
>
> If the answer is "none of this would have mattered," that's the most useful thing you could tell me, and I'd stop.
>
> Worth a conversation?

**What is doing the work here:** the local-execution promise in the second paragraph, and the last line. An expert who is being sold to expects the seller to want a yes; offering to be killed by the answer is the cheapest available signal of not selling.

**Do not include:** a product name, a category, a deck, a demo request, the words *defensible*, *context graph* or *decision intelligence*, or any efficiency claim. There is no product yet and pretending otherwise is discovered immediately.

### 2.2 The follow-up — what we actually need

Sent once they say yes.

> Two things:
>
> **1. An export of closed findings, 12–24 months.** I need **two things**:
>
> - a **CVE identifier**
> - a **close date**
>
> That's the whole requirement. A third column — **the close reason** — makes the report better but nothing depends on it.
>
> The CVE doesn't need its own column; the script finds CVE ids anywhere in the row. Everything else your export contains is ignored. So the easiest thing is to export whatever your tool gives you and delete nothing.
>
> If it's easier to strip it down first: a two-column CSV of `CVE, close date` is enough, and at that point there's very little in the file to be nervous about.
>
> **2. 60 minutes with whoever makes the close decisions.** Not a demo — I'll show you findings from your own export and ask which ones you'd have wanted to know about.
>
> **What I see:** only what you choose to show me in the session. The script writes a single HTML file to your disk. I don't need it, and I'd rather not have it.

### 2.3 Export instructions, by system

Provide these unprompted. An ask that requires the partner to figure out the export is an ask that stalls.

| System | Path |
|---|---|
| **DefectDojo** | Findings → filter `Status: Risk Accepted, False Positive, Out of Scope` and date range → Export CSV. Include `Risk Acceptance` fields if present |
| **Jira** | JQL on the security project: `status = Done AND resolution in (...) AND resolved >= -365d` → Export CSV (all fields). Ask which resolutions mean "dismissed" |
| **GitHub code scanning** | REST: `GET /repos/{o}/{r}/code-scanning/alerts?state=dismissed` — carries `dismissed_at`, `dismissed_reason`, `dismissed_by`. Loop repos. **This is the purest false-positive pile available** |
| **Snyk** | Ignores list per project, via API or UI export |
| **Semgrep** | Triage state export, and the **Memories** list if they use Assistant |
| **Anything else** | Ask for whatever it emits. Adapting a parser is an hour; a partner giving up on an export is the whole partner |

**Ask for the false-positive pile explicitly.** It is the largest and the least instrumented, it is assumption **A4** in `competitive-positioning.md` §7, and the default export usually contains only formal risk acceptances.

### 2.4 What is deliberately NOT requested

Every field in the ask is friction, and friction at pre-product stage is the difference between a reply and silence. So the ask was cut to what the tool actually reads:

| Not requested | Why |
|---|---|
| Package / file location | Never read by the backtest |
| Who closed it | Never read. Also the most personal field in the export, for zero return |
| Rule ids, SAST and secret findings | KEV is indexed by CVE. A rule-only finding **cannot** be tested by V1 at all — asking for it implies a capability this experiment does not have |
| Severity, CVSS, scanner name, repo | Not read. Enriched from public sources anyway |
| Anything still open | The whole subject is the **closed** pile |

**Do not ask for data "for later."** If a second experiment needs another field, ask again then — by which point there is a relationship and a report they have already seen. Asking for everything up front, on the theory that a second ask is awkward, is how the first ask fails.

---

## 3. What we promise, in writing

Short enough to paste into an email. Every line is backed by `retention.md`.

| # | Commitment |
|---|---|
| P1 | **The script runs on your infrastructure.** It reads your export, fetches two public feeds (CISA KEV, EPSS), writes one local file. No telemetry, no upload, no callback |
| P2 | **We do not need a copy of your export.** If you choose to share output, you choose what |
| P3 | **No credentials.** Not to your repos, your scanners, your ticketing, or anything else |
| P4 | Anything you do show us is confidential, unattributed, and not reused with other partners |
| P5 | You get the full report and the script. Keep both, re-run them whenever, with or without us |
| P6 | **If the result is "none of this matters," we will say so** — to you and in our own write-up |
| P7 | No cost, no commitment, no purchase conversation in this session |

P6 is not decoration. `phase-0-protocols.md` §0.2 pre-registers the pass mark before any data is seen, and the report carries the commit hash of that pre-registration. Showing a practitioner that the threshold was fixed in advance is a credibility move no vendor benchmark in this market makes.

---

## 4. The 60-minute session

| Time | What |
|---|---|
| 0–5 | What this is, what it is not. **No product pitch.** State that there is nothing to buy |
| 5–15 | Their current triage process, in their words. Volume, who closes, what "closed" means. *This is V6's baseline capture — same conversation, no extra meeting* |
| 15–45 | **The walk-through.** 20 findings from their export, stratified. The three questions below, verbatim answers recorded |
| 45–55 | *"What would have to be true for this to be worth paying for?"* — open, unled |
| 55–60 | What happens next. Ask for one introduction |

The three questions, in this order and no other (`phase-0-protocols.md` §1.5):

1. *"Here are 20 findings you closed. Since then, this changed about each. Which would you have wanted to know about?"* → **K1**
2. *"Is there one here that concerns you?"* → **K2**
3. *"If this had arrived the week it happened — what would you have done, and would you still feel that way if it arrived twenty times a month?"* → the alert-fatigue failure mode

**The interviewer states what changed and stops talking.** "Would you have wanted to know about a KEV listing?" answers itself. The finding-by-finding walk does not, and it is the only part that produces a real signal.

**Record verbatim.** Where possible, someone other than the founder runs the session — the person who needs the yes is the wrong person to ask the question.

---

## 5. Objections

| Objection | Answer |
|---|---|
| *"I can't share security findings with a vendor."* | "You don't. The script runs on your machine and I never see the file. I only see what you point at in the call." |
| *"What's the catch — what do you want?"* | "45 minutes and an honest answer. If the answer is no, that's worth more to me than a polite yes." |
| *"We already have <ASPM vendor>."* | "Good — keep it. Ask them what happens when a CVE you dismissed 60 days ago enters KEV and no new scan has run. I'd genuinely like to know the answer." |
| *"Our closed findings are all correctly closed."* | "That's the hypothesis I'm testing, and if you're right this takes an hour and I stop bothering you. If even one isn't, you'd want to know which." |
| *"How long does this take us?"* | "One export, one script run, 60 minutes. If it takes longer than that, the ask is badly designed and that's on me." |
| *"Is this GDPR-relevant?"* | "The export stays with you, so there is no transfer. If you later share output, it contains findings, not personal data — and we'd redact any names first." |
| *"What if you find something bad?"* | "You find it. It's your machine and your report. I'd only learn about it if you told me." |

---

## 6. Tracking

Five partners, and the funnel leaks between "interesting" and "here is the file" — recruit against 5 confirmed, not 5 contacted.

| Field | Values |
|---|---|
| Stage | contacted → replied → qualified → export produced → **script run** → session booked → **session done** |
| Q1 headcount signal | yes / no / unknown |
| Q2 closed pile exists | yes / no |
| Source system | DefectDojo / Jira / GitHub / other |
| FP pile size vs risk-acceptance pile | **counts — this is A4** |
| K1 answer | wanted / did not want |
| K2 finding named | yes + verbatim / no |
| Q3 alert-fatigue response | verbatim |

**Record the negatives with the same discipline as the positives.** A partner who runs the backtest and says "none of these mattered" is the single most valuable data point available, and the one most likely to be quietly dropped from a founder's tracker.

---

## 7. What V0 is really measuring

The stated purpose is to obtain five exports. The unstated one matters more:

> **Whether an AppSec director, hearing this idea cold, finds it interesting enough to spend an hour on.**

If five qualified practitioners cannot be recruited in three weeks for a free, local, no-credential, no-commitment experiment on a problem they supposedly have — that is a result about the problem, and it arrives before any code is written. Note it, and do not explain it away as a recruiting problem.
