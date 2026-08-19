# ADR-0016 — No terminal suppression: decisions expire and are re-litigated on evidence

**Status:** Accepted
**Date:** 2026-08-14
**Source:** `competitive-positioning.md` §5 (D1, D2); `critique-product.md` §9; `critique-ai-rag.md` §8.2; `critique-security.md` §5.6
**Depends on:** ADR-0001, ADR-0012, ADR-0013

---

## Context

This is the ADR that encodes the product thesis into the domain model. It is architecturally significant precisely because it is not primarily an architecture decision.

CLAUDE.md §7 offers `false_positive_candidate` and `accepted_risk` as decision values with no expiry, no conditions and no owner. §25 says "do not merge findings irreversibly" and says nothing about suppressing them irreversibly.

Verification against vendor documentation (2026-08-14) established the market position:

| Platform | Expiry | Auto-reopen triggers |
|---|---|---|
| DefectDojo (free) | Full Risk Acceptance only | **Calendar only.** `false_p` never expires |
| Snyk | Ignores | Calendar, **plus one evidence trigger**: a fix becoming available |
| Vulcan Cyber / Tenable | Exception requests | **Calendar only** |
| Rapid7 InsightVM | Vulnerability exceptions | **Calendar only** |
| Nucleus | Structured exceptions | Re-evaluation on rescan; a stronger marketing claim is unverified |
| GitHub / Semgrep / Orca | Dismissals, memories | **None** — permanent until a human reverses it |

**Every vendor instruments the clock. None instruments the world.** And no vendor expires a *false-positive dismissal* at all — which is the largest and fastest-growing part of the closed pile, precisely because AI triage is now generating it automatically.

## Decision

### 1. Suppression is a state with conditions, never a terminal outcome

Replace `false_positive_candidate` and `accepted_risk` as terminal values with:

```
deprioritized_until(conditions[])
```

Every suppression record carries: the evidence set that justified it (with snapshot ids and content hashes), the **invalidation conditions**, an expiry, an approver identity, a reason code, and a **scope**.

`false_positive_candidate` is a *hypothesis* that routes to review, never a terminal state. `accepted_risk` is reachable **only** through an authenticated analyst action with an attributable identity and an expiry — never emitted by a model (ADR-0007).

### 2. The invalidation conditions

Evaluated continuously, deterministically, in SQL and cron — **not by inference**:

| Condition | Source |
|---|---|
| CVE added to CISA KEV | KEV feed |
| EPSS crosses a policy threshold (model-version-pinned) | EPSS |
| Public exploit or PoC published | advisory / exploit sources |
| **Advisory affected-range narrowed** so our version is now covered | ADR-0013's range-narrowing detector |
| Reachability verdict changes to reachable | scanner evidence |
| Asset becomes internet-exposed | deployment/exposure context |
| Service criticality increases | asset registry |
| Ownership changes | ownership resolution |
| Calendar expiry | the floor, not the mechanism |

### 3. Scope is part of the model, and it is the hard part

A suppression applies to one of: this finding / this rule in this repo / this CVE org-wide / this package everywhere. **An org-wide CVE suppression must automatically apply to findings that do not exist yet** — which means scope is a predicate evaluated at decision time, not a list of finding ids. This is genuinely hard modelling work and it is entirely absent from CLAUDE.md.

### 4. Re-opening is a first-class event

A re-opened finding carries: what changed, when, the original decision, the original approver, the original evidence, and **what was not knowable then** (`evidence_availability`, ADR-0012). The notification names an owner. This is the deliverable the buyer is paying for — not a status flip.

### 5. The non-suppressible path

KEV listing and confirmed active exploitation escalate **outside the risk score**, unsuppressible by policy, analyst or model (ADR-0007). This is also the EU CRA Art. 14 control: reporting obligations begin **2026-09-11**, with a 24-hour early warning for actively exploited vulnerabilities. **If a deprioritization delays a customer's awareness of active exploitation, SDIP has interposed itself in a statutory clock.** Contractually: SDIP does not determine regulatory reportability.

### 6. Guardrails against becoming the noise

- **Re-litigation precision** — of findings re-opened, the % an analyst agrees should have been re-opened. Target ≥60%; **below 40% the product is a new alert-fatigue source**.
- **Re-opens per analyst per week, capped.** The failure mode is becoming the thing it replaced.
- Retroactive outcome labels (ADR-0010) are the automatic label source that makes both measurable.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Terminal `accepted_risk` (CLAUDE.md §7) | Permanent silent debt; the first thing an auditor asks about; and it is a liability surface with no owner |
| Calendar expiry only | Commodity — DefectDojo does it free. A date does not know a CVE entered KEV |
| Re-evaluate on rescan only | Misses everything that changes when no scan runs, which is most of what matters |
| LLM decides when to re-open | Non-deterministic, expensive, injectable, and unauditable — the exact opposite of the pitch |
| Notify on every evidence change | Becomes noise within a week; hence policy thresholds and the precision guardrail |

## Consequences

- **This is why ADR-0001 is irreversible.** Re-litigation requires the evidence state at decision time. A mutable model cannot answer "what did we know then," so the product claim is unbuildable on it.
- Requires ADR-0013's snapshots and version pins, or the deltas are noise.
- The delta-detector is cheap (SQL + cron), which is what keeps it inside ADR-0008's cost ceiling — the model is invoked only when a decision actually wakes up.
- Scope predicates make suppression evaluation a query, not a lookup — a performance consideration in the schema design (deliverable F).
- Sales consequence: the product can be demonstrated against a prospect's *existing* closed pile without replacing anything.

## Reversal strategy

The conditions and thresholds are configuration. The **structural** part — suppression as a conditional state rather than a terminal one — is not reversible after data exists, because terminal records do not carry the conditions that would have made them conditional.

## Verification

- **The falsification test comes first, before any schema:** take three prospects' historical closed-finding exports, compute how many would have re-opened in the last 12 months, and ask an AppSec director whether they would have wanted to know. Pre-registered threshold: ≥3 of 5 partners say yes and ≥1 names a specific alarming finding. **If it fails, this ADR and the company thesis are both dead** — and it costs one week and no product.
- A test asserting no code path can write a suppression without conditions and an approver.
- A test asserting an org-wide scope applies to a finding created after the suppression.
- Re-litigation precision reported per trigger type, so a noisy trigger can be disabled individually.
