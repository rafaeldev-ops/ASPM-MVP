# ADR-0002 — Finding lifecycle is not the decision

**Status:** Accepted
**Date:** 2026-08-14
**Source:** `critique-architecture.md` §11.1
**Depends on:** ADR-0001

---

## Context

CLAUDE.md §7 defines a `decision` enum (`prioritize` / `deprioritize` / `false_positive_candidate` / `needs_review` / `accepted_risk`). There is **no finding state** anywhere in the brief.

These are different axes and conflating them is a category error: `prioritize` is an opinion, `open` is a fact. A finding can be `open` and `deprioritized`, or `remediated` and never decided at all.

## Problem

The dangerous case is a finding absent from the latest scan. It may be:

- fixed;
- the file moved or was renamed;
- the scanner version changed and the rule no longer fires;
- the scan configuration changed (different paths, different ruleset);
- **the scan failed and imported partially.**

Treating absence as "fixed" mass-auto-resolves real vulnerabilities, silently. This is the single most damaging bug this product class ships, and it realizes CLAUDE.md §33's own risk #6 at scale.

## Decision

**A separate lifecycle state machine on `finding_state`, orthogonal to decisions.**

```
open ──► reopened ──► remediated
  │                       ▲
  ├──► not_present ───────┘  (only via evidence of a fix, or an analyst)
  ├──► suppressed  (see ADR-0016 — always with expiry conditions)
  ├──► expired
  └──► superseded
```

Rules:

1. Transition to `not_present` requires **N consecutive successful, comparably-scoped scan runs** that do not contain the identity. Comparability is decided by `scan_run.scope_hash` **and** `tool_version` — not by scan presence alone. Default N = 3; configurable per tenant, never 1.
2. `not_present` **is not** `remediated`. Only evidence of a fix (a fixed version present, a commit closing the location) or an authenticated analyst produces `remediated`.
3. A partial or failed `scan_run` contributes **nothing** to absence counting.
4. Re-observation of a `not_present` or `remediated` identity produces `reopened`, never a new identity.
5. Lifecycle transitions are events on the append-only log, not in-place status edits.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Use the decision enum as the state | Category error; makes "we decided to deprioritize" indistinguishable from "the scanner stopped reporting it" |
| Close on first absence | The industry default and the source of silent mass auto-resolution. Fails on every partial import |
| Close on absence with a fixed time window (e.g. 14 days) | Time is the wrong variable. Three failed scans over 14 days is not evidence of a fix |
| Never auto-close | Backlog grows without bound and analysts lose trust in the state column. N-scan confirmation is the compromise |

## Consequences

- Requires ADR-0001's observation history; not expressible over mutable rows.
- Requires `scan_run.scope_hash` — a canonical hash of paths scanned, ruleset, and configuration. Defining it precisely is real work and is a precondition, not a detail.
- Analysts will ask why a fixed finding still shows as `not_present` for three scans. That is the correct trade and needs UI language, not a shorter N.
- Metrics in CLAUDE.md §31 must be computed against lifecycle state, not decision state, or "remediation acceleration" measures the wrong thing.

## Reversal strategy

Reversible at moderate cost. The state machine is a projection; transition rules can be re-run over the observation log. Changing N or the comparability definition triggers a recompute job (ADR-0006's reprocessing machinery), not a migration.

## Verification

- A test that imports a partial scan and asserts zero transitions to `not_present`.
- A test that changes `tool_version` between scans and asserts absence is not counted.
- A golden fixture of a rename (`git mv`) asserting identity survives and no lifecycle transition fires.
