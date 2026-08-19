# SDIP — Security Decision Intelligence Platform

Working name for a platform that turns large volumes of application-security
findings into a small number of defensible security decisions — not a
scanner, and not another dashboard on top of scanners. Full mission and
constraints: [`CLAUDE.md`](CLAUDE.md).

**Status: pre-MVP, in Phase 0 validation.** Nothing here claims to be a
finished product. What follows is what is actually true today, not the
aspirational architecture.

---

## Run the demo (30 seconds, nothing to install)

```bash
cd phase0
python v1_backtest.py --demo
```

Reads a synthetic export of "closed" security findings, checks each one
against the real CISA KEV catalog (one HTTPS call, cached locally after the
first run), and writes `decision-debt-report.html` — a self-contained report
showing which closed findings later turned out to be known-exploited.

Point it at a real export instead of `--demo` and it runs the same analysis
on real data — still nothing leaves the machine it runs on.

```bash
python v1_backtest.py path/to/your-export.csv
```

## The one-sentence thesis

Security teams don't lack scanners; they lack a reliable way to know which
past "close this, it's fine" decisions quietly stopped being fine. A finding
closed as a false positive or accepted risk a year ago can be sitting on a
CVE that entered CISA's Known Exploited Vulnerabilities catalog last week —
and nothing today tells anyone that happened.

`v1_backtest.py` answers exactly that question, for free, from data an
organization already has.

## What is actually validated, not just designed

This repository was built under a rule: a specification that has never been
executed is a draft. Two design documents were run against real inputs
specifically to find out where they were wrong, and both were:

- **The deterministic risk-scoring tree** (`docs/decisions/risk-model.md`)
  left 19% of its own input space undefined and contained a rule that could
  never fire. Both were bugs in a document that had only ever been read, not
  run. Fixed — see [`docs/evaluation/exp-002-risk-model-executed.md`](docs/evaluation/exp-002-risk-model-executed.md).
- **Using EPSS scores to detect "risk went up since we closed this"** was
  tested against real snapshot data and rejected: a single EPSS model
  version change moved 71,885 CVEs across a common threshold in ten days,
  against 306 for ten days of the world actually changing — 235× inflation.
  See [`docs/evaluation/exp-001-epss-model-boundary.md`](docs/evaluation/exp-001-epss-model-boundary.md).
  This is why the backtest above uses KEV, not EPSS.

## Repository map

| Path | What's in it |
|---|---|
| [`phase0/`](phase0/) | The only code that runs today. Single-file, standard-library-only instruments — no install step, on purpose. |
| [`docs/adr/`](docs/adr/) | 17 architecture decisions, with alternatives and consequences, not just conclusions. |
| [`docs/product/`](docs/product/) | Product critique, competitive teardown, MVP backlog (MoSCoW), design-partner recruitment kit. |
| [`docs/evaluation/`](docs/evaluation/) | Pre-registered Phase 0 validation protocols, and the two experiments above. |
| [`docs/architecture/`](docs/architecture/) | Architecture critique, diagrams, repository structure for the eventual platform. |
| [`docs/data/`](docs/data/) | Domain model and database schema for the full platform. |
| [`docs/api/`](docs/api/) | OpenAPI contract for the full platform. |
| [`docs/threat-model/`](docs/threat-model/) | Threat model and OWASP ASVS 5.0.0 verification mapping. |

## What is deliberately not built yet

No LLM, no database, no scanner integration, no correlation engine. The
backlog ([`docs/product/mvp-backlog.md`](docs/product/mvp-backlog.md)) splits
the plan into **Ring 0** (~14 engineer-weeks: import decisions, enrich, diff,
report — what `v1_backtest.py` already does the core of) and **Ring 1**
(~62 engineer-weeks: the full platform). Ring 1 is not worth building until
Ring 0's thesis is confirmed against real organizational data — building it
first is explicitly listed as the failure mode this project is trying to
avoid.

## Where this stands right now

Phase 0 validation (`docs/evaluation/phase-0-protocols.md`) is in progress:
pre-registered thresholds, five external design-partner validations planned.
None of those require this repository to grow before they can happen —
recruiting partners and running the backtest on their real data is the
actual next step, not more code.
