# ADR-0013 — External knowledge: pin versions, snapshot everything, tier by authority

**Status:** Accepted
**Date:** 2026-08-14
**Source:** `critique-architecture.md` §1, §11.3, §11.7; `critique-security.md` §4

---

## Context

CLAUDE.md §8 requires freshness metadata and a "reliability score," and never defines either. It also names EPSS, ASVS and SARIF without pinning versions — while §18 explicitly demands version pinning.

Meanwhile the environment moved under the design:

| Input | State | Consequence |
|---|---|---|
| **EPSS** | **v5** (announced 2026-05-13, publishing since 2026-06-15); v4 shipped 2025-03-17 | Scores are **not comparable across model versions**. Any historical risk score, calibration curve or trend chart mixing v4 and v5 is wrong |
| **ASVS** | **5.0.0** (2025-05-30); chapter numbering changed from 4.0.3 | A control map written against 4.0.3 numbering will not survive review |
| **SARIF** | **2.1.0 + Errata 01**; 2.2 is a draft | Build against 2.1.0; do not assume 2.2 fingerprint guarantees |
| **NVD** | Risk-based enrichment since **2026-04-15** — only KEV / federal / EO-critical CVEs get enrichment | **~80–85% of new CVEs have no authoritative CVSS and no CPE mapping.** Version-range matching loses its authoritative source |
| **CISA KEV, OSV, GHSA** | Mutate records in place; GHSA has a *reviewed* and an *unreviewed* tier | Freshness metadata without an invalidation sweep is decoration |

## Problem

Three distinct failures follow:

1. **Silent score incomparability.** Organizational statistics (FP rate by rule, recurrence, remediation time) are the claimed moat. Computed across a rule-version or model-version boundary they average two different detectors and report a number that describes nothing — and the failure is invisible because the number still looks reasonable.
2. **Suppression via range narrowing.** Edit an advisory so the affected range excludes the version the target runs. The system concludes "not affected," suppresses, and records the suppression in decision memory. Same false-negative primitive as prompt injection, delivered through a channel that *looks* authoritative.
3. **Stale evidence presented as current.** A decision made at EPSS 0.02, still displayed when EPSS is 0.7.

## Decision

### 1. Pin and record every external version

`(tool_version, rule_version, ruleset_hash)` on every observation; `epss_model_version` on every EPSS evidence record; snapshot dates on NVD/KEV; `severity_mapping_version` (ADR-0004). Pin **ASVS 5.0.0**, **SARIF 2.1.0 + Errata 01**, **OWASP Top 10 for LLM Applications 2026 v1.0** in the verification docs.

**A model-version change is a global evidence-invalidation event**, not a background update.

> **Amendment 2026-08-16, from [`exp-001`](../evaluation/exp-001-epss-model-boundary.md).** This clause was measured at the v4 → v5 boundary and holds: **0.0% of 339,488 CVE scores were unchanged**, and threshold crossings were **235× the same-model rate** over an identical 10-day gap. Two refinements follow:
>
> - **Pin the version string the feed emits** — `v2026.06.15`, `v2025.03.14`, `v2023.03.01` — not the marketing version. `epss_model_version` matching on `"v5"` matches nothing. This fixes the field's value domain.
> - **A bump emits no `ReopenEvent`.** It produces a one-time re-baseline as a reviewed `reprocessing_job`. Faithfully reporting every change would wake ~27% of a tenant's below-threshold suppressions on the night of an upstream release — the alert-fatigue failure this product exists to prevent, delivered by a routine third-party release. See `risk-model.md` §7.4.

### 2. Statistics are segmented, never pooled across versions

Every organizational metric is reported per `(rule_id, scanner_major_version)` **or it is not reported.** A rule-alias map handles renames; a drift detector flags "rule X's finding population changed >30% across a version boundary" and segments rather than pools.

### 3. Source authority as a record, not a float

```
source_record {
  authority_tier: A | B | C | D | E
  mutability:     immutable_signed | append_only | mutable
  attestation:    signature_verified | checksum_verified | tls_only | none
  corroboration:  count of independent tier-A/B sources agreeing
  dispute_state:  none | disputed | rejected | withdrawn
  first_seen, last_verified, content_hash, snapshot_id
}
```

| Tier | Definition |
|---|---|
| A | Vendor PSIRT advisory with verified signature; CISA KEV; signed distro feed |
| B | CNA-assigned CVE record from the assigning CNA; NVD-enriched record (now rare) |
| C | Curated community DB with maintainer review (GHSA *reviewed*, distro trackers) |
| D | Community-editable / unreviewed (GHSA *unreviewed*, mirrors, scrapes) |
| E | Model-generated, inferred, or derived by SDIP itself |

**Policy rules, not scores:**

- A **suppressive** decision may never rest on tier D or E. It requires **≥2 independent tier-A/B corroborations**, or a purely org-internal deterministic fact (not deployed / not reachable / compensating control attested by a named owner).
- An **escalating** decision may use any tier. Same asymmetry as ADR-0007.
- `dispute_state != none` ⇒ **cannot drive suppression**, at any tier.
- **Quarantine window:** an advisory first seen less than T hours ago (default 24–72) cannot drive suppression.
- **Independence is defined by `source_type`, not count.** Three chunks from the same NVD record is **one** piece of evidence — the guardrail an evidence-ranking pipeline silently violates if independence is not modelled.

### 4. Snapshot at decision time; never resolve a mutable URL during a decision

The audit record cites `snapshot_id + content_hash`, so a later edit cannot silently change what the log claims the system saw. This is what makes ADR-0012 work at all.

### 5. Range-narrowing detection is mandatory

Snapshot every advisory version with a content hash. **Diff affected ranges on every refresh. A narrowing is a security event that re-opens every finding previously suppressed on the basis of that advisory.** Log it, alert on it, expose it in the UI.

No competitor advertises this; it is cheap, and it is one of the seven genuinely open capabilities identified in `competitive-positioning.md`.

### 6. Nightly freshness sweep

Content-hash every evidence record; re-hash external evidence nightly; flag dependent decisions `evidence_stale`; trigger re-analysis **gated by ADR-0008's materiality check** so the sweep does not become an unbounded bill.

### 7. Feed ingestion is untrusted input

CVE and GHSA free text passes the same injection detector as repository content and is classified T3 (ADR-0007).

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| A single `reliability_score` float (CLAUDE.md §8) | A float is not a control. Policy needs rules with named preconditions |
| Trust "CVE data" as one feed | NVD enriches ~15–20% of new CVEs since 2026-04-15; GHSA has an unreviewed tier; OSV aggregates heterogeneous review |
| Re-analyze on every feed refresh | ~$1.46M/year/tenant on autopilot (ADR-0008) |
| Ignore EPSS model versions | Breaks longitudinal comparability and every calibration curve |
| Pay for EPSS version stability | Worth evaluating commercially; does not remove the need to record the version |

## Consequences

- Advisory snapshotting adds storage and a diffing job — small, and it is the mechanism behind two product claims (range-narrowing detection and `evidence_availability`).
- NVD's enrichment change is also an opening: every competitor faces the same missing-CVSS problem, and explicit source-authority handling is a real differentiator if built deliberately.
- Golden evaluation sets must store the evidence snapshot as of the annotation date, and an EPSS model bump forces an eval-set refresh (ADR-0010).

## Reversal strategy

Additive and cheap to extend. **Not retroactive:** evidence recorded without a version pin or snapshot cannot have one added later, so decisions made before this exists are permanently unauditable on the "what did we see" axis.

## Verification

- A test asserting no decision path resolves a live URL.
- A range-narrowing fixture asserting dependent suppressions re-open.
- A test asserting three chunks from one source count as one corroboration.
- A test asserting statistics refuse to pool across scanner major versions.
