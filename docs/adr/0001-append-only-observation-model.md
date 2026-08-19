# ADR-0001 — Append-only observations, versioned identity, `scan_run` as first-class

**Status:** Accepted
**Date:** 2026-08-14
**Source:** `critique-architecture.md` §4, §5, §11.2
**Supersedes:** the natural reading of CLAUDE.md §24

---

## Context

CLAUDE.md §24 defines a canonical finding carrying `first_seen` / `last_seen`, implying one mutable row per finding. §25 separately requires that the system "allow re-correlation as algorithms improve."

These two requirements are incompatible. A mutable canonical row destroys the inputs that re-correlation would have to recompute from.

The volume is also mis-modelled. The brief reasons in *findings* (10k, 100k). The real quantity is *observations*: a 500-repo organization emits **1–5M finding-observations per day**, of which >99% are byte-identical to the previous scan.

## Problem

Against a mutable model, 1–5M observations/day means 1–5M UPDATEs/day against a ~100k-row table. Postgres MVCC writes a new tuple per update and leaves a dead one: **1–5 GB/day of dead tuples on a ~100 MB table**. HOT updates would mitigate this, but `last_seen` is precisely the column indexed for "not seen in 7 days," so updates are non-HOT: index bloat on every index, autovacuum permanently behind, physical size ~50× logical size.

That is the operational symptom. The structural problem is worse: three concerns with different lifetimes are fused into one row.

| Concern | Volume | Mutation rate | Requirement |
|---|---|---|---|
| Identity | ~100k | Only when the fingerprint algorithm version changes | Stable, versioned, recomputable |
| Observation | 1–5M/day | **Never** — it is a historical fact | Immutable, append-only, cheap to write |
| State | ~100k | On decision/lifecycle events (~100s/day) | Mutable, queryable, projected |

## Decision

Split them. The canonical attribute list in §24 is kept verbatim, but demoted from primitive to *the shape of the attributes an observation carries*.

```
finding_identity(id, org_id, fingerprint_version, fingerprint, class, first_observed_at)

observation(id, org_id, scan_run_id, identity_id, observed_at,
            tool, tool_version, rule_id, rule_version, ruleset_hash,
            <canonical attributes>, raw_payload_ref)          -- APPEND ONLY

finding_state(identity_id, org_id, status, current_decision_id,
              last_observed_at, updated_at)                    -- projection

scan_run(id, org_id, tool, tool_version, ruleset_version, ruleset_hash,
         repo_id, commit_sha, scope_hash, started_at, completed_at,
         status, finding_count, idempotency_key)
```

Identity is a **versioned pure function**, `fingerprint_v{n}(observation) -> bytes`, stored as a column. Multiple fingerprint versions coexist on the same observation.

`scan_run` is created **before** parsing, so "no findings" and "scan failed" are distinguishable — a precondition for ADR-0002 and ADR-0005.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| **Mutable canonical finding (CLAUDE.md §24 as written)** | Destroys re-correlation inputs permanently; 1–5 GB/day of dead tuples; "absent from scan" is unrepresentable |
| Mutable row + parallel audit table | The audit table drifts from the primary and is hand-maintained. Two sources of truth, one of which is wrong |
| Full event sourcing | Over-general. This is a fact/dimension split, not a command/event architecture. Do not import the ceremony |
| Time-series database alongside Postgres | A second store with its own tenant-isolation story, for a problem a partitioned append-only table solves |

## Rationale

Five properties, none available retroactively:

1. **Writes become INSERTs.** Append-only tables partition by time, never bloat, vacuum trivially.
2. **Re-correlation becomes mechanically possible.** `fingerprint_v2` is computed over the same stored observations; clusters re-derive; nothing is destroyed.
3. **"Absent from scan" becomes representable** — a fact the lifecycle machine (ADR-0002) can act on. Without it, "gone" and "never happened" are indistinguishable, which is how platforms silently auto-close real vulnerabilities.
4. **Scanner drift becomes visible** — same identity, different `tool_version`, different attributes. This is what keeps the §16 organizational statistics meaningful (ADR-0013).
5. **Audit is a timestamp filter** rather than a second parallel log.

## Consequences

**Accepted costs.** Every list view and API response reads the `finding_state` projection, which must be maintained transactionally on observation ingest. Storage grows with observations, not findings — partition by month and define a retention policy for observation rows distinct from decisions (ADR-0012). Developers must learn that "the finding" is three tables.

**Enabled.** ADR-0002 (lifecycle), ADR-0006 (versioned re-correlation), ADR-0012 (`evidence_availability`), ADR-0016 (decision expiry). All four depend on having the historical record.

## Reversal strategy

**None. This is the one irreversible decision in the system.**

Ship the mutable model for twelve months and the pre-change history does not exist to recompute from. §25 becomes permanently unachievable for all data collected before the fix, and the accumulated-decision-history asset restarts from zero on the day it is corrected.

Going the other way is cheap: a mutable projection can always be built from append-only observations. That asymmetry is the entire argument.

## Verification

- A test asserting no `UPDATE` grant exists on `observation` for the application role.
- A test that computes `fingerprint_v2` over a fixture corpus and re-derives clusters without touching source rows.
- A load test at 1M observations/day measuring table bloat over a simulated week.
