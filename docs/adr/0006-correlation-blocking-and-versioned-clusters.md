# ADR-0006 — Correlation via blocking, append-only edges, versioned materialization

**Status:** Accepted
**Date:** 2026-08-14
**Source:** `critique-architecture.md` §6, §11.4
**Depends on:** ADR-0001

---

## Context

CLAUDE.md §25 lists ten correlation *signals* and zero algorithms. It also requires that findings must not be merged irreversibly and that re-correlation must be possible as algorithms improve.

## Problem

**Naive all-pairs does not scale and there is no tuning path.** n=100k → 5×10⁹ comparisons ≈ 83 minutes single-threaded at an optimistic 1 µs each. n=1M → 5×10¹¹ ≈ 5.8 days.

**Naive union-find violates §25.** Writing a `cluster_id` onto a finding row *is* an irreversible merge — the pre-merge state is gone and algorithm v2 cannot be compared against v1.

## Decision

### Four tiers, with a hard cap

**Tier 0 — exact identity (hash join, O(n)).** Fingerprint equality, executed **at ingest**, not in the correlation worker. Absorbs ~99% of re-scan volume and is what keeps the worker's input small.

**Tier 1 — blocking (equi-join, O(n)).** Candidates are generated *only* within blocks; never compare across blocks.

| Class | Blocking key |
|---|---|
| SCA | `(purl_name, purl_version)` and `(cve_id)` |
| SAST | `(repo_id, cwe_normalized, dirname(file_path))` |
| Secrets | `(secret_ref_prefix, repo_id)` — never the secret itself (ADR-0011) |
| Container | `(image_digest, package_name)` |

SAST blocks on CWE + location, not rule id: cross-tool agreement exists at that granularity, not at rule granularity.

**Tier 2 — in-block scoring, bounded.** Weighted similarity over §25's signals inside a block only.

> **The block-size cap is load-bearing.** One pathological block — everything under `vendor/`, or every CVE in a shared base image — reintroduces O(n²) inside a single block and hangs the worker. Enforce a hard cap `B` (start at 200). A block exceeding `B` is **skipped and alerted**, never processed. At B=200, n=1M: ≤2×10⁸ comparisons — minutes.

**Tier 3 — LSH/MinHash over normalized snippets.** The only place LSH earns its cost (same vulnerable code vendored across repos with no shared key) and the least valuable tier at MVP. **Deferred past MVP.**

### Never persist cluster membership as mutable state

```
correlation_edge(org_id, a_identity_id, b_identity_id,
                 relation,        -- exact_duplicate | same_root_cause | related | suspected
                 confidence, algorithm_version, evidence_json, created_at)   -- APPEND ONLY

correlation_cluster_materialized(org_id, algorithm_version, identity_id, cluster_id)
```

Union-find runs **in memory at materialization time** (near-linear with path compression), producing a *versioned* materialization. Algorithm v2 inserts edges at `algorithm_version=2` and materializes alongside v1: diff the two, shadow-run v2 for a week, measure against the golden set, promote by flipping which materialization the API reads. Nothing is destroyed.

### Incremental by default, with tracked full recompute

New observation → resolve identity → generate candidates against existing blocks → emit edges. Bounded and small. Algorithm change → full recompute per tenant as a tracked job: **10–20 min of one worker at 1M findings**, which is fine as a scheduled job and impossible as an ad-hoc script.

Therefore **reprocessing orchestration is a required MVP component**, not a nice-to-have: progress, resumability, per-tenant scoping, rate limiting against the primary workload, versioned output written alongside current, shadow diff, and an explicit promotion step. The same subsystem serves re-correlation, re-scoring (ADR-0008) and evidence invalidation (ADR-0013).

### No LLM on this path

CLAUDE.md §25's signals are all structural — identifiers, versions, fingerprints, locations. An LLM here adds cost, latency, non-determinism and a prompt-injection surface to a problem with an exact answer and a measurable golden set.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| All-pairs with better hardware | 5.8 days at 1M. Not a tuning problem |
| Persisted mutable `cluster_id` | Irreversible merge; violates §25; makes v1/v2 comparison impossible |
| Streaming correlation (Kafka) | CLAUDE.md §22 correctly defers Kafka; incremental+batch covers the requirement |
| LSH first (it is the interesting part) | Choosing the sophisticated tier over the load-bearing one. Blocking delivers ~99% of the value |
| LLM-assisted correlation | Non-deterministic answer to a deterministic question, plus an injection surface |

## Consequences

- Blocks must be monitored: a skipped oversized block is a silent recall loss and needs an alert plus a UI surface.
- Cluster reads go through the materialization, so the API must carry an `algorithm_version` selector internally.
- Golden set for correlation/dedup (300 pairs, half true duplicates, half hard near-misses) is a precondition for promoting any v2.

## Reversal strategy

Cheap by construction — that is the point of the design. Edges are append-only; materializations are disposable and recomputable. Changing blocking keys is a full recompute, which is a scheduled job.

## Verification

- A 300-pair golden set with measured precision/recall per relation type.
- A pathological-block fixture asserting the cap trips, the block is skipped, and an alert fires.
- A v1-vs-v2 shadow diff report generated by the reprocessing job.
