# ADR-0014 — No graph database; one polymorphic edge table, one precomputed closure, selective embedding

**Status:** Accepted
**Date:** 2026-08-14
**Source:** `critique-architecture.md` §7, §8
**Strengthens:** CLAUDE.md §10 (which defers a graph DB; this ADR says it is never needed for the known query set)

---

## Context

CLAUDE.md §10 says to use Postgres relations first and treat GraphRAG as a later optimization, and §9.4 says to be "GraphRAG-ready." The implied claim is that migrating to a graph database later is cheap.

## Problem

**Half true, and the brief implies the wrong half is the expensive one.** You do not migrate data to a graph database; you migrate *queries*. Every recursive CTE must be rewritten in Cypher/Gremlin, revalidated for semantic equivalence and re-benchmarked. With a clean schema the export is a weekend; the query rewrite and revalidation is the multi-month piece.

The common failure: a team writes §10's bullet list, then implements relationships as foreign-key columns because that is what SQLAlchemy makes easy, and discovers in year two that ~40 relationships are FK columns and 6 are edges. **FK-encoded relationships are invisible to a generic exporter and must be hand-translated one column at a time. This is the single most common way the "graph-ready" claim becomes false.**

Separately, Postgres's recursive executor is an iterative set processor, not a traversal engine: it **cannot maintain visited state across iterations**, cannot prune explored nodes mid-walk, and collapses duplicates only at the end.

| Traversal | Verdict |
|---|---|
| finding → repo → owner | Fine forever, milliseconds |
| finding → CVE → package → affected versions | Fine |
| repo → service → deployment → environment | Fine — tens of millions of edges, sub-second |
| "which analyst decisions cite this evidence" | Fine — a join, not a traversal |
| **"which internet-exposed services transitively depend on a package with a KEV CVE"** (depth 5–8, fanout 20–100) | **Will not serve.** ~3×10⁸ frontier rows before dedup, all materialized. Times out or OOMs |

## Decision

### 1. One polymorphic edge table

```
edges(org_id, src_type, src_id, dst_type, dst_id, rel_type,
      confidence, provenance, inferred, algorithm_version,
      valid_from, valid_to)
```

with **opaque, stable, global IDs (UUID/ULID) on every node**. Relationships are **edge rows, not FK columns** — that rule is the whole of "graph-ready" and everything else is decoration. Temporal validity lives on the edge, not in application code. `inferred` + `confidence` + `algorithm_version` distinguish derived from authoritative relationships.

### 2. Precompute the one relation Postgres cannot traverse

```
dependency_closure(org_id, root_component_id, reachable_component_id,
                   min_depth, computed_at)
```

Refreshed on dependency-graph change — infrequent (lockfile commits, not every scan). This turns the 5–8 hop traversal into a single indexed lookup and is **~10× cheaper than operating a second database** with its own backup, HA, auth and tenant-isolation story.

### 3. The position, stated stronger than §10

**SDIP will not need a graph database for the queries it actually has.** One polymorphic edge table plus one precomputed closure covers them. Deferring the graph DB is not a compromise being tolerated; it is the correct end state.

### 4. Selective embedding

**Do not embed findings.** Finding text is templated and near-duplicate: embedding 1M findings produces 1M nearly-identical vectors and a retrieval layer that returns noise. Embed what has real semantic variance — **analyst decision rationales, remediation notes, external advisory prose** — which is 10k–100k vectors per tenant in year one, not millions.

At 768 dimensions: 100k vectors ≈ 300 MB raw, HNSW index ≈ 1.2–1.5 GB resident. Comfortable. At 5M vectors: ~60 GB of index — a large memory instance for the index alone.

**This moves the pgvector wall from ~6 months away to ~2–3 years away.** The architectural choice that matters is *what you embed*, not which index type.

### 5. pgvector configuration, pinned

- **HNSW is the default** below ~5M vectors (5–50 ms queries; ~30× better throughput and p99 than IVFFlat at equal recall, at ~4× the memory). IVFFlat only past ~50M vectors or when memory binds — and it needs rebuilds as the distribution shifts, which is bad for a continuously-ingesting corpus.
- Start at `m=16, ef_construction=64`; tune `ef_search` against a recall target.
- **pgvector ≥ 0.8, pinned, with iterative index scans enabled and `hnsw.max_scan_tuples` explicitly set.** Without it, a filtered query against a shared index walks the graph, collects candidates and *then* applies `org_id` — so a tenant holding 0.5% of rows silently gets 2 rows instead of 10. **No error, just degraded recall, worst for the smallest tenants — who are the ones on a pilot deciding whether to buy.**
- Decide `strict_order` vs `relaxed_order` deliberately; relaxed is usually right for RAG.
- Past a tenant-count threshold, move to **partitioned per-tenant indexes** — an index topology change, which is why ADR-0003 requires deciding it early.

### 6. Lexical search

Postgres FTS is sufficient initially, with a `simple` configuration plus `pg_trgm` for identifier-shaped fields (ADR-0009). Do not let anyone benchmark "Postgres FTS is bad" using the default English stemmer on CVE IDs.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Neo4j / a native graph DB now | A second store with independent backup, HA, auth and tenant isolation, for one query class a materialized closure answers |
| Per-relationship join tables | Twelve tables → twelve bespoke exporters; the migration this ADR exists to keep cheap becomes expensive |
| FK columns for relationships | The specific mistake that makes "graph-ready" false |
| Embed every finding | 1M near-identical vectors, noisy retrieval, and the vector wall arrives in ~6 months |
| A dedicated search engine now | CLAUDE.md §9.3 correctly defers it; introduce only when relevance evaluation justifies it |

## Consequences

- Writing relationships as edges is less ergonomic than SQLAlchemy relationships. That friction is the price of the property, and it needs a documented convention plus review enforcement.
- The dependency closure needs a refresh job with its own staleness monitoring.
- Per-tenant vector recall becomes a monitored evaluation metric (ADR-0010), not an assumption.

## Reversal strategy

Deliberately cheap: opaque IDs plus a single edge table make export mechanical. If a measured query pattern ever requires ≥4-hop traversal at a latency Postgres cannot meet, the data leaves in a weekend and the query rewrite is the real project — which is exactly what this ADR wants the future team to budget for.

## Verification

- A lint/review rule rejecting new FK columns that encode a domain relationship.
- A recall regression test per tenant-size class (tiny / medium / large).
- A benchmark of the dependency-closure lookup vs the equivalent recursive CTE at 1M edges.
