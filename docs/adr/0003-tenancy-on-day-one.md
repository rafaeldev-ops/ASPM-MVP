# ADR-0003 — Full tenancy on day 1

**Status:** Accepted
**Date:** 2026-08-14
**Source:** `critique-architecture.md` §10, `critique-security.md` §3

---

## Context

CLAUDE.md §19 says to design domain boundaries so tenant scope is explicit, but defers implementation. §19 is a list of prohibitions ("Never allow cross-organization retrieval") with **zero mechanisms**. Prohibitions are not controls.

In a system whose entire value is org-specific memory, one missing `WHERE org_id = ?` is a cross-customer intelligence disclosure that produces no error and no log line — just a plausible answer containing another customer's security posture.

## Problem

Two things are cheap now and expensive later, and neither is a "boundary":

1. **Embeddings.** Row scoping is a `WHERE`. Vector scoping is an *index topology decision*: a shared HNSW index with a post-filter has a silent recall cliff for small tenants; per-tenant indexes have a memory cliff. Choosing late means re-embedding *and* re-architecting retrieval *and* re-tuning `ef_search` *and* re-running the whole retrieval evaluation.
2. **Caches.** A Redis key like `evidence:cve-2024-1234` looks tenant-neutral. It is not — an evidence bundle includes org-specific context. Serving org B a bundle assembled for org A is a cross-tenant leak with no exception and no log line.

Cost now: **~1–2 engineer-weeks.** Cost at month 12: **~3–6 engineer-months plus an unbounded security review**, including online migrations across ~25 multi-million-row tables, a rebuild of every index, and re-embedding.

## Decision

Implement tenancy in migration #1, while still single-tenant.

1. **`org_id UUID NOT NULL` as the first column of every primary key and every index** on every tenant-scoped table.
2. **RLS `ENABLE` *and* `FORCE`** on every such table. The application connects as a **non-owner, non-superuser** role. `BYPASSRLS` exists only for a reviewed break-glass path whose use alerts.
3. Tenant context set with **`SET LOCAL app.tenant_id` inside an explicit transaction**. Every query path runs in a transaction — no autocommit paths, no exceptions. With PgBouncer, transaction pooling only; statement mode is incompatible.
4. **One cache wrapper.** No component touches Redis directly. Every key is `t:{org_id}:{...}`, enforced by a lint rule.
5. **A shared cache may hold only data whose provenance is entirely public** (NVD/OSV/KEV/EPSS keyed by public identifier). Anything org-derived is tenant-partitioned. **Never key a cache by bare content hash** — a content-addressed shared cache is a cross-tenant oracle measurable by hit latency.
6. **Vector index topology is decided now**, not later: start shared with pgvector ≥0.8 iterative scans, with a documented tenant-count threshold that triggers partitioning (ADR-0014).
7. Prompt-cache prefixes are never constructed from one tenant's data.

## Alternatives considered

| Alternative | Verdict |
|---|---|
| Application-layer scoping only | **Reject.** Fails the first raw SQL query, analytics export, or background job — undetectably |
| Schema-per-tenant | **Reject.** O(tenants) cost per migration, breaks pooled connections, loses shared index efficiency, still one role from disclosure |
| Database-per-tenant | **Adopt as a paid enterprise tier**, not as the MVP default. CLAUDE.md §35 already lists private deployment as premium — this is the same line item with a security justification |
| Defer to month 12 (CLAUDE.md §19 as written) | **Reject.** ~2 weeks vs ~4 engineer-months, and the later path carries non-recoverable leak risk |

## Consequences

**Operational costs accepted, stated honestly:** migrations run as the owner and are therefore an RLS bypass surface — classify migration review as security-relevant and require a second reviewer. Indexes must lead with `org_id` or the RLS predicate turns index scans into sequential scans. pgvector + RLS applies the predicate *after* ANN candidate selection, so small tenants silently lose recall — per-tenant recall becomes a monitored evaluation metric, not an assumption.

**Enabled:** the enterprise SKU, the security review, and the ability to onboard a second customer without a migration project.

## Reversal strategy

Not applicable in the useful direction — this ADR exists because the reversal (retrofitting) is the expensive path. Removing tenancy later, if the product were ever single-tenant-only, is a no-op.

## Verification (blocking CI)

- **Migration gate:** a test querying `pg_class.relrowsecurity` / `relforcerowsecurity` that fails if any table with an `org_id` column lacks both.
- **Isolation suite:** run the entire API contract suite as tenant A with tenant B's data resident; assert zero rows of B in any response, error message, log line, metric label, or export.
- **Pooling gate:** two sequential requests for different tenants on the same pooled connection; assert no context bleed.
- **Cache lint:** no raw Redis client import outside the wrapper module.
