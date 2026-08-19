# ADR-0005 — Idempotent ingest and admission control

**Status:** Accepted
**Date:** 2026-08-14
**Source:** `critique-architecture.md` §4.3, §11.9; `critique-security.md` §7
**Depends on:** ADR-0001 (`scan_run`)

---

## Context

CLAUDE.md §23 says API contracts must define "idempotency behavior **where applicable**." §43 lists "denial of service through ingestion" as a threat, and §24 specifies no defense.

## Problem

**For scan ingestion, idempotency is not "where applicable" — it is the single most-exercised property in the system.** CI uploads retry on timeout. A 90-second SARIF import behind a 60-second gateway timeout will be retried by every well-behaved client, guaranteed, on day one. A half-imported scan that looks complete will silently mark hundreds of findings absent (ADR-0002).

Payload size is the second failure. An unfiltered Checkov or Gitleaks history scan reaches hundreds of MB. A naive `json.load()` on a 500 MB SARIF is ~5–10 GB resident. One misconfigured customer scan OOMs the ingest worker — repeatedly, because the upload is retried.

Third, cost asymmetry. An attacker who can push scanner output controls both the count and the size of findings, and generates it for approximately zero. Dedup does not help (make each finding structurally unique) and prompt caching does not help (the attacker-controlled content is the uncacheable suffix).

## Decision

1. **`Idempotency-Key` is mandatory** on ingest — client-supplied, or derived as `sha256(payload) + tool + repo + commit`. `scan_run` carries a unique constraint on it.
2. **`scan_run` is created before parsing.** A retry with the same key returns the existing `scan_run_id` and its status — **200, not 409**, and not a second import.
3. **Import is transactional per scan run**, or carries a `status` distinguishing `partial` from `complete`. Only `complete` runs participate in absence counting (ADR-0002).
4. **Streaming parse always.** Never `json.load()` a customer file. Hard payload cap (default 100 MB, per-tenant configurable upward with review).
5. **Per-field length caps** at the adapter. Truncation is recorded as evidence: `{truncated: true, original_hash, original_length}` — which satisfies CLAUDE.md §24's "never destroy source-specific information" because the full payload lives in the payload store while the *context* is capped.
6. **Per-finding validation with a poison-record DLQ.** One bad record must not fail a 50k import.
7. **Per-tenant quotas:** uploads/hour, findings/day, bytes/day. Exceeding queues rather than rejecting where possible; rejects carry a machine-readable reason.
8. **Circuit breaker** on repeated OOM or parse failure from the same tenant.
9. **Fair-share scheduling.** One tenant's 500k-finding import must not starve others.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Idempotency "where applicable" (CLAUDE.md §23) | Guarantees duplicate imports on day one |
| Return 409 on retry | Clients treat 409 as an error and escalate; the correct semantic is "this is the same request, here is its status" |
| Reject oversized payloads outright | Punishes the customer for their scanner's verbosity. Cap fields, stream the body, keep the import |
| Rely on dedup to absorb duplicate imports | Dedup is a cost optimization, not a correctness control — and an adversary makes every record unique |

## Consequences

- The ingest API becomes asynchronous: `POST /scan-runs` returns a run id and status; findings appear as the worker progresses. This is the correct shape anyway for a batch-first product (ADR-0008).
- Clients must send a stable key. Document it prominently; derive one when absent.
- Truncation must be visible in the UI, or analysts will believe they are seeing full evidence.
- Quota rejections need clear error semantics in the API contract (deliverable G).

## Reversal strategy

Cheap and additive. Caps and quotas are configuration; the idempotency key is a column with a unique index. The only expensive mistake is *not* creating `scan_run` before parsing, since retro-attributing observations to runs is guesswork.

## Verification

- A test issuing the same payload twice with the same key, asserting one `scan_run` and one set of observations.
- A test that kills the worker mid-import and asserts the run is `partial` and contributes nothing to absence counting.
- A 500 MB SARIF fixture asserting bounded memory (streaming parse) and a clean cap rejection.
- A poison-record fixture asserting the remaining records import and the bad one lands in the DLQ.
