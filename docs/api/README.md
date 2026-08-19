# API Contracts — SDIP

**Deliverable:** CLAUDE.md §46.G · **Artifact:** [`openapi.yaml`](openapi.yaml)
**Date:** 2026-08-14
**Status:** Design. MVP surface only; post-MVP endpoints are listed and explicitly deferred.

---

## 1. What CLAUDE.md §23 requires, and where each requirement is answered

| §23 requirement | Where |
|---|---|
| Request schema | `components/schemas` in `openapi.yaml` |
| Response schema | idem |
| Error model | §3 below — RFC 9457 `application/problem+json` |
| Authentication | §2 — OIDC bearer for humans, scoped ingest tokens for CI |
| Authorization | §2.3 — scope + role matrix per operation |
| Idempotency | §4 — mandatory on ingest, optional elsewhere |
| Pagination | §5 — cursor/keyset only. Offset pagination is banned |
| Filtering | §5.2 |
| Versioning | §6 |
| Async jobs for expensive reprocessing | §7 |

---

## 2. Authentication and authorization

### 2.1 Two credential classes, deliberately asymmetric

| Class | Used by | Shape | Scope |
|---|---|---|---|
| **Ingest token** | Customer CI | Short-lived, **minted by SDIP**, per project, per purpose | `ingest:findings` on exactly one project. Nothing else |
| **User session** | Analysts, admins | OIDC / SSO. Access token ≤15 min; server-side revocable refresh | Role-derived |

**SDIP holds no credential that authenticates *into* the customer** (ADR-0011). Ingestion is customer-side push. This removes the largest procurement objection — a Series-A vendor holding `contents:read` across 500 repos is, correctly, read by a CISO as an org-wide source-code exfiltration capability.

A stolen analyst session is a **mass-suppression capability**, which is why a stateless never-revocable JWT is the wrong choice here and why suppression operations require step-up authentication.

### 2.2 Roles

| Role | Can |
|---|---|
| `viewer` | Read findings, decisions, evidence, audit |
| `analyst` | + submit revisions, acknowledge reopen events, request re-analysis |
| `approver` | + create and revoke suppressions (**step-up auth required**) |
| `admin` | + manage integrations, budgets, policy, auto-suppression configuration |
| `ci` | `POST /scan-runs` only |

### 2.3 Rules that are not role-derived

- **No role can suppress a KEV-listed or actively-exploited finding.** `403` with `non_suppressible_reason`. Not a permission — a domain invariant (I19).
- **Enabling auto-suppression is itself a signed, audited configuration change** naming the human who enabled it. It is never a default.
- Every suppression carries a named approver. There is no system-authored suppression.

---

## 3. Error model — RFC 9457

```json
{
  "type": "https://sdip.example/problems/suppression-not-permitted",
  "title": "Suppression not permitted",
  "status": 422,
  "detail": "CVE-2026-1234 is listed in CISA KEV as of 2026-08-02.",
  "instance": "/v1/suppressions",
  "code": "non_suppressible",
  "non_suppressible_reason": "kev_listed",
  "trace_id": "01J…"
}
```

Rules:

- `code` is a stable machine-readable string; `title`/`detail` are human text and may change.
- **Error bodies never contain another tenant's data, and never echo untrusted input verbatim** — echoing a finding's `rule_message` into an error is an injection and exfiltration path.
- `429` carries `Retry-After`.
- `503` from budget exhaustion is wrong: budget exhaustion returns `202` with `analysis_state: deferred`, because **the system queues, it does not spend** (ADR-0008).

| Status | Used for |
|---|---|
| 200 / 201 / 202 | 202 is the normal result for ingest and re-analysis |
| 400 | Malformed request |
| 401 / 403 | Unauthenticated / insufficient scope or role |
| 404 | Not found **or not visible to this tenant** — never distinguish the two |
| 409 | Conflicting state change (not used for idempotent retries) |
| 413 | Payload above the hard cap |
| 422 | Domain invariant violated (suppression without conditions, non-suppressible finding) |
| 429 | Quota or rate limit |

---

## 4. Idempotency

**Mandatory on `POST /v1/scan-runs`.** Not "where applicable" — CI uploads retry on timeout, and a 90-second import behind a 60-second gateway timeout will be retried by every well-behaved client on day one (ADR-0005).

- Client sends `Idempotency-Key`. If absent, the server derives `sha256(payload) ‖ tool ‖ repo ‖ commit`.
- A retry with the same key returns **200 with the existing scan run and its status** — not 409, not a second import.
- Keys are scoped to the organization and retained for 30 days.

Optional and supported on `POST /v1/suppressions` and `POST /v1/decisions/{id}/revisions`.

---

## 5. Pagination and filtering

### 5.1 Cursor only

```
GET /v1/findings?limit=50&cursor=eyJvIjoi…
→ { "items": [...], "next_cursor": "…", "estimated_total": 41233 }
```

**Offset pagination is banned.** `OFFSET 50000` on a multi-million-row table scans and discards 50,000 rows per request, and results shift under concurrent ingestion so pages silently skip records. Cursors are keyset-encoded over the same column order as the driving index (`org_id`, then the sort key, then `id`).

`estimated_total` is explicitly an estimate (from statistics, not `COUNT(*)`) and is named so.

### 5.2 Filtering

| Resource | Filters |
|---|---|
| `/findings` | `status`, `class`, `severity`, `disposition`, `repo_id`, `service_id`, `tool`, `rule_id`, `cve_id`, `purl`, `owner`, `first_observed_after`, `last_observed_before`, `has_evidence_gap`, `cluster_id` |
| `/suppressions` | `status`, `scope_kind`, `expires_before`, `approver_id`, `condition_type` |
| `/reopen-events` | `trigger`, `detected_after`, `acknowledged` |
| `/audit` | `subject_type`, `subject_id`, `action`, `actor`, `from`, `to` |

Filters compose with AND. No free-text query DSL — a DSL over a security dataset is an injection surface and an unbounded-query surface, and every filter above maps to an index.

---

## 6. Versioning

- Path-based: `/v1/…`. A breaking change produces `/v2` and the two run in parallel.
- Additive changes (new optional fields, new enum members on **output** enums) are not breaking. **New members on input enums are breaking** and require a new version.
- Deprecation is announced with `Deprecation` and `Sunset` headers plus a `Link` to migration notes, at least 180 days ahead.
- `decision_version`, `policy_version`, `scoring_model_version`, `prompt_template_version` and `retrieval_config_version` are **payload fields, not API versions**. A client must never infer behaviour from the API version.

---

## 7. Async job APIs

Expensive work is never synchronous:

| Operation | Pattern |
|---|---|
| Scan ingestion | `POST /v1/scan-runs` → `202` + run id → poll `GET /v1/scan-runs/{id}` |
| Re-analysis | `POST /v1/findings/{id}/analyses` → `202` + job id → poll `GET /v1/analyses/{id}` |
| Re-correlation / re-scoring | `POST /v1/reprocessing-jobs` (admin) → shadow → explicit promote |
| Decision-debt report | `GET /v1/decision-debt` for the live view; `POST /v1/decision-debt/exports` for the full artifact |

Re-analysis is subject to the **materiality gate**: an unchanged evidence bundle returns the cached decision with a new `valid_as_of` and `analysis_state: unchanged`, and costs nothing. A client that polls re-analysis in a loop cannot generate cost.

---

## 8. Endpoint inventory

### MVP

| Method | Path | Notes |
|---|---|---|
| `POST` | `/v1/scan-runs` | Idempotent ingest. `ci` scope only |
| `GET` | `/v1/scan-runs`, `/v1/scan-runs/{id}` | |
| `GET` | `/v1/findings`, `/v1/findings/{id}` | |
| `GET` | `/v1/findings/{id}/observations` | The history that makes re-litigation possible |
| `GET` | `/v1/findings/{id}/related` | Correlation, with `relation` and `confidence` |
| `GET` | `/v1/findings/{id}/decisions` | |
| `POST` | `/v1/findings/{id}/analyses` | Async; materiality-gated |
| `GET` | `/v1/analyses/{id}` | |
| `GET` | `/v1/decisions/{id}` | Full record incl. `evidence_availability` |
| `GET` | `/v1/decisions/{id}/evidence` | Includes **gaps and drops**, not just what was used |
| `POST` | `/v1/decisions/{id}/revisions` | Analyst feedback; appends, never overwrites |
| `POST` | `/v1/suppressions` | Requires conditions + expiry + approver. Step-up auth |
| `GET` | `/v1/suppressions`, `/v1/suppressions/{id}` | |
| `POST` | `/v1/suppressions/{id}/revoke` | |
| **`GET`** | **`/v1/decision-debt`** | **The product.** Closed decisions whose justification expired |
| `GET` | `/v1/reopen-events` | |
| `POST` | `/v1/reopen-events/{id}/acknowledge` | Sets `analyst_agreed` — the re-litigation precision metric |
| `GET` | `/v1/audit` | |
| `POST` | `/v1/audit/verify` | Chain + anchor verification |
| `GET` | `/v1/usage` | Spend, budget, degraded state |
| `GET` | `/healthz`, `/readyz` | Unauthenticated, no tenant data |

### Deferred, with the trigger

| Endpoint | Deferred until |
|---|---|
| `/v1/knowledge/search` | Semantic retrieval is proven necessary beyond the two free-text evidence slots |
| `/v1/patterns` | ~20 customers (statistical power does not exist before then) |
| `/v1/remediation/*` | Never, probably — Jira exists and incumbents own that surface |
| `/v1/webhooks` | After the first design partner asks for push notification |
| `/v1/exports/decision-log` (continuous) | Enterprise SKU — but design the format now (customer custody of evidence is a selling point) |

---

## 9. Contract tests that must exist before the first customer

1. **Tenant isolation:** the entire suite run as tenant A with tenant B's data resident; assert zero rows of B in any response, error message, log line, metric label or export.
2. **Idempotency:** identical payload twice, same key ⇒ one scan run, one observation set, 200 on the second.
3. **Non-suppressible:** attempt to suppress a KEV-listed finding as `admin` ⇒ 422 with `non_suppressible_reason`.
4. **Suppression invariants:** create without conditions ⇒ 422; without expiry ⇒ 422; without approver ⇒ 422.
5. **Materiality gate:** re-analysis with an unchanged bundle ⇒ `analysis_state: unchanged`, zero model calls.
6. **Cursor stability:** paginate while inserting; assert no record is skipped or duplicated.
7. **Error hygiene:** assert no error body echoes untrusted input or names another tenant.
8. **Budget:** exhaust the budget ⇒ 202 `deferred`, never 5xx, never a silent spend.
