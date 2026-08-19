# ADR-0011 — Redaction boundary, `no_code` default, and zero credentials into the customer

**Status:** Accepted
**Date:** 2026-08-14
**Source:** `critique-security.md` §2, §6, §9
**Resolves:** the direct contradiction between CLAUDE.md §24 ("never destroy source-specific information", "raw source payload reference") and §18 ("safe handling of source code and secrets")

---

## Context

CLAUDE.md §5 puts Gitleaks in the MVP. **Gitleaks and TruffleHog findings *contain the secrets they found*.** Gitleaks emits `Secret` (the raw credential) and `Match` (surrounding text that **also contains it** — redacting only `Secret` is the most common implementation mistake). TruffleHog emits `Raw`, `RawV2`, and on `Verified: true` findings an `ExtraData` block containing data retrieved while authenticating with the credential.

## Problem

In a naive implementation a secret becomes durable in thirteen places, of which four are unrecoverable: **embeddings** (sent to a third-party provider — the secret has already left, and vectors are partially invertible, so a pgvector table of secret embeddings is a secret store), the **LLM provider prompt** (provider retention windows are days-to-weeks by default; zero-retention is an eligibility-gated enterprise option, not the default; you cannot recall what you sent), the **append-only audit trail** (a secret written there is one contractually promised never to be deleted), and **evaluation golden datasets** (committed to repos, copied into CI, shared with contractors — the highest realistic exfiltration probability of any row).

**Embeddings of secrets sent to a third-party provider is a breach** — a disclosure of credentials to an unauthorized processor, reportable under most DPAs.

Separately: SDIP holding `contents:read` across 500 repos is, functionally, **an org-wide source-code exfiltration capability held by a Series-A startup.** A CISO's security review will say exactly that, and the assessment is correct.

## Decision

### 1. The redaction boundary is a type, not a code review

**Location: inside the source adapter, in-process, before the payload touches any durable store, log, queue or metric label.** Not at the LLM call. Not at display time.

```
RawScannerPayload   # non-serializable by construction: no __str__, __repr__,
                    # __format__, model_dump, no JSON encoder registration.
                    # Exists only inside the adapter.
    └── redact() ──► RedactedFinding   # the ONLY type the rest of the system accepts
```

Every downstream signature (`persist`, `enqueue`, `embed`, `analyze`, `log`) accepts `RedactedFinding` and nothing else. MyPy in strict mode makes "we forgot to redact" a build failure rather than an incident.

**Rules:** drop `Secret`, `Match`, `Raw`, `RawV2`, and any `ExtraData` field not explicitly allowlisted. Retain `RuleID`, `File`, line numbers, `Commit`, `Entropy`, `Verified`, `Redacted`, `Fingerprint`. Retain a correlation handle as **`secret_ref = HMAC-SHA256(tenant_key, normalize(secret))`** with the key in KMS, never leaving the adapter process — **HMAC, not a plain hash**, because low-entropy secrets are trivially recovered from an unkeyed digest. This preserves recurrence detection, cross-scanner dedup, "this secret appears in 14 repos" and rotation verification without ever storing the secret. Pseudonymize `Author`/`Email` to an internal `owner_id` and classify them as personal data. `Message` (commit message) is untrusted T3 content.

### 2. The adjacent-secret problem

Redaction scoped to secret-scanner findings is insufficient. SAST and SCA snippets routinely contain hardcoded credentials, connection strings, JWTs in fixtures and API keys in comments. **Every snippet from every scanner passes a secondary detector (pattern + entropy) before it can be embedded, cached or sent to a provider.** A secret leaked through a Semgrep finding is exactly as breached as one leaked through Gitleaks.

### 3. Snippet policy tiers — `no_code` is the MVP default and the only MVP tier

| Tier | Behaviour | Availability |
|---|---|---|
| `no_code` | Rule id, file path, line, package, version only. No snippet ever leaves SDIP | **Default; the only tier in MVP** |
| `scrubbed` | Secrets/PII replaced by typed placeholders, length-capped | Post-MVP opt-in |
| `full_optin` | Full snippet | Explicit per-tenant opt-in **plus** a contractual zero-retention configuration with the provider |

The active tier is recorded **in the audit record of every decision**, so a customer can prove exactly what left their perimeter on a given date. That is a compliance feature, not overhead.

### 4. Zero credentials authenticating into the customer, in MVP

**Ingestion is customer-side push.** The customer's CI posts scanner output using a **per-project, per-purpose, short-lived token minted by SDIP**, scoped to `ingest:findings` for one project. A compromise of SDIP yields findings data (bad) but no repo access, no code, no write access and no pivot.

Where pull is genuinely required later (ownership, branch, commit, PR context): **a GitHub App with per-repo installation — not a PAT, not OAuth-as-user.** Minimum permissions `metadata: read`, plus `pull_requests: read` and `code_scanning_alerts: read` only if used. **`contents: read` only if snippets are required — and under `no_code` they are not.** Never `contents: write`, `workflows`, `actions: write`, `administration`, `members`, `organization_*`, `secrets`, `packages: write`, `deployments: write`. Publish the requested scope set with a justification for each, in the docs, before the first customer asks.

### 5. Custody and blast radius

Envelope encryption with per-tenant DEKs in KMS. Tokens are **write-only through the API** — no endpoint ever returns one. **Process separation:** the ingest/integration path (holds tenant credentials) and the analysis path (talks to the model provider, processes untrusted content) are separate processes with separate credentials and separate egress policy, so a prompt-injection-driven SSRF in the analysis path is structurally unable to reach the credential store. Default-deny egress with a per-integration allowlist. A customer-visible credential inventory with one-click revoke, a published mean-time-to-revoke, and a break-glass "disconnect everything."

### 6. Gitleaks ingestion is deferred

It is the highest-blast-radius integration with the lowest triage value: **a verified secret is never a triage question — the answer is always "rotate now."** It contributes near-zero decision intelligence while importing the entire secret-handling threat surface. Defer until the redaction boundary exists, type enforcement is in CI, and canary tests pass in production. Then ship it as a differentiated, provably-safe integration.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Redact at the LLM call | Twelve other landing zones remain, four unrecoverable |
| Redact in the service layer, enforced by review | Code review does not survive a new contributor and a deadline. Types do |
| Store raw payloads encrypted and call it safe | Encryption does not stop the embed/prompt/audit/eval-dataset paths |
| Plain hash for the correlation handle | Low-entropy secrets are recovered from an unkeyed digest by brute force |
| Ship secrets scanning in MVP as briefed | Maximum blast radius for minimum decision value |

## Consequences

- **Store raw payloads in a separate encrypted store with the shortest retention of any data class**, referenced by hash from observations. This satisfies §24's intent (nothing destroyed) without §18's violation (nothing leaked).
- The audit hash chain is computed **over references, not content** (ADR-0012), so a leaked payload can be deleted without breaking the chain.
- `no_code` reduces evidence quality for SAST triage. That is the accepted trade for MVP, and it shortens enterprise security review by weeks.
- Push-only ingestion removes the largest procurement objection — a security posture that is also a sales asset.

## Reversal strategy

Loosening (adding `scrubbed`, then `full_optin`, then pull-based integration) is straightforward and gated on contracts. **Tightening after a leak is impossible** — a secret sent to a provider cannot be recalled. Hence the restrictive default.

## Verification — canaries, not code review

Plant uniquely identifiable synthetic credentials in the evaluation corpus and in a permanent shadow tenant. On every CI run and on a production schedule, scan for those strings in: the provider request log, application logs, the database, **a restored backup**, the object store, the embeddings table (nearest-neighbour to a canary embedding), and every export artifact. Any hit fails the build or pages on-call. Register the canaries with a honeytoken service so external use also alerts.

Plus: a MyPy strict gate; a test asserting no downstream function accepts `RawScannerPayload`; a fuzz suite for every parser; a CI check failing on canary or PII patterns in test fixtures.

**A written runbook for the case where a real secret reaches a provider** — identify tenant and window, notify within the DPA SLA, drive rotation with the customer, request provider-side deletion where contractually permitted, record in the audit log. Write it before shipping, not after.
