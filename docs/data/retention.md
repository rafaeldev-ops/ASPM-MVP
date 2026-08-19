# Retention, Deletion and Data Governance — SDIP

**Deliverable:** CLAUDE.md §44 · §42 (`docs/data/`)
**Date:** 2026-08-16
**Status:** Design. Binds migration #1 (partitioning, grants) and the DPA.
**Governed by:** ADR-0001 (append-only), ADR-0003 (tenancy), ADR-0011 (secrets), ADR-0012 (audit integrity)
**Blocks:** the first enterprise security review, jointly with `threat-model.md`

---

## 0. The correction this document exists to make

CLAUDE.md §44 asks for "retention policy" — singular. **There are three, they have different lifetimes, and they are in direct conflict:**

| Class | Wants | Because |
|---|---|---|
| Raw scanner payloads | **The shortest possible life** | They contain secrets and source fragments. Every day retained is exposure |
| Findings and observations | Medium — long enough for longitudinal claims | "This recurred four times in 13 months" is a product claim, and it needs the history |
| Decisions and audit records | **The longest — years** | The product's defence in a dispute is a record that outlives the finding it describes |

Written as one policy, these collapse into whichever number was written first, and the usual outcome is a single "retain everything for 2 years" that is simultaneously **too long for secrets and too short for audit.**

The second thing §44 does not confront:

> **Deleting a finding does not delete what was derived from it.** Its embedding, its contribution to `rule_disposition_stats`, the memory entry it produced, the decision that cited it, and the calibrator fitted partly on it all survive. Without a designed answer, the deletion commitment in §44 cannot be honoured and should not be made.

Both of those are answered below, and the second is answerable **only because the source data is append-only** (ADR-0001). On a mutable model, aggregates cannot be recomputed from surviving source, and the obligation is unfulfillable in principle.

---

## 1. Data inventory and classification

Every class below has: a sensitivity tier, a retention period, a deletion mechanism, and a named location. A class not on this list may not be persisted.

| # | Class | Contains | Tier | Retention | Mechanism |
|---|---|---|---|---|---|
| **C1** | **Raw scanner payloads** | Original SARIF/JSON incl. snippets and, if secret scanning is enabled, **secrets** | **Restricted** | **30 days** (configurable down, never up without a signed exception) | Object-store lifecycle rule + **crypto-shred** (§4.3) |
| C2 | Observations | Normalized findings: rule, location, package, severity, `secret_ref` (HMAC) | Confidential | **13 months** | Monthly partition `DETACH` + `DROP` |
| C3 | Evidence bodies | Extractive advisory/KEV/EPSS content, code-flow steps | Confidential | 13 months, follows C2 | Cascade with C2 |
| C4 | Finding identity + state | Fingerprints, lifecycle, `absent_run_count` | Confidential | Tenant lifetime | Explicit delete on offboarding |
| C5 | **Decisions** | `deterministic_assessment`, `model_recommendation`, `policy_decision`, `evidence_availability` | Confidential | **7 years** | Never partition-dropped. WORM export |
| C6 | **Audit records** | Chained hashes over **references** | Confidential | **7 years** | Append-only; never deleted before term |
| C7 | Suppressions, conditions, reopen events | The product's core objects | Confidential | 7 years (follows C5) | With C5 |
| C8 | Organizational memory | `memory_entry`, corroboration, derivations | Confidential | Tenant lifetime | Quarantine + cascade; delete on offboarding |
| C9 | Embeddings | Vectors over 3 subject types | Confidential | Follows subject | Delete by `subject_id`; **HNSW rebuild scheduled** |
| C10 | Statistical aggregates | `rule_disposition_stats`, calibrators | Confidential | Recomputed | **Recompute from surviving source** (§3.2) |
| C11 | **Personal data** | Analyst identities, IdP subjects, emails, commit-author identifiers, CODEOWNERS entries | **Restricted / PII** | Tenant lifetime, subject to erasure (§3.4) | Tombstoning + pseudonym retention |
| C12 | Operational logs & metrics | Request logs, worker logs, traces, cost ledger | Internal | 90 days | Rotation. **Never contains prompt content or payload bodies** |
| C13 | Evaluation datasets | Golden sets + evidence snapshots | **Restricted — production-classified** | Versioned indefinitely | §6 |
| C14 | Backups & PITR | Everything above | Mirrors source tier | **35 days** (§4.2) | Aging + crypto-shred |
| C15 | Exports | WORM decision-log, decision-debt artifacts | Confidential | Customer-controlled once delivered | Out of SDIP custody — stated as such |

### 1.1 Personal data is smaller than people assume, and in specific places

Security findings are mostly not personal data. C11 is, and it is confined to an enumerated set so that erasure is a bounded operation rather than a search:

- `actor.subject`, `actor.email` — analysts and admins
- Commit-author name/email arriving via scanner metadata or Git provider metadata
- CODEOWNERS entries and ownership records naming individuals
- `decision_revision.actor_id`, `suppression.approver_actor_id` — **references, not content**
- Free text an analyst typed: `justification`, revision `note`

**The last one is the leak.** A free-text justification can contain anything, including a colleague's name and an opinion about them. It is classified as PII by construction, not by inspection.

---

## 2. Retention, stated as policy

```
raw payloads        ├──30d──┤
observations        ├──────────────── 13 months ────────────────┤
evidence bodies     ├──────────────── 13 months ────────────────┤
embeddings          ├─── follows subject ───┤
operational logs    ├─90d─┤
backups / PITR      ├─35d─┤  (rolling, over everything)
decisions           ├──────────────────────── 7 years ──────────────────────────┤
audit records       ├──────────────────────── 7 years ──────────────────────────┤
```

Three consequences worth naming before a customer does:

1. **A decision outlives the observation that produced it.** At 14 months a decision still exists and its raw evidence does not. This is intentional, and it is why `evidence_availability` and content hashes are mandatory on the decision record (I13): the decision must remain interpretable after its source is gone. A decision that becomes unintelligible at 13 months is not a record, it is a receipt.
2. **The 13-month observation window is a product decision, not a storage one.** It is set to cover a full annual cycle plus a month, so "recurred every quarter for a year" is computable. Shortening it below 12 months silently removes a class of product claim.
3. **7 years is derived from contract and limitation periods, not from a technical need.** It is negotiable per tenant *upward*; downward it is a signed exception, because it is the artifact that defends both parties in a dispute.

### 2.1 Per-tenant overrides

| Parameter | Default | Range | Approval |
|---|---|---|---|
| Raw payload retention | 30d | 0–90d | 0d is self-service. >30d requires a signed exception naming the risk owner |
| Observation retention | 13mo | 6–36mo | Self-service within range |
| Decision/audit retention | 7y | 7y–∞ | Increase self-service; **decrease requires legal sign-off** |
| Snippet tier | `no_code` | `no_code` · `scrubbed` · `full_optin` | Increase requires a signed configuration change naming the approver |

Every override is a signed, audited configuration change and is surfaced in-product. A customer must be able to answer "what does this vendor hold about us, and for how long" from the UI, without asking us.

---

## 3. Deletion

Four distinct operations. Conflating them is how a vendor ends up believing it honoured a request it did not.

| ID | Operation | Trigger | Scope |
|---|---|---|---|
| **D1** | Object deletion | A repository, service or project is removed | That subject and everything derived from it |
| **D2** | Tenant offboarding | Contract ends | Everything for one `org_id` |
| **D3** | Subject erasure | GDPR Art. 17 / equivalent | One natural person's personal data, across tenants |
| **D4** | **Emergency purge** | A secret or regulated datum entered where it must not be | One content-addressed blob, immediately, everywhere |

### 3.1 D1 — object deletion, and the cascade that is the real work

Deleting a repository is not one `DELETE`. It is a **tracked job** with an auditable completion record:

```
delete_repository(org_id, repo_id):
  1. scan_run, observation, observation_fingerprint         → by repo scope, across partitions
  2. finding_identity, finding_state                        → identities whose observations are all gone
  3. correlation_edge, correlation_cluster_materialized     → edges touching removed identities
  4. evidence, evidence_gap, evidence_drop, conflict,
     code_flow, code_flow_step                              → by decision scope
  5. embedding                                              → by (subject_type, subject_id); schedule index maintenance
  6. memory_entry                                           → quarantine + cascade if solely derived from removed data
  7. rule_disposition_stats, calibrator                     → RECOMPUTE, do not patch  (§3.2)
  8. raw payload objects                                    → crypto-shred by key
  9. decision, decision_revision, suppression, audit_record → RETAINED (§3.3) unless D2
 10. write completion record: counts per step, duration, operator
```

Steps 5–7 are the ones that get skipped, and each has a distinctive failure:

- **A surviving embedding** is a semantic ghost: the vector still returns as a retrieval hit and its `subject_id` no longer resolves. Either it silently disappears from results (a recall bug) or it surfaces content that was supposed to be gone (a disclosure).
- **Un-recomputed statistics** mean the deleted repository still influences every future decision on that rule, forever, invisibly.
- **Memory entries** are the durable ones by design; that is exactly why they need explicit handling.

### 3.2 Aggregates are recomputed, never patched

`rule_disposition_stats` and every calibrator are **derived state with no independent authority**. Deletion does not subtract from them; it invalidates them and they are rebuilt from surviving append-only source.

This is only possible because observations are immutable and complete (ADR-0001). It is worth stating the counterfactual plainly: **on a mutable `finding` table with incremented counters, there is no way to remove one repository's contribution to a year-old statistic, and the deletion promise in CLAUDE.md §44 would be a lie that no code review would catch.**

Recomputation is a `reprocessing_job` with progress and resumability, and it carries the same shadow/promote discipline as any other derived-state rebuild.

### 3.3 The audit conflict, resolved

Deletion says *remove it*. Audit integrity says *the record is immutable for 7 years*. Both are correct. The resolution is structural and was made in ADR-0012:

> **The hash chain is computed over references, not content.** `audit_record.payload_ref` is the hash of the payload, not the payload.

Therefore:

| | Deleted | Chain still verifies | Provable |
|---|---|---|---|
| Payload content | ✅ | ✅ | That it existed, when, and that it is now gone |
| Reference + hash | ❌ retained | ✅ | Existence and integrity |

**Provable existence plus provable deletion.** A decision record survives with the *fact* that it cited evidence whose content is deleted, which is the correct outcome in both a deletion audit and a deposition.

Under D1, decisions and audit records referencing deleted objects are retained with their subjects tombstoned. Under D2 they are deleted with the tenant, and the last audit record before deletion is exported to the customer.

### 3.4 D3 — subject erasure

Personal data (C11) is erased by **tombstoning with pseudonym retention**:

- `actor.subject`, `actor.email` → `NULL`, with `actor.status = 'erased'` and the erasure timestamp.
- The `actor.id` UUID **survives**, because decisions, revisions, suppressions and audit records reference it. Replacing a foreign key with `NULL` to satisfy an erasure request destroys the accountability chain that says a *named human* approved a suppression — trading a data-protection obligation for an audit failure.
- Commit-author identifiers → replaced with a per-tenant HMAC, preserving the "same author" join without the identity.
- **Free-text `justification` and `note` fields are redacted, not deleted**, leaving a tombstone: `[redacted on 2026-11-04 under erasure request ER-118]`.

The defensible position, and the one to put in the DPA: **erasure yields a pseudonymous record of an accountable act, not the disappearance of the act.** Where a customer's legal team requires more, the only honest answer is D2 for that tenant.

### 3.5 D4 — emergency purge

The secret-leak runbook, because this will happen and the time to design it is not during it:

1. Freeze the affected raw-payload objects and DLQ entries; revoke the object-store lifecycle race.
2. **Rotate first, delete second.** Deletion is not remediation; the credential is already out.
3. Content-addressed purge across: object store, DLQ, Postgres columns, embeddings, **exports already generated**, operational logs, and **restored backups**.
4. Crypto-shred the affected payload key (§4.3) to cover backup residue inside the PITR window.
5. Canary sweep across provider request logs, application logs, database, a restored backup, the object store, the embedding table and every export artifact.
6. Breach-notification assessment against the SLA in §5.
7. Post-incident: which control at TB1 should have stopped this, and is the canary harness covering that path.

Target: **purge initiated within 1 hour of confirmation, complete within 24 hours excluding backup expiry, which is covered by crypto-shredding rather than by waiting.**

### 3.6 Deletion SLAs

| Operation | Initiate | Complete (live systems) | Backups |
|---|---|---|---|
| D1 | 24h | 7 days | Aged out ≤35d |
| D2 | 24h | **30 days**, then a signed certificate of deletion | Crypto-shredded at completion |
| D3 | 72h (regulatory) | 30 days | Pseudonymous residue only |
| D4 | **1 hour** | 24h | Crypto-shredded immediately |

### 3.7 Legal hold overrides deletion, and says so

A legal hold on a tenant or subject **suspends D1–D3** (never D4, which is a security control). The hold is itself an audited record naming who placed it, when, and under what matter. A customer whose deletion request is suspended by a hold is told that it is suspended — silence here is the failure mode that turns a data-protection question into a litigation question.

---

## 4. Backups, PITR and the "deleted" ambiguity

### 4.1 The question every enterprise reviewer asks

*"You say deleted in 30 days. Is it in your backups?"* The honest answer is yes, and the design must make that bounded and provable rather than embarrassing.

### 4.2 Stated windows

| Mechanism | Window | Notes |
|---|---|---|
| Postgres PITR / WAL | **35 days** | Stated in the DPA. This is the true floor for logical deletion |
| Full backups | 35 days rolling | Encrypted; separate key custody; restore path audited |
| Object store versioning | **Disabled** for the raw-payload bucket | Versioning would silently defeat the 30-day payload lifetime |

**"Deleted" means: removed from live systems within the §3.6 SLA, and unrecoverable from backups within 35 days — except where crypto-shredding makes it unrecoverable immediately.** That sentence goes in the DPA verbatim.

### 4.3 Crypto-shredding — where it works and where it does not

Envelope encryption with a **per-tenant data key** (and, for C1, a **per-payload key** wrapped by it) in KMS. Destroying a key makes the ciphertext unrecoverable everywhere it exists, including inside backups, without waiting for the backup to age out.

| Data | Crypto-shreddable | Why |
|---|---|---|
| **C1 raw payloads** (object store) | ✅ Immediately | Per-payload keys. This is the class where it matters most |
| C15 exports | ✅ | Per-export keys |
| C14 backups of the above | ✅ | Ciphertext is inert once the key is destroyed |
| **Postgres rows** | ❌ **Not per-row** | Rows in shared tables under one cluster-level encryption context. Logical delete + 35-day PITR expiry is the actual guarantee |
| C9 embeddings | ❌ | Deleted logically; index maintenance scheduled |

**Do not claim per-row crypto-shredding in Postgres.** A reviewer who probes it will find the claim false, and the credibility loss extends to every other statement in the questionnaire. Claim it exactly where it is true — which is where the secrets are — and state the 35-day window for the rest.

---

## 5. Governance commitments

Each of these is a sentence in a DPA or a security questionnaire. They are written here so that they are answered once, consistently, by everyone.

| # | Commitment |
|---|---|
| **G1** | **Customer data is the customer's.** SDIP holds it as processor. Findings, decisions, evidence and organizational memory are exportable in a documented format at any time, and on termination |
| **G2** | **No customer data trains any model.** Not ours, not a provider's. Contractual with each provider, and stated per tenant in-product |
| **G3** | **Sub-processor register is published**, names the model provider and the hosting provider, and change notification is contractual (GDPR Art. 28) |
| **G4** | **Provider retention is stated as fact per tenant**, not as a range — including whether ZDR is active for that tenant — and is recorded in **every decision record** (`provider.zdr_enabled`, `provider.inference_geo`) |
| **G5** | **Default snippet tier is `no_code`.** Source code is not sent to a model provider unless the tenant signs an opt-in naming the approver |
| **G6** | **Prompt content is never logged.** Prompt *hash*, template version and evidence ids are. Enforced by the type boundary and canary tests, not by policy |
| **G7** | Data residency / inference geography pinned where the provider supports it; stated per tenant |
| **G8** | Encryption in transit everywhere; at rest for all classes; separate key custody for backups |
| **G9** | **Breach notification within 24 hours of confirmation**, with the §3.5 runbook attached |
| **G10** | **Continuous decision-log export to customer-controlled storage** is available. Customer custody of their own evidence is a selling point, not a concession |
| **G11** | Cross-tenant knowledge is **off by default** (`knowledge_scope = tenant_private`). ADR-0017 is unresolved; until it resolves, the answer to "do you learn across customers" is **no** |
| **G12** | Deletion is provable: every D1/D2 job produces a signed completion record with per-step counts |

G11 deserves the emphasis. It is the question that gets asked in every enterprise review, the answer must be one word, and it must match the code. `knowledge_scope` is part of the RLS predicate specifically so that the one-word answer is enforced rather than promised.

---

## 6. Evaluation data governance

**Golden datasets carry production classification.** This is not administrative caution — evaluation data has the highest realistic exfiltration probability of any class in the system, because it gets committed to repositories, copied into CI, shared with contractors, and pasted into benchmark harnesses.

| Rule | Enforcement |
|---|---|
| Classified, access-controlled and retained as production data | Repository permissions, CI secret scoping |
| **No real secrets in any fixture. Ever** | CI fails on canary and PII patterns in `tests/fixtures/` and `eval/datasets/` |
| **Planted canaries** — unique synthetic credentials seeded into the corpus | Scanned on every CI run and on a production schedule across provider request logs, application logs, the database, a restored backup, the object store, the embedding table and every export artifact |
| Customer-derived data is never published without contractual consent | The published benchmark is built from public advisories and synthetic-but-realistic findings |
| Dataset changes are reviewed like production code | Content-hashed, versioned, second reviewer (TH-43) |
| Golden items excluded from the retrieval index at evaluation time | A test asserts the contamination filter is active |

---

## 7. Verification

Governance that is not tested is a paragraph. Each row below is a test that must exist.

| # | Test | Asserts |
|---|---|---|
| V1 | Payload lifetime | No raw payload object older than the configured window exists in the bucket |
| V2 | **Deletion cascade** | After `delete_repository`, zero rows survive in each of the ten steps, **including embeddings and recomputed aggregates** |
| V3 | **Aggregate recomputation** | `rule_disposition_stats` after deletion equals a from-scratch rebuild over surviving source |
| V4 | **Chain survives content deletion** | Delete a referenced payload; `POST /v1/audit/verify` still passes |
| V5 | Erasure | After D3 the actor's PII is `NULL`/tombstoned, referential integrity holds, and the audit chain verifies |
| V6 | Canary | Seeded canaries appear in **zero** of: provider request logs, application logs, database, restored backup, object store, embedding table, export artifacts |
| V7 | Log hygiene | No log line contains prompt content or a payload body |
| V8 | Partition drop | A monthly `DETACH` + `DROP` removes exactly one month and no decision rows |
| V9 | Crypto-shred | After key destruction, a restored backup cannot decrypt the affected payload |
| V10 | Export completeness | An export round-trips: findings, decisions, evidence references and audit chain, verifiable independently of SDIP |
| V11 | Legal hold | A hold suspends D1–D3 and produces an audited record; D4 still executes |

V4 and V9 are the two that turn §3.3 and §4.3 from claims into properties. V10 is the one that makes G1 and G10 real: an export that only SDIP can read is not customer custody.

---

## 8. Open items

| # | Item | Blocks | Owner |
|---|---|---|---|
| RT-1 | Confirm current provider retention windows and ZDR eligibility from each DPA directly | G4, and any written commitment | security |
| RT-2 | Legal review of the 7-year decision/audit term against the target markets' limitation periods | The DPA template | founder |
| RT-3 | Decide whether tenant offboarding hard-deletes or exports-then-deletes by default | D2 mechanics; likely a contract-tier question | product |
| RT-4 | Measure HNSW index maintenance cost after bulk `subject_id` deletion | Whether §3.1 step 5 needs a scheduled rebuild or can be incremental | platform |
| RT-5 | Resolve **ADR-0017**; until then G11 is "no" and must stay "no" in every document and every sales conversation | The cross-tenant learning narrative | founder |
| RT-6 | Confirm whether any target customer requires per-row crypto-shredding, which would force per-tenant databases (backlog C6) | Enterprise tier design | product |
