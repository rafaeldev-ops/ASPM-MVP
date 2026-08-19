# ADR-0012 — Audit integrity and the decision record that survives a deposition

**Status:** Accepted
**Date:** 2026-08-14
**Source:** `critique-security.md` §5
**Depends on:** ADR-0007, ADR-0011

---

## Context

CLAUDE.md §43 lists "audit-log tampering" as a bullet. That is not a design.

The scenario to design against: a customer is breached through CVE-X. Forensics establishes the vulnerable component was present for 11 months. Discovery produces SDIP's decision log showing SDIP deprioritized CVE-X on day 4 with `confidence: 0.91`. That log becomes the central exhibit in a negligence claim, an insurer's coverage dispute, and possibly a regulatory proceeding.

Two questions decide the outcome: **is the log trustworthy**, and **does it show what was knowable at the time**.

## Decision

### 1. Integrity, in cost order

1. **Append-only at the schema level.** The application role holds `INSERT` and `SELECT` only — no `UPDATE`, `DELETE` or `TRUNCATE` on audit tables. Revoked at the grant level, not in the ORM.
2. **Per-record hash chain:** `record_hash = H(prev_hash ‖ canonical_serialization(record))`. Canonical serialization is specified explicitly (sorted keys, fixed encoding, explicit null handling) or the chain is unverifiable across library versions.
3. **External anchoring — the load-bearing part.** A hash chain is worth nothing against an attacker who owns the database, because they recompute the chain. Publish a periodic Merkle root to somewhere SDIP cannot rewrite: an RFC 3161 timestamp authority, and/or a customer-controlled bucket the service account can write to but not delete from. **Without an external anchor, "immutable audit log" is marketing.**
4. **WORM export** to object storage with Object Lock in compliance mode.
5. **Signing separated from the app** (KMS/HSM), with a policy preventing backdating. If the API process can produce a valid signature for an arbitrary timestamp, the signature proves nothing.
6. **Clock discipline:** record both server time and TSA time; monitored NTP.

### 2. The decision record

CLAUDE.md §7's contract is nowhere near sufficient. Required:

```
decision_id, decision_version, tenant_id
finding_id, finding_content_hash

deterministic_assessment { score, feature_vector, scoring_model_version, severity_floor }
model_recommendation      { validated structured output, verbatim }
policy_decision           { decision, policy_version, predicates_satisfied[],
                            suppression_authorized_by, non_suppressible_reason }

evidence_set[]            { evidence_id, content_hash, trust_tier, source_id,
                            snapshot_id, retrieved_at }
evidence_availability     { kev_status_at_decision_time, epss_at_decision_time,
                            epss_model_version, advisory_versions_seen[],
                            what_did_NOT_exist_yet }
evidence_dropped[]        { evidence_id, slot, score, reason }        -- ADR-0009
untrusted_content         { segment_count, bytes, injection_detector_verdict,
                            detector_version }
redaction_tier            { no_code | scrubbed | full_optin }         -- ADR-0011
review_propensity                                                      -- ADR-0010
provider                  { vendor, model_id, params_hash, zdr_enabled, inference_geo }
prompt_template_version, prompt_template_hash, retrieval_config_version
reproducibility           { prompt_hash, context_manifest_hash }
actor                     { type: system|analyst, subject, auth_method, reason_code }
audit                     { prev_hash, record_hash, merkle_root_id, tsa_token }
```

> **`evidence_availability` is the field that saves the customer.** "CVE-X was not in KEV until day 197; EPSS was 0.008 on day 4" turns a hindsight-negligence narrative into a documented, reasonable decision. A log that records only the conclusion is a liability; a log that records the epistemic state is a defence.

Competitive note: this field is unoccupied. Nucleus and ArmorCode both say "defensible" about *prioritization*; neither ships a record designed to be read by an incident reviewer.

### 3. Reproducibility is a test, not an aspiration

Given a decision record, the system must be able to re-render the exact prompt and re-run the deterministic engine. **If it cannot, the log is a narrative, not evidence.** Automate this as a test.

### 4. Audit immutability vs secret deletion

You cannot have both "append-only forever" and "we can delete a leaked secret." Resolution: **hash-chain over references, not over content.** The audit record stores content *hashes* plus pointers into a separately-retained, deletable payload store. Deleting the payload does not break the chain — you retain provable existence and gain provable deletion, and can state exactly when it occurred. Adopt before writing the audit schema; retrofitting is a migration across immutable data.

### 5. Split retention

| Class | Retention |
|---|---|
| Audit / decision records | **Long — 7 years** (breaches are discovered 12–24 months later) |
| Findings / observations | Medium, partitioned by month |
| Raw payloads | **Shortest** (ADR-0011) |

CLAUDE.md §44 treats retention as one policy. It is three, and they must be reconciled with the WAL/PITR window — "deleted" means something different during that window and the DPA must say so.

### 6. Liability posture, enforced in the product

- **Fully automatic suppression is not a default.** It is an explicit per-tenant opt-in whose enablement is a signed, audited configuration change naming the human who enabled it.
- **Give the customer custody of their own evidence:** continuous verifiable export of the decision log into customer-controlled storage. The customer, not SDIP, is then the custodian in any proceeding — which reduces SDIP's discovery exposure, improves the customer's position, and is a differentiated feature to sell.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Hash chain without external anchoring | Worthless against an attacker who owns the database |
| Blockchain | The requirement is a trusted timestamp and a root nobody can rewrite. A TSA plus a customer-controlled bucket delivers that without operating a chain |
| Hash the full record content | Makes secret deletion impossible without breaking the chain |
| Single retention policy (CLAUDE.md §44) | Audit must outlive findings; raw payloads must not |
| Log only the decision | The liability version of the same log |

## Consequences

- The audit schema must be right on the first migration; changing a canonical serialization later invalidates every prior verification.
- `evidence_availability` requires that "what we knew then" be reconstructible — which requires ADR-0001's observation history and ADR-0013's snapshots. Three ADRs converge on this one field.
- Continuous customer export is real engineering (streaming, verification tooling) and should be scoped as a feature, not a background job.

## Reversal strategy

None in practice. Retrofitting integrity onto historical records produces a log whose early period cannot be verified — which an opposing expert will point out. Build it into migration #1.

## Verification

- A tamper test: modify a record directly in the database and assert chain verification fails at that record.
- A reproducibility test: replay a stored decision record and assert an identical prompt hash and deterministic score.
- An anchoring test: verify a published Merkle root against an independently retained copy.
- A deletion test: delete a payload and assert the chain still verifies.
