# ADR-0018 — Local-first provider selection: egress topology is the user's choice, not the vendor's

**Status:** Accepted
**Date:** 2026-08-24
**Amends:** ADR-0015 §1 (does not supersede it)
**Constrained by:** ADR-0007 (decision authority), ADR-0009 (evidence contract), ADR-0010 (confidence), ADR-0011 (redaction boundary), ADR-0012 (audit integrity)
**Source:** the Pride Security Desktop brief; `docs/product/mvp-aspm.md`; `mvp-backlog.md` §2.5

---

## Context

The product is becoming a desktop application that a user installs on their own laptop.
That changes who holds the question *"is it acceptable for this data to leave this
machine?"* — from us, once, at architecture time, to the user, per install and per
analysis.

`mvp-backlog.md` §2.5 lists **"Multi-provider LLM abstraction"** in the WON'T table,
trigger *"Never as briefed; one adapter, one fallback."* ADR-0015 §1 states it directly:
*"One provider, one thin adapter, one fallback. Not six."*

Taken at face value, this ADR reverses an Accepted decision. It does not, and the
distinction is the whole point of writing this down.

## Problem

**ADR-0015 answers a different question.** It rejects *vendor optionality* — six
adapters so a procurement conversation goes more smoothly, bought with a month of
engineering and an abstraction that leaks on five capability axes that genuinely are
not abstractable: sampling parameters, logprobs, structured-output expressiveness,
refusal behaviour, and retention terms.

Every one of those reasons remains true and none of them is contradicted here.

What this ADR decides is *egress topology*: one local runtime and one cloud vendor,
which are not two interchangeable suppliers but **two answers to a different question** —
does the finding data leave the machine. On a product that ships to a security
engineer's laptop and asks for their organisation's vulnerability history, that is a
product requirement and a security control, not a supplier hedge.

There is also a concrete defect that this decision must be designed around.
`app/interfaces/routes.py:204` calls the AI provider **inside the GET handler** for
`/aspm/findings/{id}`. That is harmless today because only a null provider exists. The
moment a cloud provider becomes selectable, every page view ships finding data to a
third party on an idempotent GET — no consent, no record, and a browser refresh
multiplies it. The architecture must make that shape impossible, not merely fix the line.

## Decision

### 1. Three providers, and the cap is enforced by a test

The registry contains exactly `null`, `ollama`, `openai`. A test asserts the count and
the names. Intent is not a mechanism; a test is. Adding a fourth requires editing this
ADR and that test in the same change, which is precisely the friction ADR-0015 was
protecting.

The shared surface stays deliberately thin — transport, retries, timeouts, telemetry,
and one validated output contract. **No layer pretends the providers are equivalent.**
Each adapter owns its own quirks, and where behaviour differs it differs visibly rather
than being smoothed into a false common denominator.

### 2. Analysis is an explicitly consented POST, never a side effect of rendering

No render path may invoke a provider. The finding page keeps its deterministic synthesis,
which performs no I/O and is always available. Model analysis happens only through an
explicit POST, behind a pre-flight screen that discloses the egress class **before** the
call and shows the actual redacted payload rather than a description of it.

Consent is per analysis. A "don't ask again this session" affordance is permitted for
local and none, and **never** for third-party egress.

### 3. Egress class replaces the `is_external` boolean

```
NONE        no I/O at all
LOCALHOST   loopback only; never leaves the machine
THIRD_PARTY leaves the machine, to a vendor
```

`is_external` survives as a derived property so the existing API contract and
`tests/test_api.py:143` keep working, and keep meaning what they say.

**`LOCALHOST` is verified, not declared.** The local adapter resolves its configured
host and refuses to send unless every resolved address is loopback. The badge the user
sees is a checked property. Two consequences follow: Ollama Cloud is structurally
excluded, and the adapter must build its HTTP opener with an empty proxy handler —
otherwise `HTTP_PROXY` would route a "127.0.0.1" request through a corporate proxy, off
the machine, while the interface displays `local`.

### 4. The ADR-0011 redaction boundary is instantiated one layer down

ADR-0011 put a type between the scanner payload and the system:
`RawScannerPayload → redact() → RedactedFinding`. The same shape now guards the way out:

```
FindingContext → redact(egress, tier) → RedactedContext
```

`RedactedContext` is the only type a provider accepts. `analyze()` is a final template
method on the base class that performs the check; adapters implement `_call` and never
`analyze`. Forgetting the gate requires editing the base class.

**ADR-0011 enforces its boundary with MyPy strict. This repository has no MyPy, no lint
and no CI.** Saying otherwise would be claiming a control we do not have. The substitute
is structural and runtime: `FindingContext` is non-serializable by construction, the
template method is final, and tests assert both — including a reflection test that no
registered provider defines `analyze` in its own `__dict__`.

### 5. `raw_json` is out of bounds at every tier, for every provider, including local

`Finding.raw_json` holds the entire original scanner row, up to 200 KB. It is the
highest-density secret carrier in the database and precisely the "adjacent secret" case
of ADR-0011 §2. No AI code path reads it, at any tier, for any provider. A canary test
enforces it.

`no_code` remains the only tier, as ADR-0011 §3 requires. Local egress earns one bounded
relaxation — file basenames, which are genuinely useful for SAST triage and cannot leave
the machine. It earns nothing else, and it does not earn `raw_json`.

Where the detector fires and egress is third-party, the call **fails closed** rather than
shipping a partially scrubbed payload. ADR-0011's reversal logic is the argument:
loosening later is easy; a secret sent to a provider cannot be recalled.

### 6. `confidence` stays deterministic

The desktop brief asks for `confidence` in the model's output contract. ADR-0007 §2 says
*"Deterministic + calibrator. Remove from the model's schema."* ADR-0010 §1 is titled
*"The model never emits confidence or score."*

**Those ADRs win.** The field exists because the interface needs it, and it is computed
from evidence completeness — slots filled, source authority, freshness, minus conflicts,
minus unresolved asset criticality, minus synthetic provenance. It is versioned, and it
is rendered as a band with its inputs visible rather than as a bare number (ADR-0010 §2).

For the same reason, `provider`, `model` and timestamps stay **out** of the JSON schema.
A record in which the model self-reported its own identity is worthless as an audit
artifact.

### 7. Schema versioning is an in-code runner, not Alembic

`CLAUDE.md` §21 names Alembic. This deviates, for a reason that is specific and
forward-looking: Alembic discovers revision scripts by filesystem path at runtime, and
in a frozen desktop build that directory lands under the extraction root, breaking
`script_location`. A `schema_version` table plus ordered migration functions in an
ordinary module has zero dependencies and freezes without special handling.

**The escape hatch is named so this is not a one-way door:** if branching migrations or
PostgreSQL arrive, Alembic is adopted by stamping `alembic_version` from `schema_version`.

### 8. The prompt-injection surface stops being zero

`docs/PROJECT_STATE.md` currently records *"prompt injection surface: zero today — there
is no LLM in the path."* That sentence becomes false with the first model, and must be
updated rather than left standing.

Containment shipping now: the model holds no tools, initiates no network calls, writes
no memory, and cannot alter a band, a score or a finding's state. Evidence ids are
validated against what the model was actually given. Untrusted content travels in a
delimited data-only block declared as untrusted. Output is escaped, never marked safe,
never placed in an `href` or `src`, and **not rendered as Markdown** — remote image
loading is the zero-click exfiltration channel ADR-0007 names.

**Deliberately not shipping: an injection detector.** ADR-0007 §3 says a detector is not
a control, and a partial one invites trust it has not earned.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Honour the WON'T entry literally; ship one cloud provider only | Defeats the product. A local-first desktop whose only inference path is a third party is local-first in name |
| Local provider only, no cloud at all | Defensible and genuinely tempting. Rejected because a user with no capable local hardware is left with the deterministic engine alone, and the brief asks for all three modes to be legitimate |
| Six providers, as `CLAUDE.md` §13 briefs | Exactly what ADR-0015 measured the cost of. Nothing has changed about that analysis |
| Keep `is_external` and call Ollama "external" | Factually wrong and destroys the one property the local mode is sold on |
| Keep `is_external` and call Ollama "internal" | True about the machine, false about the process, and a boolean cannot carry the distinction the user is actually buying |
| Model-emitted confidence, as briefed | Reverses two Accepted ADRs to obtain a number that is known to be uncalibrated |
| Adopt Alembic now | The stack document's choice, but its runtime script discovery is the one mechanism that does not survive freezing — and freezing is the whole point of the next phase |

## Consequences

- **`mvp-backlog.md` §2.5 must record that this trigger fired, and why**, with the
  original wording left visible. A rejected item silently reversed is worse than one
  never written down.
- The refusal rate that ADR-0015 §2 says *"may be the criterion that decides the
  provider"* becomes measurable per install, because failed analyses are persisted, not
  only successful ones. A design that records only successes destroys that metric.
- Every analysis record carries the egress class and the effective tier, so a user can
  prove what left their machine on a given date — ADR-0011 §3's compliance property,
  at desktop scale.
- The user, not us, now benchmarks. The Settings screen reports outcomes and latency per
  provider over 30 days, which is ADR-0015 §2's benchmark requirement scaled down to one
  person's corpus.
- Two adapters is the ceiling this ADR buys. The next one is a new decision, not an
  increment.

## Reversal strategy

Cheap in one direction, expensive in the other — as with ADR-0011, and for the same
reason. Removing the cloud adapter is deleting a registry entry and a file; the local
adapter and the deterministic engine keep the product whole. Loosening the redaction
tier, or admitting a third provider, is a new ADR.

The irreversible part is not the code. It is any data already sent to a third party.
That is why consent is per analysis, why the pre-flight screen shows the real payload,
and why a detector hit blocks rather than scrubs.

## Verification

- A test asserting the registry holds exactly three providers, by name.
- A test asserting no render path calls a provider — with an `unavailable`-raising
  monkeypatch, a full finding-page render must still succeed.
- A test asserting `analyze()` rejects an unsanitized `FindingContext` with `TypeError`,
  and one asserting `json.dumps` of a `FindingContext` raises.
- A reflection test asserting no provider overrides `analyze`.
- A `raw_json` canary absent from the payload, the persisted record, and any `str()`.
- A planted-credential canary: with third-party egress configured against a local
  capture server, the request count must be **zero** and the outcome `blocked_redaction`.
- The local adapter refuses a non-loopback host, and ignores `HTTP_PROXY` — proven by
  pointing the proxy at one fake server and the adapter at another.
- No outcome, including success, changes a finding's band, ordering score or risk-model
  version.
- A hallucinated evidence id rejects the whole response; so does an id that exists in the
  database but was dropped from the context before the model saw it.
- The detector produces **zero** hits on a realistic KEV + EPSS evidence set. A control
  that fires on ordinary data gets switched off, and a switched-off control is worse than
  none.
