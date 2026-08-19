# ADR-0015 — One provider, one adapter; benchmark on the criteria that actually bind

**Status:** Accepted
**Date:** 2026-08-14
**Source:** `critique-ai-rag.md` §9; `critique-architecture.md` §13; `critique-product.md` §10

---

## Context

CLAUDE.md §13 requires an AI provider abstraction and lists six candidate providers, while warning that the abstraction must not become an excuse for premature multi-vendor support. §14 defers multi-agent architectures pending measured improvement.

## Problem

**The abstraction leaks in exactly the places that matter.** Sampling parameters, logprob availability, refusal behaviour, structured-output constraints, prompt-cache minimums and data-retention terms differ materially between vendors and are not abstractable:

- `temperature` / `top_p` / `top_k` are **removed** on the current frontier Claude models — sending them returns 400. Any ensemble design that assumes temperature sampling does not run at all.
- The Messages API exposes **no logprobs**. Any calibration design depending on token probabilities is unavailable.
- Structured outputs enforce the schema but support **no `minimum`/`maximum`/`multipleOf`, no string-length constraints, no recursive schemas** — so a numeric field cannot be schema-constrained to [0,1], and application-side validation is mandatory regardless of provider. They are also **incompatible with citations** (400), so provenance must be our own evidence-id validation.
- **Refusals are a first-class operational event here.** Cybersecurity safety classifiers can return **HTTP 200 with `stop_reason: "refusal"`**. For a product whose entire input corpus is vulnerability descriptions and exploit references, this is a recurring production event, not an edge case.
- **Data retention differs and is contractual.** At least one high-end model requires 30-day retention and is unavailable under zero-data-retention — and the enterprise SKU that pays the bills requires ZDR.

## Decision

1. **One provider, one thin adapter, one fallback.** Not six. The adapter's job is transport, retries, timeouts and telemetry — not pretending vendors are interchangeable.
2. **Benchmark before choosing, on the full criteria set.** CLAUDE.md §13's list (accuracy, adherence, hallucination, structured-output reliability, latency, cost, privacy, context) plus five it omits:
   - **refusal rate on our own corpus** — may be the criterion that decides the provider;
   - **ZDR availability** — a model the paying segment cannot use must not win;
   - **structured-output constraint expressiveness**;
   - **logprob availability**, if any calibration design depends on it;
   - **sampling-parameter availability**, if any ensemble design depends on it.
3. **Tiered routing, not a single model.** High-volume structured classification over pre-assembled evidence is a mid-tier task. Reserve a frontier model for a low-volume escalation route (`needs_review` adjudication, correlation ambiguity, conflicting-evidence synthesis) behind an explicit router. **If more than ~5% of findings take that route, the deterministic layer is under-built** (ADR-0008).
4. **`effort` / thinking configuration is explicit, versioned per route, and swept on the golden set.** Adaptive thinking is on by default on the current generation and thinking tokens bill as output — 1,000–3,000 thinking tokens per decision is more than the entire naive per-finding cost estimate. Leaving it at the default is a silent doubling.
5. **Byte-stable cacheable prefix.** Prompt caching only amortizes the shared prefix, which forbids interpolating the current date, tenant name or request id into the system prompt. That is an architectural constraint on the prompt builder, not a tuning knob — and it coincides with ADR-0007's rule that the system prompt is never assembled from database content.
6. **Refusal and provider failure fail closed to `needs_review`.** Never `deprioritize`. Any code path reading `content[0]` unconditionally breaks; check `stop_reason` first. Where a server-side fallback parameter exists, use it and log every fallback event as an observability metric.
7. **Operator instructions delivered as mid-conversation system-role messages** where supported — a non-spoofable operator channel, unlike instruction text in a user turn that untrusted content can imitate.
8. **Avoid per-tenant schema variation.** A new schema pays a one-time compilation cost cached ~24 hours; per-tenant schemas pay it repeatedly.
9. **No multi-agent pipeline.** Stage 2/3 of CLAUDE.md §14 requires beating both the single-model baseline **and** the deterministic-only ablation on the frozen golden set, at acceptable cost and latency. Excessive Agency is the fastest-climbing entry on the 2026 LLM risk list precisely because deployments granted agency by default.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Six-provider abstraction (CLAUDE.md §13's list) | Costs a month, leaks anyway on the five capability axes above |
| Pick the most popular model and move on | CLAUDE.md §13 forbids it, correctly. Refusal rate and ZDR may dominate accuracy here |
| Single model for everything | Wastes frontier pricing on classification, or under-serves adjudication |
| Self-hosted open-weight model in MVP | Adds inference operations to a pre-MVP team; revisit for the private-deployment SKU when a customer pays for it |
| Multi-agent critic pipeline now | Unmeasured benefit, measurable cost, and it adds agency to a decision path before the containment controls are proven |

## Consequences

- Provider choice is a benchmark output, not an architecture input. The benchmark harness is therefore a Phase 0 deliverable, not a Phase 1 one.
- The enterprise SKU constrains the model set. Benchmark accordingly rather than discovering it during a security review.
- Refusal handling, fallback events and cost per decision all join the observability set alongside model, prompt version, retrieval config version, scoring version and evidence ids.

## Reversal strategy

Cheap by design. A thin adapter with a benchmark harness makes provider switching a re-benchmark plus a config change. The expensive mistake is the opposite one: building a deep abstraction that encodes assumptions (temperature, logprobs) which the chosen vendor does not support.

## Verification

- A refusal fixture asserting a fail-closed route to `needs_review` and a logged metric.
- A test asserting the cacheable prefix is byte-stable across requests and tenants.
- A structured-output validation test asserting out-of-range numerics are rejected application-side.
- An `effort` sweep on the golden set recorded as a versioned benchmark artifact.
