# ADR-0009 — Typed evidence contract; retrieval is mostly a join

**Status:** Accepted
**Date:** 2026-08-14
**Source:** `critique-ai-rag.md` §1, §2
**Depends on:** ADR-0007

---

## Context

CLAUDE.md §11 shows six parallel retrieval branches converging on a box labelled "Evidence Ranking," then "Context Compression," then the Decision Engine. §12 requires "reranking" without saying rerank by what. The retrieval policy is a six-entry preference ordering with no weights and no tie-break.

An ordering preference is not a fusion function. Applied literally, "prefer high-authority, then fresh, then organization-specific" means a stale NVD record always outranks a fresh internal decision — the opposite of the product thesis.

## Problem

**The Context Engine is framed as a retrieval problem when it is mostly a join problem.** Enumerate what an SCA decision actually needs: CVE record (join on `cve_id`), EPSS (join), KEV membership (join), version-range applicability (deterministic comparison), service criticality (join), owner (join), prior decisions on the same rule+repo (join, ordered by recency), reachability (computed), compensating controls (join), vendor advisory nuance (**semantic**), similar-but-not-identical past decisions (**semantic**).

**Nine of eleven are joins or computations. Two need embeddings.**

Framing this as RAG produces: top-k retrieval where a typed slot-filler is correct (so evidence is *ranked* when it should be *required* — a decision missing its KEV lookup should be an error, not a low-ranked chunk); retrieval metrics (nDCG, MRR) that are unmeasurable because there is no per-query relevance ground truth; and a latency and cost profile dominated by an embedding round-trip most evidence never needed.

## Decision

### Stage A — Evidence Contract (deterministic)

Each finding class (SAST / SCA / secrets / container) declares a **required slot set** and an **optional slot set**. Slots are filled by keyed lookup. **A required slot that cannot be filled produces a typed `evidence_gap` record, not silence.** `evidence_gap` is a first-class input to confidence (ADR-0010) and a **hard blocker for auto-deprioritize**.

### Stage B — Semantic fill (narrow)

Only the two free-text slots. Hybrid pgvector + Postgres FTS, fused with **Reciprocal Rank Fusion (k=60)**, top-8 per slot, **hard-filtered by `org_id` and `as_of` before ranking, never after**.

Postgres FTS caveat: the default English stemmer mangles `CVE-2024-1234`, `com.fasterxml.jackson.core:jackson-databind`, `python.lang.security.audit.*`. Use a `simple` configuration plus `pg_trgm` indexes on identifier-shaped fields.

### Budget and drop log

- **Fixed evidence budget in tokens** (start 8,000) with **per-slot quotas**, so one chatty advisory cannot crowd out the KEV lookup.
- **Every dropped evidence id is persisted** with its slot, score and reason (`over_budget` / `below_threshold` / `stale` / `duplicate`). Without this, "was the decisive evidence dropped before the model saw it?" is unanswerable and every retrieval regression is misattributed to the prompt.

### Compression is extractive, never abstractive

An LLM summarizing evidence before another LLM reasons over it is a second hallucination surface directly upstream of the decision, and it breaks the content-hash provenance chain. It is also an injectable model call whose output is then presented downstream as trusted, SDIP-generated content. Compress by field selection and truncation with explicit markers.

### Contradiction: a deterministic rule table, not an NLI model

Contradictions in this domain are overwhelmingly **structured field conflicts**: vendor says not-affected while NVD says affected; CVSS 9.8 with EPSS 0.0003; KEV-listed but reachability says unreachable; scanner A says fixed-in 2.4.1 while scanner B still reports on 2.4.3; asset registry says internal-only while deployment shows a public ingress.

~20 versioned rules cover the large majority, at zero inference cost with perfect explainability. Each emits a typed `conflict` record with both evidence ids and a rule id.

**Dense retrieval cannot find contradictions anyway** — embedding models are documented as insensitive to negation, so a query for "evidence that X is *not* exploitable" retrieves substantially the same neighbourhood as its opposite. Negation-based query expansion is a hope, not a mechanism.

**A detected contradiction never flips a decision.** It adjusts confidence and appears in the evidence record.

### Deferred, with explicit triggers

| Deferred | Trigger to revisit |
|---|---|
| Cross-encoder reranker (~220 ms, ~$2/1k searches) | Slot-B semantic precision proven the binding constraint on decision accuracy |
| NLI contradiction model | Rule-table recall measured inadequate **and** ≥300 labelled conflict pairs exist to measure precision against (gate at ≥0.85 precision) |
| Learned reranker (LambdaMART) | ≥5,000 labelled evidence-relevance judgments |
| Abstractive compression | Extractive proven to be the binding constraint |

The reranker is the wrong task, not merely premature: a general reranker scores *topical relevance to a query*, and "is this exploitable in our environment" is not a query semantic similarity answers. A miscalibrated NLI detector is worse than none — at 30–40% false contradictions it routes a large fraction of findings to human review, destroying the north-star metric.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Vector-first RAG over all evidence (CLAUDE.md §11 as read) | Ranks what should be required; unmeasurable; pays an embedding round-trip for joins |
| RRF over everything | Rank-only — structurally discards the reliability, authority and freshness scores §8 mandates |
| Weighted score fusion | Requires per-source normalization that is unstable across corpora; weights have no principled source until labels exist |
| Retrieve everything, let the model sort it out | Unbounded cost, and the model's attention is the scarcest resource in the pipeline |

## Consequences

- Evidence slots per finding class become a versioned artifact reviewed like a schema.
- `evidence_gap` makes incompleteness visible instead of silently degrading decisions — and blocks suppression, which is the safe direction.
- The retrieval evaluation set measures slot-fill rate and gap rate, not nDCG.
- Selective embedding follows (ADR-0014): embed decisions, rationales and advisory prose — not findings, whose text is templated and near-duplicate.

## Reversal strategy

Cheap. Slots, budgets and rules are configuration and code. The one thing that would be expensive to add later is the **drop log**, because absent records cannot be reconstructed — add it from the first decision.

## Verification

- A bake-off before implementation: 200 real findings, evidence assembled twice (deterministic slots vs top-k semantic), analysts judge sufficiency. If deterministic wins or ties, the RAG framing is wrong and this ADR is confirmed empirically.
- A test asserting a missing required slot produces `evidence_gap` and blocks auto-deprioritize.
- A leakage test injecting a future-dated decision and asserting it is not retrieved (`as_of` enforced **in the query**).
- Per-tenant retrieval recall measured per tenant-size class.
