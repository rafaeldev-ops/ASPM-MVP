# ADR-0004 — SARIF for SAST, native JSON for SCA; `codeFlows` preserved structurally

**Status:** Accepted
**Date:** 2026-08-14
**Source:** `critique-architecture.md` §5.1, §5.2
**Contradicts:** the natural reading of CLAUDE.md §24 ("all integrations map into a canonical finding model")

---

## Context

The obvious plan is one canonical pipeline: everything becomes SARIF, SARIF becomes the canonical finding. SARIF 2.1.0 + Errata 01 is the OASIS standard and gives a great deal for free — tool driver and version, the full rules catalogue, `ruleId`, `level`, physical locations with snippets, existing in-tool `suppressions`, and `versionControlProvenance`.

## Problem

**SARIF has no representation for purl, fixed-version, or dependency path (direct vs transitive, and which path).** Those three fields are the entire basis of an SCA decision. A one-canonical-SARIF-pipeline plan silently discards the dependency graph.

Three further losses, each concrete:

1. **`codeFlows` is the most valuable evidence and the most commonly discarded.** SARIF encodes a taint trace as ordered, nested `threadFlows`. There is no clean single-row relational form, so aggregators flatten to the primary location and drop it. But "is this reachable from untrusted input, and by what path" is exactly the evidence that makes a SAST triage decision defensible.
2. **Severity is a lossy enum cast.** SARIF `level` has four values; Trivy natively speaks CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN and loses ordinality on the way in.
3. **CVSS has no home in SARIF.** Trivy carries per-source scores (NVD, Red Hat, GHSA) that routinely disagree by 2+ points on the same CVE.

Separately: of the CLAUDE.md §5 MVP tool list, **two of three ship no usable fingerprint** — Trivy emits no `partialFingerprints` (open feature request), Gitleaks is thin. Only CodeQL's `primaryLocationLineHash` is best-in-class. "Just use SARIF fingerprints" is not an available plan.

## Decision

1. **Ingest SAST (Semgrep, CodeQL) via SARIF 2.1.0 + Errata 01. Ingest SCA and container (Trivy, Snyk) via native JSON.** Two adapters, one canonical attribute model. Do not build against SARIF 2.2 — `partialFingerprints` semantics are still under TC discussion.
2. **Preserve `codeFlows` structurally** as `evidence_code_flow` / `evidence_code_flow_step` rows — not as an opaque JSON blob. Evidence that cannot be ranked or cited is not evidence, and flattening it makes the "evidence-first" positioning hollow for the entire SAST class.
3. **Store `severity_raw` (verbatim), `severity_normalized`, and `severity_mapping_version`** so a mapping change is detectable rather than a silent rewrite of history.
4. **Store CVSS as `(source, vector, score)` triples.** A single `cvss_score` column is an unattributed editorial decision.
5. **Compute identity ourselves** (ADR-0001's versioned fingerprint), consuming tool fingerprints as one input where available. Never put a raw line number in the identity hash; normalize whitespace before hashing; follow renames using git rename detection; use package-coordinate identity for SCA, not file paths.
6. **Round-trip in-tool suppressions.** `results[].suppressions` means a developer already dismissed this in Semgrep or GitHub. Re-surfacing it as new is an instant, unrecoverable trust loss with the exact user this product targets.
7. **Multi-location results are one finding with N locations.** Never fan out (inflates every metric) and never flatten to the first (drops evidence).

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Single SARIF pipeline for everything | Discards purl, fixed-version and dependency path — the whole SCA decision basis |
| Native JSON for everything | Loses SARIF's free rules catalogue, provenance and suppressions for SAST; multiplies adapter work per tool |
| Canonical model with a generic `extra` JSONB and no structure | "Store it in JSONB" is how `codeFlows` becomes unqueryable and un-citable |
| Borrow DefectDojo's parsers wholesale | Attractive and license-compatible (BSD-3) — revisit for breadth *after* the two-format core exists. Not a substitute for deciding the model |

## Consequences

- Two adapter families to maintain rather than one. Accepted: the alternative is silently correct-looking data.
- The canonical attribute list from CLAUDE.md §24 is kept, but it is the *shape of observation attributes* (ADR-0001), not a table.
- Parsers handle attacker-influenced files and are therefore untrusted-input parsers: they must be fuzzed (ADR-0011), size-capped and streamed (ADR-0005).
- Reachability verdicts emitted by Semgrep/Endor are ingested as **first-class evidence with high reliability**, not competed with — they are the highest-precision input to the deterministic pre-filter (ADR-0008).

## Reversal strategy

Cheap. Adapters are leaf components writing into a stable observation schema. Adding, replacing or re-running an adapter re-parses stored raw payloads (retained per ADR-0011's retention rules) into new observations. The one thing that is *not* cheap to reverse is discarding `codeFlows` — that data is gone if never stored.

## Verification

- Golden fixtures per tool: a SARIF from Semgrep and CodeQL, native JSON from Trivy and Snyk, with expected canonical output committed.
- A test asserting a multi-location secret produces one finding with N locations.
- A test asserting an in-tool suppression is imported as suppressed, not new.
- Fuzz targets for every parser.
