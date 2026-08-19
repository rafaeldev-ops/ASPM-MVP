# phase0 — validation instruments

**Not product code.** Never imported by `app/`. Deleted or promoted after the V1 gate.

Every file: **one file, standard library only, no install step.** An instrument that
needs a virtualenv is an instrument that does not get run — and two of these are
meant to run on a design partner's laptop, not ours.

| Instrument | What it does | Try it |
|---|---|---|
| `v1_backtest.py` | **The partner runs this.** Reads their closed-findings export, reports decision debt against CISA KEV. One network call, one local HTML file, nothing uploaded | `--demo` |
| `v2_riskmodel.py` | `risk-model.md` executed: decision points, urgency tree, ordering score, counterfactual | `--assert` · `--fixture` · `--diff` · `--corpus` · `--selftest` |
| `v4_corpus.py` | Builds **and validates** the 50-finding annotation corpus. Refuses to emit if a stratum's property does not hold | `--check` · `--offline` |
| `v4_kappa.py` | Fleiss κ with bootstrap CI for the agreement probe | `--demo` |

## CI gates

    python v2_riskmodel.py --assert      # tree total · no dead rows · no active→deprioritize
    python v2_riskmodel.py --selftest    # the worked examples in risk-model.md §11
    python v4_corpus.py --check          # stratum assertions · rule ids verified upstream

## Why these exist at all

Each was written to execute a document, and each found a defect that prose review
had not:

- `v4_corpus.py` rejected two non-KEV findings in a KEV-only stratum, and Maven
  packages placed on Node services.
- `v4_kappa.py` found gate eligibility resting on shared ignorance — three
  annotators agreeing they cannot tell counts as agreement under raw κ.
- `v2_riskmodel.py` found the published decision tree does not terminate, and
  contains a rule that can never fire.

**A specification that has never been executed is a draft, however carefully it was
reviewed.** See `docs/evaluation/exp-001…` and `exp-002…`.
