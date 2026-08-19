#!/usr/bin/env python3
"""
V4 agreement probe -- analysis.

Computes Fleiss' kappa for the holistic form, for the decision DERIVED from each
annotator's own sub-question answers, and for each sub-question individually.

See docs/evaluation/v4-annotation-kit.md. The comparison that answers the
experiment's question is kappa_holistic vs kappa_derived: same 3-category output
space, same findings, same raters -- the only difference is the route the
annotator took. Per-sub-question kappa is a secondary output whose job is to
decide which sub-questions are eligible to be a release gate (>= 0.6).

Standard library only. No install step. Same constraint as the V1 backtest, and
for the same reason: an instrument that needs a virtualenv is an instrument that
does not get run.

    python v4_kappa.py annotations.csv
    python v4_kappa.py --demo          # dry-run the whole pipeline on synthetic data

Input CSV (long format), one row per answer:

    finding_id,annotator,form,question,answer

    form      : "A" (holistic) | "B" (decomposed)
    question  : "holistic" for form A; "Q1".."Q5" for form B
    answer    : form A -> prioritize | deprioritize | needs_review
                form B -> yes | no | unknown
"""

import csv
import random
import sys
from collections import defaultdict, Counter

DECISIONS = ("prioritize", "deprioritize", "needs_review")
SUBQ = ("Q1", "Q2", "Q3", "Q4", "Q5")
SUBQ_ANSWERS = ("yes", "no", "unknown")
BOOTSTRAP_N = 10_000
SEED = 20260816  # fixed so a re-run reproduces the interval exactly

GATE_KAPPA = 0.6  # below this a sub-question is a diagnostic, never a release gate


# --------------------------------------------------------------------------
# The fusion rule. PUBLISHED BEFORE ANNOTATION BEGINS (kit section 6.3).
# Deliberately simpler than risk-model.md's 15-row tree: V4 tests whether
# decomposition raises agreement, not whether the production tree is correct.
# Using the full tree here would confound V4 with V2.
# --------------------------------------------------------------------------
def fuse(a):
    """a: dict Q1..Q5 -> yes|no|unknown. Returns a decision, or None if incomplete."""
    if any(q not in a for q in SUBQ):
        return None
    if a["Q5"] == "no":
        return "deprioritize"          # affected range excludes our version
    if a["Q1"] == "no":
        return "deprioritize"          # not reachable
    if a["Q2"] == "yes" and a["Q3"] == "yes" and a["Q4"] != "yes":
        return "prioritize"            # exposed, exploit exists, unmitigated
    if a["Q1"] == "yes" and a["Q3"] == "yes":
        return "prioritize"
    return "needs_review"


# --------------------------------------------------------------------------
# Fleiss' kappa
# --------------------------------------------------------------------------
def fleiss_kappa(items, categories):
    """
    items: list of lists of category labels (one inner list per item, one label
           per rater). Items whose rater count differs from the modal count are
           dropped and reported by the caller.
    Returns (kappa, n_items, marginals) or (None, n, marginals) when undefined.
    """
    items = [it for it in items if it]
    if not items:
        return None, 0, {}
    n = len(items[0])
    items = [it for it in items if len(it) == n]
    if not items or n < 2:
        return None, len(items), {}

    N = len(items)
    counts = [Counter(it) for it in items]

    # P_i: proportion of rater pairs on item i that agree
    P = []
    for c in counts:
        s = sum(v * v for v in c.values())
        P.append((s - n) / (n * (n - 1)))
    P_bar = sum(P) / N

    marg = {cat: sum(c.get(cat, 0) for c in counts) / (N * n) for cat in categories}
    P_e = sum(p * p for p in marg.values())

    if abs(1 - P_e) < 1e-12:
        return None, N, marg          # everyone chose one category: kappa undefined
    return (P_bar - P_e) / (1 - P_e), N, marg


def bootstrap_ci(items, categories, rng, n=BOOTSTRAP_N):
    """Percentile bootstrap over ITEMS (not raters): findings are the sampling unit."""
    if len(items) < 3:
        return None, None
    ks = []
    for _ in range(n):
        samp = [items[rng.randrange(len(items))] for _ in range(len(items))]
        k, _, _ = fleiss_kappa(samp, categories)
        if k is not None:
            ks.append(k)
    if len(ks) < n * 0.5:
        return None, None             # too many undefined resamples to trust
    ks.sort()
    return ks[int(0.025 * len(ks))], ks[int(0.975 * len(ks))]


def agreement_stats(items):
    """Unanimity, majority agreement, and marginal skew."""
    if not items:
        return 0.0, 0.0, 0.0
    unan = sum(1 for it in items if len(set(it)) == 1) / len(items)
    majo = sum(1 for it in items if Counter(it).most_common(1)[0][1] >= 2) / len(items)
    flat = Counter(x for it in items for x in it)
    skew = max(flat.values()) / sum(flat.values())
    return unan, majo, skew


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------
def report_task(label, items, categories, rng, note=""):
    k, n, marg = fleiss_kappa(items, categories)
    unan, majo, skew = agreement_stats(items)
    lo, hi = bootstrap_ci(items, categories, rng)

    ks = "undefined" if k is None else f"{k:.3f}"
    ci = "" if lo is None else f"  95% CI [{lo:.3f}, {hi:.3f}]"
    print(f"\n{label}")
    print(f"  n items          {n}")
    print(f"  Fleiss kappa     {ks}{ci}")
    print(f"  unanimous        {unan:6.1%}")
    print(f"  majority (>=2)   {majo:6.1%}")
    print(f"  marginal skew    {skew:6.1%}   (largest category share; high skew depresses kappa)")
    dist = ", ".join(f"{c}={marg.get(c,0):.2f}" for c in categories)
    print(f"  marginals        {dist}")
    if note:
        print(f"  {note}")
    return k


def load(path):
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            rows.append({k: (v or "").strip() for k, v in r.items()})
    return rows


def analyse(rows):
    rng = random.Random(SEED)

    holistic = defaultdict(dict)                    # finding -> annotator -> decision
    sub = defaultdict(lambda: defaultdict(dict))    # finding -> annotator -> Qn -> answer

    for r in rows:
        f, a, q, ans = r["finding_id"], r["annotator"], r["question"], r["answer"].lower()
        if r["form"].upper() == "A" or q.lower() == "holistic":
            holistic[f][a] = ans
        elif q.upper() in SUBQ:
            sub[f][a][q.upper()] = ans

    findings = sorted(set(holistic) | set(sub))
    annotators = sorted({a for v in holistic.values() for a in v} |
                        {a for v in sub.values() for a in v})

    print("=" * 72)
    print("V4 AGREEMENT PROBE")
    print("=" * 72)
    print(f"findings {len(findings)}   annotators {len(annotators)}   rows {len(rows)}")
    print(f"bootstrap {BOOTSTRAP_N:,} resamples, seed {SEED}")

    # --- the primary comparison -------------------------------------------
    h_items, d_items, incomplete = [], [], 0
    for f in findings:
        hv = [holistic[f][a] for a in annotators if a in holistic[f]]
        if hv:
            h_items.append(hv)
        dv = []
        for a in annotators:
            if a in sub[f]:
                fused = fuse(sub[f][a])
                if fused is None:
                    incomplete += 1
                else:
                    dv.append(fused)
        if dv:
            d_items.append(dv)

    print("\n" + "-" * 72)
    print("PRIMARY COMPARISON  --  same output space, same findings, same raters")
    print("-" * 72)
    kh = report_task("kappa_holistic   (form A, asked directly)", h_items, DECISIONS, rng)
    kd = report_task("kappa_derived    (form B, fused by the pre-registered rule)",
                     d_items, DECISIONS, rng,
                     note=f"{incomplete} annotator-findings dropped: incomplete sub-question set"
                     if incomplete else "")

    # --- secondary: which sub-questions can gate --------------------------
    print("\n" + "-" * 72)
    print("SECONDARY  --  per sub-question (decides gate eligibility, not the experiment)")
    print("-" * 72)
    sub_k = {}
    for q in SUBQ:
        items, unk_total, unk_all = [], 0, 0
        for f in findings:
            v = [sub[f][a][q] for a in annotators if a in sub[f] and q in sub[f][a]]
            if not v:
                continue
            items.append(v)
            unk_total += sum(1 for x in v if x == "unknown")
            if all(x == "unknown" for x in v):
                unk_all += 1
        if not items:
            continue
        total = sum(len(i) for i in items)
        k = report_task(f"{q}", items, SUBQ_ANSWERS, rng)
        print(f"  unknown rate     {unk_total/total:6.1%}   "
              f"({unk_all} findings where ALL annotators said unknown)")

        # Kappa excluding all-unknown items: three people agreeing they cannot
        # tell is agreement about the EVIDENCE, not about the finding, and it
        # inflates kappa. Gate eligibility uses this figure when it exists --
        # otherwise a sub-question nobody can answer looks like a reliable one.
        sub_k[q] = k
        trimmed = [i for i in items if not all(x == "unknown" for x in i)]
        if unk_all and trimmed:
            kt, nt, _ = fleiss_kappa(trimmed, SUBQ_ANSWERS)
            kts = "undefined" if kt is None else f"{kt:.3f}"
            print(f"  kappa ex-unknown {kts}      (n={nt}; GATE ELIGIBILITY USES THIS)")
            sub_k[q] = kt

    # --- verdict ----------------------------------------------------------
    print("\n" + "=" * 72)
    print("VERDICT  (pre-registered -- docs/evaluation/v4-annotation-kit.md section 1)")
    print("=" * 72)
    if kh is None or kd is None:
        print("  Kappa undefined for at least one form. Check marginal skew above:")
        print("  a degenerate corpus cannot answer this experiment. Re-stratify and re-run.")
    else:
        print(f"  kappa_holistic {kh:.3f}   kappa_derived {kd:.3f}   delta {kd-kh:+.3f}")
        if kh < 0.5 and kd > 0.7:
            print("  -> EXPECTED RESULT. Decomposition becomes the core data model.")
            print("     Rewrite the decision contract around the five sub-questions")
            print("     BEFORE implementation begins.")
        elif kh > 0.7 and kd > 0.7:
            print("  -> Holistic questions are usable. Simplify the annotation protocol")
            print("     and save the cost across every future golden set.")
        elif kh < 0.5 and kd < 0.5:
            print("  -> DANGEROUS RESULT. Neither form is a reliable label source.")
            print("     T2 adjudicated consensus cannot support a release gate, and the")
            print("     false-negative gate must rest entirely on T1 retroactive outcomes.")
        elif kd > kh:
            print("  -> Decomposition helps but is not sufficient. Report the delta and")
            print("     revisit sub-question wording -- not the design.")
        else:
            print("  -> Decomposition did not help. Investigate before concluding:")
            print("     check the unknown rates and the environment brief first.")

    gated = [q for q, k in sub_k.items() if k is not None and k >= GATE_KAPPA]
    barred = [q for q, k in sub_k.items() if k is None or k < GATE_KAPPA]
    print(f"\n  gate-eligible sub-questions (kappa >= {GATE_KAPPA}): "
          f"{', '.join(gated) if gated else 'none'}")
    print(f"  diagnostic only:                        "
          f"{', '.join(barred) if barred else 'none'}")

    print("\n  At n=50 with 3 raters the CI is roughly +/-0.10-0.15. This is a")
    print("  DIRECTIONAL PROBE that picks a data model. Do not quote its kappa as")
    print("  a headline number. Read the free-text answers before reading any of")
    print("  the above -- that is where a sixth sub-question comes from.")


# --------------------------------------------------------------------------
# Demo: dry-run the pipeline before booking 12 annotator-hours
# --------------------------------------------------------------------------
def demo_rows(seed=7):
    """Synthetic data with holistic agreement deliberately worse than decomposed."""
    rng = random.Random(seed)
    ann = ["ann1", "ann2", "ann3"]
    rows = []
    for i in range(50):
        fid = f"F{i+1:03d}"
        truth = rng.choice(DECISIONS)
        for a in ann:
            # Form A: noisy -- 45% chance of drifting off the latent truth
            d = truth if rng.random() > 0.45 else rng.choice(DECISIONS)
            rows.append(dict(finding_id=fid, annotator=a, form="A",
                             question="holistic", answer=d))
            # Form B: each sub-question answered with low noise
            base = {"prioritize":   dict(Q1="yes", Q2="yes", Q3="yes", Q4="no",  Q5="yes"),
                    "deprioritize": dict(Q1="no",  Q2="no",  Q3="no",  Q4="yes", Q5="no"),
                    "needs_review": dict(Q1="yes", Q2="unknown", Q3="no",
                                         Q4="unknown", Q5="yes")}[truth]
            for q in SUBQ:
                v = base[q] if rng.random() > 0.12 else rng.choice(SUBQ_ANSWERS)
                rows.append(dict(finding_id=fid, annotator=a, form="B",
                                 question=q, answer=v))
    return rows


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    if argv[1] == "--demo":
        print(">>> DEMO MODE: synthetic data, no real annotations.")
        print(">>> Use this to dry-run the pipeline BEFORE booking annotators.\n")
        analyse(demo_rows())
        return 0
    analyse(load(argv[1]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
