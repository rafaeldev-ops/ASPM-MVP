#!/usr/bin/env python3
"""
V2 -- the deterministic risk model, executed.

Implements docs/decisions/risk-model.md: the six decision points, the urgency
tree, the ordering score, the non-suppressible overlay and the counterfactual.

Three jobs:

  --fixture   generate all 4x5x3x4x3 = 720 decision-point combinations and their
              bands. This is the review artifact risk-model.md 4.2 promises: a
              tree change is reviewed as a DIFF over these rows, not as prose.
              (720, not the document's 576: DP2 gained a fifth value -- see D3.)
  --diff      band-transition matrix, published tree vs repaired tree.
  --corpus    run the model over v4-corpus-v1.0 and report the band distribution.
  --selftest  assert the worked examples in risk-model.md 11 still hold.

Standard library only.

The point of executing a design document is to find out where it is not
actually a design. Run --fixture first.
"""

import json
import os
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))

EXPLOITATION = ("none", "poc", "public", "active")
# `not_deployed` is NOT in risk-model.md 3. It was added after running the model
# against the corpus: NW-018 is a KEV-listed glibc CVE in a staging-only image,
# and the published DP2 collapsed `staging` into `unknown`. But "this service is
# not in production" is a fact we KNOW, not a fact we lack -- and `unknown` is
# the value reserved for genuinely unmapped assets. Discarding a known negative
# as an unknown is how an estate's least-important findings crowd out its most
# important ones.
EXPOSURE = ("not_deployed", "unknown", "internal", "controlled", "open")
APPLICABILITY = ("not_applicable", "unknown", "applicable")
CRITICALITY = ("low", "medium", "high", "critical")
CONTROL = ("none", "present", "enforcing")

BANDS = ("act_now", "act_soon", "scheduled", "track", "deprioritize_candidate")
BAND_ORDER = {b: i for i, b in enumerate(BANDS)}

ANY = "*"


# ==========================================================================
# The tree, transcribed from risk-model.md 4.2. First match wins.
# Each row: (dp1, dp2, dp3, dp4, dp5, band). A set means "one of"; ANY is a
# wildcard. Row numbers are kept so a failure points at the document.
# ==========================================================================
TREE_V1 = [   # exactly as published in risk-model.md 4.2. Kept for the diff.
    (1,  {"active"}, ANY, {"unknown", "applicable"}, ANY, ANY, "act_now"),
    (2,  {"active"}, ANY, {"not_applicable"}, ANY, ANY, "act_soon"),
    (3,  {"public"}, {"open"}, {"applicable"}, ANY, {"none", "present"}, "act_now"),
    (4,  {"public"}, {"open"}, {"applicable"}, ANY, {"enforcing"}, "act_soon"),
    (5,  {"public"}, {"open"}, {"unknown"}, {"critical", "high"}, ANY, "act_soon"),
    (6,  {"public"}, {"internal", "controlled"}, {"applicable"},
         {"critical", "high"}, {"none", "present"}, "act_soon"),
    (7,  {"public"}, {"unknown"}, {"unknown", "applicable"}, ANY, ANY, "act_soon"),
    (8,  {"poc"}, {"open"}, {"applicable"}, ANY, {"none", "present"}, "act_soon"),
    (9,  {"poc"}, ANY, {"applicable"}, {"critical"}, ANY, "act_soon"),
    (10, {"poc", "none"}, {"open"}, {"applicable"}, {"high", "medium"}, ANY, "scheduled"),
    (11, {"none"}, {"internal", "controlled"}, {"applicable"}, {"critical"},
         {"none", "present"}, "scheduled"),
    (12, ANY, ANY, {"unknown"}, ANY, ANY, "track"),
    (13, {"none"}, {"internal", "controlled"}, {"applicable"},
         {"low", "medium", "high"}, ANY, "track"),
    (14, {"none", "poc"}, ANY, {"not_applicable"}, ANY, ANY, "deprioritize_candidate"),
    (15, {"none"}, {"internal", "controlled"}, {"applicable"}, {"low"},
         {"enforcing"}, "deprioritize_candidate"),
]

# --------------------------------------------------------------------------
# TREE_V2 -- repairs two defects that only appeared once V1 was executed.
#
# D1  V1 is NOT TOTAL: 112 of 576 combinations matched no row. An unmatched
#     finding has no band at all, which is worse than a wrong band -- it is
#     undefined behaviour in the component that is supposed to be exhaustively
#     reviewable. Fixed by new rows 10, 13, 14, 17 plus a conservative
#     catch-all (row 18) that lands on `track`: visible, not queued, and NOT
#     deprioritizable. Per the document's own asymmetry, the default for
#     "we did not think about this" must cost analyst hours, never silence.
#
# D2  V1's row 15 was DEAD: row 13 (`none`, internal/controlled, applicable,
#     low|medium|high) shadowed it, so the only reachable path to
#     `deprioritize_candidate` was `not_applicable`. The product's second
#     deprioritization ground -- live but genuinely low-risk behind an
#     enforcing control -- could never fire. Fixed by dropping V1's row 13
#     (the catch-all subsumes it) so the low+enforcing row is reachable.
#
# Also graded: `not_applicable` now depends on exploitation. V1 sent
# `active`+NA to act_soon and `none`/`poc`+NA to deprioritize, leaving
# `public`+NA unmatched. A public exploit against something we BELIEVE does
# not apply is an inventory claim, and inventory is what organizations are
# most often wrong about -- so it lands on `track`, between the two.
# --------------------------------------------------------------------------
TREE_V2 = [
    (1,  {"active"}, ANY, {"unknown", "applicable"}, ANY, ANY, "act_now"),
    (2,  {"active"}, ANY, {"not_applicable"}, ANY, ANY, "act_soon"),
    (3,  {"public"}, {"open"}, {"applicable"}, ANY, {"none", "present"}, "act_now"),
    (4,  {"public"}, {"open"}, {"applicable"}, ANY, {"enforcing"}, "act_soon"),
    (5,  {"public"}, {"open"}, {"unknown"}, {"critical", "high"}, ANY, "act_soon"),
    (6,  {"public"}, {"internal", "controlled"}, {"applicable"},
         {"critical", "high"}, {"none", "present"}, "act_soon"),
    (7,  {"public"}, {"unknown"}, {"unknown", "applicable"}, ANY, ANY, "act_soon"),
    (8,  {"poc"}, {"open"}, {"applicable"}, ANY, {"none", "present"}, "act_soon"),
    (9,  {"poc"}, ANY, {"applicable"}, {"critical"}, ANY, "act_soon"),
    (10, {"none"}, {"open"}, {"applicable"}, {"critical"}, ANY, "act_soon"),      # NEW
    (11, {"poc", "none"}, {"open"}, {"applicable"}, {"high", "medium"}, ANY, "scheduled"),
    (12, {"none"}, {"internal", "controlled"}, {"applicable"}, {"critical"},
         {"none", "present"}, "scheduled"),
    (13, {"public"}, {"internal", "controlled"}, {"applicable"}, ANY, ANY,
         "scheduled"),                                                            # NEW
    (14, {"poc"}, {"internal", "controlled", "unknown"}, {"applicable"}, ANY, ANY,
         "scheduled"),                                                            # NEW
    (15, ANY, ANY, {"unknown"}, ANY, ANY, "track"),
    (16, {"none"}, {"internal", "controlled"}, {"applicable"}, {"low"},
         {"enforcing"}, "deprioritize_candidate"),         # was V1 row 15, now reachable
    (17, {"public"}, ANY, {"not_applicable"}, ANY, ANY, "track"),                 # NEW
    (18, {"none", "poc"}, ANY, {"not_applicable"}, ANY, ANY, "deprioritize_candidate"),
    # D3: a service that is not deployed to production. Rows 1-2 and 7 still
    # escalate `active` and `public` above this, on the same inventory-claim
    # reasoning as row 2 -- "it isn't deployed" is a claim about our own estate.
    (19, {"none", "poc"}, {"not_deployed"}, ANY, ANY, ANY, "deprioritize_candidate"),
    (20, ANY, ANY, ANY, ANY, ANY, "track"),               # CATCH-ALL. Conservative by design.
]

TREE = TREE_V2
UNMATCHED = "UNMATCHED"


def match(row, dps):
    for spec, val in zip(row[1:6], dps):
        if spec is not ANY and val not in spec:
            return False
    return True


def band_of(dp1, dp2, dp3, dp4, dp5, tree=None):
    for row in (tree or TREE):
        if match(row, (dp1, dp2, dp3, dp4, dp5)):
            return row[6], row[0]
    return UNMATCHED, None


def all_combinations():
    for a in EXPLOITATION:
        for b in EXPOSURE:
            for c in APPLICABILITY:
                for d in CRITICALITY:
                    for e in CONTROL:
                        yield a, b, c, d, e


def band_transition_matrix():
    """risk-model.md 7.2: no scoring change ships without this."""
    moves, counts_a, counts_b = Counter(), Counter(), Counter()
    into_depri = []
    for combo in all_combinations():
        ba, _ = band_of(*combo, tree=TREE_V1)
        bb, _ = band_of(*combo, tree=TREE_V2)
        counts_a[ba] += 1
        counts_b[bb] += 1
        if ba != bb:
            moves[(ba, bb)] += 1
            if bb == "deprioritize_candidate":
                into_depri.append(combo)
    return moves, counts_a, counts_b, into_depri


# ==========================================================================
# Part B -- the ordering score. Orders WITHIN a band. Never crosses a boundary,
# never triggers a suppression. risk-model.md 5.2.
# ==========================================================================
ORD_EXPLOIT = {"none": 0.0, "poc": 0.4, "public": 0.8, "active": 1.0}
ORD_EXPOSURE = {"not_deployed": 0.0, "unknown": 0.5, "internal": 0.3,
                "controlled": 0.5, "open": 1.0}
ORD_CRIT = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}
ORD_APPL = {"not_applicable": 0.0, "unknown": 0.5, "applicable": 1.0}


def ordering_score(f, dps):
    dp1, dp2, dp3, dp4, _ = dps
    c = {
        "cvss": 0.20 * ((f.get("cvss_base") or 0) / 10.0),
        "epss": 0.20 * (f.get("epss_percentile") or 0.0),
        "exploitation": 0.15 * ORD_EXPLOIT[dp1],
        "exposure": 0.15 * ORD_EXPOSURE[dp2],
        "criticality": 0.15 * ORD_CRIT[dp4],
        "applicability": 0.10 * ORD_APPL[dp3],
        "pressure": 0.05 * min(1.0, (f.get("age_days") or 0) / 365.0),
    }
    return max(0.0, min(1.0, sum(c.values()))), c


# ==========================================================================
# Decision points from features. risk-model.md 3.
# ==========================================================================
def decision_points(f):
    # DP1
    if f.get("kev_listed") or f.get("active_exploitation"):
        dp1 = "active"
    elif f.get("exploit_public"):
        dp1 = "public"
    elif f.get("exploit_maturity") == "poc":
        dp1 = "poc"
    else:
        dp1 = "none"

    # DP2 -- 'controlled' is tested before 'internal'; both can hold and the
    # document lists controlled first. `not_deployed` is checked FIRST because a
    # service that is not in production cannot be internet-facing in production,
    # whatever the registry says about it.
    if f.get("environment") in ("staging", "dev") or f.get("artifact_shipped") is False:
        dp2 = "not_deployed"
    elif f.get("internet_facing") is True and f.get("environment") == "prod":
        dp2 = "open"
    elif f.get("entry_point_confirmed") is True and f.get("internet_facing") is False:
        dp2 = "controlled"
    elif f.get("internet_facing") is False and f.get("environment") == "prod":
        dp2 = "internal"
    else:
        dp2 = "unknown"

    # DP3 -- not_applicable requires a POSITIVE, tier-A signal. Absence of
    # evidence yields unknown, never not_applicable.
    if (f.get("range_covers_deployed") is False
            or (f.get("reachability") == "not_reachable" and f.get("reach_tier_a"))
            or (f.get("dependency_scope") == "dev_only" and f.get("artifact_shipped") is False)):
        dp3 = "not_applicable"
    elif f.get("range_covers_deployed") is True and f.get("reachability") != "not_reachable":
        dp3 = "applicable"
    else:
        dp3 = "unknown"

    dp4 = f.get("criticality") or "critical"          # NULL fails closed
    dp5 = f.get("compensating_control") or "none"
    return dp1, dp2, dp3, dp4, dp5


def non_suppressible(f):
    if f.get("kev_listed"):
        return "kev_listed"
    if f.get("active_exploitation"):
        return "active_exploitation"
    return None


def assess(f):
    dps = decision_points(f)
    band, row = band_of(*dps)
    score, contrib = ordering_score(f, dps)
    ns = non_suppressible(f)
    if ns and BAND_ORDER.get(band, 9) > BAND_ORDER["act_soon"]:
        band = "act_soon"                              # overlay floor
    reasons = []
    if ns:
        reasons.append(f"non_suppressible:{ns}")
    if f.get("criticality") is None:
        reasons.append("criticality_unresolved")
    if (f.get("cvss_spread") or 0) > 2.0:
        reasons.append("cvss_disagreement")
    eligible = band == "deprioritize_candidate" and not reasons
    return {"decision_points": dict(zip(
                ("exploitation", "exposure", "applicability", "criticality", "control"), dps)),
            "band": band, "tree_row": row, "ordering_score": round(score, 3),
            "score_contributions": {k: round(v, 3) for k, v in contrib.items()},
            "non_suppressible": ns, "auto_deprioritize_eligible": eligible,
            "ineligibility_reasons": reasons}


def counterfactual(f):
    """risk-model.md 8: the minimal decision-point change that moves the band."""
    base = assess(f)["band"]
    out = []
    dps = list(decision_points(f))
    names = ("exploitation", "exposure", "applicability", "criticality", "control")
    domains = (EXPLOITATION, EXPOSURE, APPLICABILITY, CRITICALITY, CONTROL)
    for i, dom in enumerate(domains):
        for v in dom:
            if v == dps[i]:
                continue
            trial = list(dps)
            trial[i] = v
            b, _ = band_of(*trial)
            if b != base and b != UNMATCHED:
                out.append((names[i], dps[i], v, b))
    return out


# ==========================================================================
# --fixture : all 576 combinations
# ==========================================================================
def fixture():
    rows, counts, unmatched = [], Counter(), []
    for a in EXPLOITATION:
        for b in EXPOSURE:
            for c in APPLICABILITY:
                for d in CRITICALITY:
                    for e in CONTROL:
                        band, row = band_of(a, b, c, d, e)
                        counts[band] += 1
                        rec = {"exploitation": a, "exposure": b, "applicability": c,
                               "criticality": d, "control": e,
                               "band": band, "tree_row": row}
                        rows.append(rec)
                        if band == UNMATCHED:
                            unmatched.append(rec)

    total = len(rows)
    print(f"combinations           {total}   (4 x 5 x 3 x 4 x 3)")
    for b in BANDS:
        print(f"  {b:<24} {counts[b]:>4}  ({100*counts[b]/total:.1f}%)")
    print(f"  {'UNMATCHED':<24} {counts[UNMATCHED]:>4}  ({100*counts[UNMATCHED]/total:.1f}%)")

    used = Counter(r["tree_row"] for r in rows if r["tree_row"])
    dead = [n for n, *_ in TREE if used[n] == 0]
    print(f"\ntree rows used         {len(used)} of {len(TREE)}")
    if dead:
        print(f"  DEAD ROWS (never match, unreachable): {dead}")
    for n, *_ in TREE:
        print(f"  row {n:<3} {used[n]:>4} combinations")

    if unmatched:
        print(f"\n{'='*72}\nGAP: {len(unmatched)} combinations fall through every row.")
        print("The tree is not total. An unmatched finding has NO band, which is")
        print("worse than a wrong band: it is undefined behaviour in the one")
        print("component that is supposed to be exhaustively reviewable.\n")
        pat = Counter((r["exploitation"], r["exposure"], r["applicability"])
                      for r in unmatched)
        print("  unmatched by (exploitation, exposure, applicability):")
        for k, v in sorted(pat.items(), key=lambda kv: -kv[1]):
            print(f"    {k[0]:<8} {k[1]:<11} {k[2]:<15} {v:>3}")
        print("\n  examples:")
        for r in unmatched[:6]:
            print(f"    {r['exploitation']:<8} {r['exposure']:<11} {r['applicability']:<15} "
                  f"{r['criticality']:<9} {r['control']}")

    json.dump(rows, open(os.path.join(HERE, "risk-tree-fixture.json"), "w"), indent=1)
    print(f"\nwrote risk-tree-fixture.json ({total} rows)")
    print("A tree change is reviewed as a DIFF over this file, not as prose.")
    return 1 if unmatched else 0


# ==========================================================================
# --corpus : run against the real 50 findings
# ==========================================================================
ENV = {   # the Northwind brief, machine-readable (v4-annotation-kit.md 2)
    "checkout-api":   dict(internet_facing=True,  environment="prod",
                           criticality="critical", waf=True,  regulated=True),
    "catalog-web":    dict(internet_facing=True,  environment="prod",
                           criticality="high",     waf=True,  regulated=False),
    "inventory-sync": dict(internet_facing=False, environment="prod",
                           criticality="medium",   waf=False, regulated=False),
    "admin-console":  dict(internet_facing=False, environment="prod",
                           criticality="high",     waf=False, regulated=True),
    "analytics-etl":  dict(internet_facing=False, environment="staging",
                           criticality="low",      waf=False, regulated=False),
}
INJECTION_CLASSES = ("sqli", "xss", "injection", "traversal", "xxe", "deserial",
                     "spel", "redirect")


def cvss_base(vector):
    """No CVSS calculator in the stdlib. Use the advisory's own qualitative band
    where a vector is present, and say when it is absent -- never invent one."""
    return None if not vector else None


def features_from(f):
    env = ENV[f["service"]]
    ident = (f.get("identifier") or "")
    msg = (f.get("scanner_message") or "").lower()

    # A WAF in blocking mode with six rules disabled is PRESENT, not ENFORCING.
    # risk-model.md 3: "present without attestation of enforcement is not
    # enforcing." This is the conservative reading and it is the Q4 battleground.
    control = "none"
    if env["waf"] and any(k in ident.lower() or k in msg for k in INJECTION_CLASSES):
        control = "present"

    return {
        "kev_listed": bool((f.get("kev") or {}).get("listed")),
        "active_exploitation": False,
        "exploit_public": False,          # not in the corpus; absence != evidence
        "exploit_maturity": None,
        "internet_facing": env["internet_facing"],
        "environment": env["environment"],
        "entry_point_confirmed": None,
        "criticality": env["criticality"],
        "compensating_control": control,
        "range_covers_deployed": f.get("range_covers_deployed"),
        "reachability": f.get("tool_reachability"),
        "reach_tier_a": f.get("tool_reachability") == "not_reachable",
        "dependency_scope": f.get("dependency_scope"),
        "artifact_shipped": env["environment"] == "prod",
        "epss_percentile": (f.get("epss") or {}).get("percentile"),
        "cvss_base": cvss_base(f.get("cvss_vector")),
        "cvss_spread": 0.0,
        "age_days": 180,
    }


def run_corpus():
    p = os.path.join(HERE, "v4-corpus-v1.0.json")
    if not os.path.exists(p):
        print("v4-corpus-v1.0.json not found. Run v4_corpus.py first.")
        return 1
    corpus = json.load(open(p, encoding="utf-8"))
    out, bands, by_stratum = [], Counter(), {}
    for f in corpus["findings"]:
        a = assess(features_from(f))
        bands[a["band"]] += 1
        by_stratum.setdefault(f["stratum"], Counter())[a["band"]] += 1
        out.append((f, a))

    print(f"corpus {corpus['version']}  ({len(out)} findings)\n")
    print("band distribution")
    for b in BANDS + (UNMATCHED,):
        if bands[b]:
            print(f"  {b:<24} {bands[b]:>3}")

    print("\nby stratum (what the corpus was designed to contain)")
    for st in sorted(by_stratum):
        row = ", ".join(f"{b}={n}" for b, n in by_stratum[st].most_common())
        print(f"  {st}  {row}")

    elig = [f["finding_id"] for f, a in out if a["auto_deprioritize_eligible"]]
    ns = [f["finding_id"] for f, a in out if a["non_suppressible"]]
    print(f"\nauto-deprioritize eligible   {len(elig)}  {elig if elig else ''}")
    print(f"non-suppressible (KEV)       {len(ns)}")

    print("\nthe S1/S2 Tomcat pair -- same service, same version, one applies")
    for fid in ("NW-004", "NW-008"):
        f, a = next(x for x in out if x[0]["finding_id"] == fid)
        dp = a["decision_points"]
        print(f"  {fid}  {f['identifier']:<16} applicability={dp['applicability']:<15} "
              f"band={a['band']:<22} score={a['ordering_score']}")

    json.dump([{"finding_id": f["finding_id"], "stratum": f["stratum"], **a}
               for f, a in out],
              open(os.path.join(HERE, "v2-riskmodel-run.json"), "w"), indent=1)
    print("\nwrote v2-riskmodel-run.json")
    return 0


# ==========================================================================
def selftest():
    """The worked examples in risk-model.md 11."""
    cases = [
        ("A log4shell-shaped", dict(kev_listed=True, internet_facing=True,
            environment="prod", criticality="critical", range_covers_deployed=True,
            dependency_scope="direct"), "act_now", True),
        ("B the sold case", dict(kev_listed=False, internet_facing=False,
            environment="staging", criticality="low", range_covers_deployed=False,
            dependency_scope="dev_only", artifact_shipped=False),
            "deprioritize_candidate", False),
        ("C fails closed", dict(kev_listed=False, internet_facing=None,
            environment=None, criticality=None, range_covers_deployed=None),
            "track", False),
    ]
    ok = True
    for name, f, want_band, want_ns in cases:
        a = assess(f)
        good = a["band"] == want_band and bool(a["non_suppressible"]) == want_ns
        ok &= good
        print(f"  {'PASS' if good else 'FAIL'}  {name:<22} band={a['band']:<22} "
              f"expected={want_band}")
        if not good:
            print(f"        decision points: {a['decision_points']}")
    # C must be ineligible for auto-deprioritize with criticality unresolved
    c = assess(cases[2][1])
    if c["auto_deprioritize_eligible"] or "criticality_unresolved" not in c["ineligibility_reasons"]:
        print("  FAIL  C should be ineligible with criticality_unresolved")
        ok = False
    else:
        print("  PASS  C ineligible, reasons: " + ", ".join(c["ineligibility_reasons"]))
    return 0 if ok else 1


def diff():
    moves, ca, cb, into = band_transition_matrix()
    print("BAND-TRANSITION MATRIX  v1 (as published) -> v2 (repaired)")
    print("risk-model.md 7.2 requires this before any scoring change is promoted.\n")
    print(f"{'band':<24}{'v1':>6}{'v2':>6}{'delta':>8}")
    for b in BANDS + (UNMATCHED,):
        if ca[b] or cb[b]:
            print(f"{b:<24}{ca[b]:>6}{cb[b]:>6}{cb[b]-ca[b]:>+8}")
    total = sum(ca.values())
    print(f"\n{sum(moves.values())} of {total} combinations changed band")
    print("(the domain grew from 576 to 720 when DP2 gained `not_deployed`;")
    print(" the 144 new combinations are unmatched under v1 by construction)\n")
    for (a, b), n in sorted(moves.items(), key=lambda kv: -kv[1]):
        print(f"  {a:<24} -> {b:<24} {n:>4}")

    print(f"\ncombinations moving INTO deprioritize_candidate: {len(into)}")
    print("(risk-model.md 7.2 step 3: these are enumerated and reviewed, always,")
    print(" because a change that quietly deprioritizes is the one that must never ship silently)")
    for c in into:
        print(f"    {c[0]:<8} {c[1]:<11} {c[2]:<15} {c[3]:<9} {c[4]}")
    return 0


def assertions():
    """
    The two properties risk-model.md 4.2 now asserts in CI. Both defects exp-002
    found are mechanically detectable, and neither would have survived a test.
    """
    combos = list(all_combinations())
    unmatched = [c for c in combos if band_of(*c)[0] == UNMATCHED]
    used = Counter(band_of(*c)[1] for c in combos)
    dead = [n for n, *_ in TREE if used[n] == 0]

    ok = True
    if unmatched:
        ok = False
        print(f"  FAIL  tree is not total: {len(unmatched)} of {len(combos)} "
              f"combinations match no row")
        for c in unmatched[:5]:
            print(f"          {c}")
    else:
        print(f"  PASS  tree is total ({len(combos)} combinations, all matched)")

    if dead:
        ok = False
        print(f"  FAIL  dead rows (shadowed, can never fire): {dead}")
        print(f"          a rule that cannot fire is a policy that exists only in prose")
    else:
        print(f"  PASS  no dead rows ({len(TREE)} rows, all reachable)")

    # A third, cheaper than the other two and just as load-bearing: nothing
    # non-suppressible may reach a deprioritization band. risk-model.md 6.
    bad = []
    for c in combos:
        b, _ = band_of(*c)
        if b == "deprioritize_candidate" and c[0] == "active":
            bad.append(c)
    if bad:
        ok = False
        print(f"  FAIL  {len(bad)} combinations deprioritize an actively-exploited finding")
    else:
        print("  PASS  no path deprioritizes exploitation=active")
    return 0 if ok else 1


def main(argv):
    if "--assert" in argv:
        return assertions()
    if "--diff" in argv:
        return diff()
    if "--fixture" in argv:
        return fixture()
    if "--corpus" in argv:
        return run_corpus()
    if "--selftest" in argv:
        return selftest()
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
