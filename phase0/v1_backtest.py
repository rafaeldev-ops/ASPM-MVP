#!/usr/bin/env python3
"""
V1 decision-debt backtest.

Reads an export of findings your team CLOSED, and reports which of them
acquired evidence afterwards that invalidates the reason they were closed.

    python v1_backtest.py your-export.csv
    python v1_backtest.py --demo            # synthetic data, to see the output first

RUNS ENTIRELY ON YOUR MACHINE.
  - reads one local file
  - fetches ONE public feed (the CISA KEV catalog) over HTTPS
  - writes ONE local HTML file
  - no credentials, no telemetry, no upload, no callback

Single file, standard library only, no install step. That is a hard
requirement, not a preference: an instrument that needs a virtualenv is an
instrument that does not get run.

--------------------------------------------------------------------------
THE RULE THAT MAKES THIS HONEST

Evidence is compared AS OF THE DAY YOU CLOSED THE FINDING, not as of today.

A CVE that is in KEV today but entered KEV BEFORE you closed it is not
decision debt -- it is a finding closed while already known-exploited, which
is a different and worse thing. This script reports the two separately and
never merges them.

Read as-of-today and roughly a quarter of a typical estate lights up for
reasons that have nothing to do with anything changing.

WHAT IS AND IS NOT TESTED           (docs/evaluation/phase-0-protocols.md 1.3)

  KEV listing after close   TESTED   exact -- KEV carries dateAdded per entry
  Already in KEV at close   TESTED   exact -- same source, opposite direction
  Advisory range widened    NOT      needs per-advisory version history
  Exploit published         NOT      publication dates are approximate
  EPSS threshold crossing   NOT      see below
  Reachability / exposure   NOT      not present in an export

EPSS is deliberately excluded. Measured on 2026-06-15, a single EPSS
model-version change moved 71,885 CVEs across the 0.01 threshold in ten days
against 306 for ten days of the world actually changing -- a 235x inflation,
with 0.0% of scores unchanged. Any 12-month window crosses at least one such
boundary, so an EPSS trigger over this window measures the model, not risk.
Including it would inflate this report and it would deserve to be discounted.
"""

import csv
import html
import json
import os
import random
import re
import sys
import urllib.request
from collections import Counter
from datetime import datetime, timedelta

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".cache")
OUT = "decision-debt-report.html"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
DATE_HINT = re.compile(r"clos|resolv|dismiss|mitigat|accept|end|complet|updat|date", re.I)
REASON_HINT = re.compile(r"reason|resolution|status|state|verdict|disposition|justif", re.I)
ID_HINT = re.compile(r"^(id|key|number|finding|alert|issue)", re.I)

# How a close reason maps onto the two piles. The FP pile is the one no vendor
# expires (competitive-teardown.md section 3) and the one nobody has counted.
FP_WORDS = re.compile(r"false.?pos|not.?applic|won.?t.?fix|wontfix|no.?risk|invalid|"
                      r"not.?exploitab|by.?design|used.?in.?tests|out.?of.?scope|dismiss", re.I)
RA_WORDS = re.compile(r"risk.?accept|accepted|exception|deferr|waiver|approved", re.I)
FIXED_WORDS = re.compile(r"fixed|remediat|patched|resolved|done|mitigated|closed.?fixed", re.I)


# --------------------------------------------------------------------------
def parse_date(s):
    if not s:
        return None
    s = str(s).strip()
    if not s or s.lower() in ("none", "null", "n/a", "-"):
        return None
    s = re.sub(r"(Z|[+-]\d{2}:?\d{2})$", "", s.split(".")[0]).strip().replace("T", " ")
    for f in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d/%m/%Y %H:%M", "%d/%m/%Y",
              "%m/%d/%Y %H:%M", "%m/%d/%Y", "%d-%b-%Y", "%d %b %Y", "%b %d, %Y",
              "%Y/%m/%d", "%d.%m.%Y"):
        try:
            return datetime.strptime(s, f)
        except ValueError:
            pass
    return None


def classify_reason(text):
    t = str(text or "")
    if RA_WORDS.search(t):
        return "risk_accepted"
    if FP_WORDS.search(t):
        return "false_positive"
    if FIXED_WORDS.search(t):
        return "fixed"
    return "other" if t.strip() else "unknown"


# --------------------------------------------------------------------------
def load_export(path):
    """Adapt to whatever the tool emits. Report what was detected; guess nothing silently."""
    raw = open(path, encoding="utf-8-sig", errors="replace").read()
    rows = []
    if raw.lstrip().startswith(("[", "{")):
        d = json.loads(raw)
        if isinstance(d, dict):
            for k in ("results", "findings", "alerts", "issues", "value", "data"):
                if isinstance(d.get(k), list):
                    d = d[k]
                    break
        rows = [flatten(x) for x in d] if isinstance(d, list) else []
    else:
        dialect = csv.Sniffer().sniff(raw[:8192], delimiters=",;\t") \
            if len(raw) > 32 else csv.excel
        rows = list(csv.DictReader(raw.splitlines(), dialect=dialect))
    return [{(k or "").strip(): v for k, v in r.items()} for r in rows if r]


def flatten(o, prefix=""):
    out = {}
    if isinstance(o, dict):
        for k, v in o.items():
            out.update(flatten(v, f"{prefix}{k}."))
    elif isinstance(o, list):
        out[prefix[:-1]] = " ".join(str(x) for x in o if not isinstance(x, (dict, list)))
        for i, v in enumerate(o[:5]):
            if isinstance(v, (dict, list)):
                out.update(flatten(v, f"{prefix}{i}."))
    else:
        out[prefix[:-1]] = o
    return out


def detect(rows):
    """Pick the id / close-date / reason columns, and say which were picked."""
    cols = list(rows[0].keys())
    scored = Counter()
    for r in rows[:400]:
        for c in cols:
            if DATE_HINT.search(c) and parse_date(r.get(c)):
                scored[c] += 1
    date_col = scored.most_common(1)[0][0] if scored else None

    # A reason column DISCRIMINATES; a status column does not. GitHub's `state` is
    # always "dismissed", which classifies fine and tells you nothing, while
    # `dismissed_reason` separates false-positive from won't-fix from used-in-tests.
    # So rank by: how many rows classify, then how many DISTINCT classes appear,
    # then how specific the column name is.
    def name_rank(c):
        return 0 if re.search(r"reason|resolution|justif|disposition", c, re.I) else 1

    cands = []
    for c in cols:
        if not REASON_HINT.search(c):
            continue
        cls = [classify_reason(r.get(c)) for r in rows[:400]]
        n = sum(1 for x in cls if x not in ("unknown", "other"))
        if n:
            cands.append((-n, -len(set(cls)), name_rank(c), c))
    reason_col = sorted(cands)[0][3] if cands else None

    id_col = next((c for c in cols if ID_HINT.search(c)), cols[0] if cols else None)
    return id_col, date_col, reason_col


def extract(rows, id_col, date_col, reason_col):
    """One record per closed finding. Anything unusable is excluded and counted."""
    recs, excl = [], Counter()
    for r in rows:
        blob = " ".join(str(v) for v in r.values() if v is not None)
        cves = sorted({m.upper() for m in CVE_RE.findall(blob)})
        closed = parse_date(r.get(date_col)) if date_col else None
        reason = classify_reason(r.get(reason_col)) if reason_col else "unknown"
        if reason == "fixed":
            excl["closed as fixed (not a decision to not act)"] += 1
            continue
        if not closed:
            excl["no parseable close date"] += 1
            continue
        if not cves:
            excl["no CVE identifier (rule-only finding: KEV cannot apply)"] += 1
            continue
        recs.append({"id": str(r.get(id_col, ""))[:60], "cves": cves,
                     "closed": closed, "reason": reason,
                     "title": next((str(v)[:110] for k, v in r.items()
                                    if re.search(r"title|name|summary|desc|rule", k or "", re.I)
                                    and v), "")})
    return recs, excl


# --------------------------------------------------------------------------
def load_kev(offline=False):
    os.makedirs(CACHE, exist_ok=True)
    p = os.path.join(CACHE, "kev.json")
    if not os.path.exists(p):
        if offline:
            raise SystemExit("offline and no cached KEV catalog")
        print("  fetching the CISA KEV catalog (the only network call this makes)")
        with urllib.request.urlopen(KEV_URL, timeout=90) as r, open(p, "wb") as f:
            f.write(r.read())
    d = json.load(open(p, encoding="utf-8"))
    return d.get("catalogVersion"), {
        x["cveID"]: (parse_date(x["dateAdded"]), x) for x in d["vulnerabilities"]}


def analyse(recs, kev):
    debt, despite = [], []
    for r in recs:
        for c in r["cves"]:
            if c not in kev:
                continue
            added, entry = kev[c]
            if not added:
                continue
            row = dict(r, cve=c, kev_added=added, kev_entry=entry,
                       days=(added - r["closed"]).days)
            (debt if added > r["closed"] else despite).append(row)
            break
    debt.sort(key=lambda x: x["kev_added"], reverse=True)
    despite.sort(key=lambda x: x["closed"], reverse=True)
    return debt, despite


def sample_for_session(debt, despite, n=20):
    """Stratified by close reason, NOT top-n by severity -- that would measure the sampling."""
    rng = random.Random(1)
    pool, out = debt + despite, []
    by = {}
    for r in pool:
        by.setdefault(r["reason"], []).append(r)
    keys = sorted(by)
    i = 0
    while len(out) < min(n, len(pool)):
        k = keys[i % len(keys)]
        if by[k]:
            out.append(by[k].pop(rng.randrange(len(by[k]))))
        elif all(not v for v in by.values()):
            break
        i += 1
    return out


# --------------------------------------------------------------------------
CSS = """body{font:15px/1.6 -apple-system,Segoe UI,Roboto,sans-serif;max-width:1000px;
margin:2rem auto;padding:0 1.2rem;color:#1a1a1a}h1{font-size:1.6rem;margin-bottom:.2rem}
h2{font-size:1.15rem;margin-top:2.2rem;border-bottom:1px solid #e5e5e5;padding-bottom:.3rem}
.sub{color:#666;margin-top:0}table{border-collapse:collapse;width:100%;font-size:13.5px;
margin:.6rem 0}th,td{border-bottom:1px solid #eaeaea;padding:.45rem .5rem;text-align:left;
vertical-align:top}th{background:#fafafa;font-weight:600}
.big{font-size:2.6rem;font-weight:700;line-height:1}.card{display:inline-block;
border:1px solid #e5e5e5;border-radius:8px;padding:.9rem 1.2rem;margin:.4rem .6rem .4rem 0;
min-width:150px}.card small{color:#666;display:block;margin-top:.2rem}
.warn{background:#fff8e6;border-left:4px solid #e0a800;padding:.8rem 1rem;margin:1rem 0}
.bad{background:#fdecec;border-left:4px solid #c00;padding:.8rem 1rem;margin:1rem 0}
code{background:#f4f4f4;padding:.1rem .3rem;border-radius:3px;font-size:12.5px}
.muted{color:#777;font-size:13px}"""


def esc(x):
    return html.escape(str(x))


def table(rows, cols):
    h = "".join(f"<th>{esc(c[0])}</th>" for c in cols)
    b = "".join("<tr>" + "".join(f"<td>{esc(c[1](r))}</td>" for c in cols) + "</tr>"
                for r in rows)
    return f"<table><tr>{h}</tr>{b}</table>"


def report(recs, debt, despite, excl, kev_version, total_rows, det, path):
    piles = Counter(r["reason"] for r in recs)
    sample = sample_for_session(debt, despite)
    cols = [("Finding", lambda r: r["id"]), ("CVE", lambda r: r["cve"]),
            ("Closed", lambda r: r["closed"].date()),
            ("Reason", lambda r: r["reason"]),
            ("KEV added", lambda r: r["kev_added"].date()),
            ("Days after close", lambda r: r["days"]),
            ("Vendor / product",
             lambda r: f"{r['kev_entry']['vendorProject']} {r['kev_entry']['product']}"[:44])]

    h = [f"<!doctype html><meta charset=utf-8><title>Decision debt</title><style>{CSS}</style>",
         "<h1>Decision debt</h1>",
         "<p class=sub>Findings you closed, which later acquired evidence that "
         "invalidates why they were closed.</p>",
         f"<p class=muted>Generated locally · CISA KEV catalog <code>{esc(kev_version)}</code> · "
         f"nothing left this machine.</p>",
         f"<div class=card><span class=big>{len(debt)}</span><small>decision debt<br>"
         f"entered KEV <b>after</b> you closed it</small></div>",
         f"<div class=card><span class=big>{len(despite)}</span><small>closed despite<br>"
         f"already in KEV <b>on</b> the day you closed it</small></div>",
         f"<div class=card><span class=big>{len(recs):,}</span><small>closed findings<br>"
         f"analysed</small></div>"]

    if despite:
        h.append("<div class=bad><b>The second number is not decision debt and is "
                 "worth looking at first.</b> Those findings were already listed as "
                 "known-exploited by CISA on the day they were closed. No re-litigation "
                 "engine is needed to catch them — only a check that nobody ran.</div>")

    h += ["<h2>The two piles</h2>",
          "<p>Formal risk acceptances are governed and expire in most tools. "
          "False-positive dismissals expire nowhere, in any tool we have checked.</p>",
          table([{"k": k, "v": v} for k, v in piles.most_common()],
                [("Close reason", lambda r: r["k"]), ("Findings", lambda r: f"{r['v']:,}")])]

    h += [f"<h2>For the review session — {len(sample)} findings, stratified by close reason</h2>",
          "<p class=muted>Stratified rather than top-N by severity: a top-N sample "
          "measures the sampling.</p>", table(sample, cols)]

    if debt:
        h += ["<h2>All decision debt</h2>", table(debt[:400], cols)]
        if len(debt) > 400:
            h.append(f"<p class=muted>Showing 400 of {len(debt)}.</p>")

    h += ["<h2>What was and was not tested</h2>",
          "<table><tr><th>Trigger</th><th>Status</th><th>Why</th></tr>"
          "<tr><td>KEV listing after close</td><td><b>tested</b></td>"
          "<td>exact — KEV carries <code>dateAdded</code> per entry</td></tr>"
          "<tr><td>Already in KEV at close</td><td><b>tested</b></td>"
          "<td>same source, opposite direction</td></tr>"
          "<tr><td>Advisory affected-range widened</td><td>not tested</td>"
          "<td>needs per-advisory version history</td></tr>"
          "<tr><td>Public exploit published</td><td>not tested</td>"
          "<td>publication dates are approximate</td></tr>"
          "<tr><td>EPSS threshold crossing</td><td><b>excluded</b></td>"
          "<td>an EPSS model change moved 71,885 CVEs across the 0.01 threshold in ten "
          "days, against 306 for ten days of real change. Any 12-month window crosses "
          "such a boundary, so the trigger would measure the model, not risk</td></tr>"
          "<tr><td>Reachability / exposure / ownership change</td><td>not tested</td>"
          "<td>not present in an export</td></tr></table>",
          "<div class=warn><b>This is a floor, not a ceiling.</b> One exact trigger was "
          "used. Everything above marked <i>not tested</i> can only add findings.</div>"]

    ex = [{"k": k, "v": v} for k, v in excl.most_common()]
    h += ["<h2>Coverage</h2>",
          f"<p>{total_rows:,} rows read · {len(recs):,} analysed · "
          f"{sum(excl.values()):,} excluded "
          f"({100*sum(excl.values())/max(total_rows,1):.0f}%).</p>",
          table(ex, [("Excluded because", lambda r: r["k"]),
                     ("Rows", lambda r: f"{r['v']:,}")]),
          f"<p class=muted>Columns detected — id: <code>{esc(det[0])}</code> · "
          f"close date: <code>{esc(det[1])}</code> · "
          f"reason: <code>{esc(det[2])}</code>. If those are wrong the numbers are wrong; "
          f"say so and they can be set explicitly.</p>"]

    open(path, "w", encoding="utf-8").write("\n".join(h))


# --------------------------------------------------------------------------
def demo_export(path):
    """Synthetic export, so the output can be seen before any real data exists."""
    rng = random.Random(11)
    _, kev = load_kev()
    cves = sorted(kev)
    rows = []
    for i in range(900):
        c = cves[rng.randrange(len(cves))] if rng.random() < .28 else \
            f"CVE-20{rng.randrange(15,24)}-{rng.randrange(1000,49999)}"
        added = kev.get(c, (None,))[0]
        base = added or datetime(2025, 6, 1)
        closed = base + timedelta(days=rng.randrange(-400, 400))
        if closed > datetime(2026, 8, 1):
            closed = datetime(2026, 8, 1) - timedelta(days=rng.randrange(1, 300))
        rows.append({
            "Id": f"FIND-{i+1:04d}",
            "Title": f"{c} in package-{rng.randrange(1,60)}",
            "CVE": c,
            "Resolution": rng.choice(["False Positive", "False Positive", "False Positive",
                                      "Risk Accepted", "Won't Fix", "Not Applicable",
                                      "Fixed", "Fixed"]),
            "Closed date": closed.strftime("%Y-%m-%d"),
        })
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    return path


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    offline = "--offline" in argv
    if argv[1] == "--demo":
        print(">>> DEMO MODE: synthetic export. Use this to see the output before")
        print(">>> asking anyone for real data.\n")
        path = demo_export(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                        "demo-export.csv"))
    else:
        path = argv[1]

    rows = load_export(path)
    if not rows:
        print("No rows read. Is the file a CSV or JSON export?")
        return 1
    det = detect(rows)
    print(f"Read {len(rows):,} rows from {os.path.basename(path)}")
    print(f"  id column         {det[0]}")
    print(f"  close date column {det[1]}")
    print(f"  reason column     {det[2]}")
    if not det[1]:
        print("\n  No close-date column found. Without it the as-of comparison cannot be")
        print("  made, and an as-of-today comparison is not worth running.")
        return 1

    recs, excl = extract(rows, *det)
    kev_version, kev = load_kev(offline)
    debt, despite = analyse(recs, kev)

    print(f"\n  analysed          {len(recs):,}")
    print(f"  excluded          {sum(excl.values()):,}")
    for k, v in excl.most_common():
        print(f"                      {v:>6,}  {k}")
    print(f"\n  DECISION DEBT     {len(debt):,}   entered KEV after you closed it")
    print(f"  CLOSED DESPITE    {len(despite):,}   already in KEV on the day you closed it")
    piles = Counter(r["reason"] for r in recs)
    print(f"\n  close reasons     " + ", ".join(f"{k}={v:,}" for k, v in piles.most_common()))

    out = os.path.join(os.path.dirname(os.path.abspath(path)) or ".", OUT)
    report(recs, debt, despite, excl, kev_version, len(rows), det, out)
    print(f"\n  wrote {out}")
    print("  Nothing left this machine. The file is yours.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
