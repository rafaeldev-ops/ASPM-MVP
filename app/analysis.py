"""
Motor de analise de divida de decisao.

Porta a logica ja validada de phase0/v1_backtest.py (nao importa de la de
proposito -- phase0/README.md e explicito: "Not product code. Never
imported by app/"). O algoritmo de comparacao as-of e o mesmo, testado
contra dado real; a unica adicao e o uso confirmado por ransomware por CVE,
que a propria KEV ja carrega e phase0/v1_backtest.py nao expunha.
"""

import csv
import json
import os
import random
import re
import urllib.request
from collections import Counter
from datetime import datetime, timedelta

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# SDIP_CACHE_DIR existe para o container apontar o cache para um volume; sem
# ele o comportamento local nao muda -- reusa o cache que phase0/ ja baixou.
from app.paths import diretorio_de_cache  # noqa: E402

CACHE_DIR = diretorio_de_cache() or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "phase0", ".cache")

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
DATE_HINT = re.compile(r"clos|resolv|dismiss|mitigat|accept|end|complet|updat|date", re.I)
REASON_HINT = re.compile(r"reason|resolution|status|state|verdict|disposition|justif", re.I)
ID_HINT = re.compile(r"^(id|key|number|finding|alert|issue)", re.I)

FP_WORDS = re.compile(r"false.?pos|not.?applic|won.?t.?fix|wontfix|no.?risk|invalid|"
                      r"not.?exploitab|by.?design|used.?in.?tests|out.?of.?scope|dismiss", re.I)
RA_WORDS = re.compile(r"risk.?accept|accepted|exception|deferr|waiver|approved", re.I)
FIXED_WORDS = re.compile(r"fixed|remediat|patched|resolved|done|mitigated|closed.?fixed", re.I)


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


def load_export_from_text(raw, is_json):
    rows = []
    if is_json:
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
    cols = list(rows[0].keys())
    scored = Counter()
    for r in rows[:400]:
        for c in cols:
            if DATE_HINT.search(c) and parse_date(r.get(c)):
                scored[c] += 1
    date_col = scored.most_common(1)[0][0] if scored else None

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


def load_kev(offline=False):
    os.makedirs(CACHE_DIR, exist_ok=True)
    p = os.path.join(CACHE_DIR, "kev.json")
    if not os.path.exists(p):
        if offline:
            raise RuntimeError("offline and no cached KEV catalog")
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
            ransomware = str(entry.get("knownRansomwareCampaignUse", "")).strip().lower() == "known"
            row = dict(r, cve=c, kev_added=added, kev_entry=entry, ransomware=ransomware,
                       days=(added - r["closed"]).days)
            (debt if added > r["closed"] else despite).append(row)
            break
    debt.sort(key=lambda x: (not x["ransomware"], -x["kev_added"].toordinal()))
    despite.sort(key=lambda x: (not x["ransomware"], -x["closed"].toordinal()))
    return debt, despite


def sample_for_session(debt, despite, n=20):
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


def demo_export_rows():
    """Export sintetico -- mesma geracao de phase0/v1_backtest.py --demo."""
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
    return rows


def run_analysis(rows):
    """rows -> (summary dict, debt list, despite list, sample list, det tuple, excl Counter)"""
    if not rows:
        raise ValueError("Nenhuma linha lida. O arquivo e um CSV ou JSON de export valido?")
    det = detect(rows)
    if not det[1]:
        raise ValueError(
            "Nenhuma coluna de data de fechamento encontrada. Sem ela a comparacao "
            "as-of nao pode ser feita, e uma comparacao contra hoje nao vale a pena."
        )
    recs, excl = extract(rows, *det)
    kev_version, kev = load_kev()
    debt, despite = analyse(recs, kev)
    sample = sample_for_session(debt, despite)
    piles = Counter(r["reason"] for r in recs)
    summary = {
        "total_rows": len(rows),
        "analyzed": len(recs),
        "excluded": sum(excl.values()),
        "debt_count": len(debt),
        "despite_count": len(despite),
        "debt_ransomware": sum(1 for r in debt if r["ransomware"]),
        "despite_ransomware": sum(1 for r in despite if r["ransomware"]),
        "kev_version": kev_version,
        "piles": dict(piles),
        "id_col": det[0], "date_col": det[1], "reason_col": det[2],
    }
    return summary, debt, despite, sample, excl
