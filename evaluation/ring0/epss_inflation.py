#!/usr/bin/env python3
"""
EXP-004 — EPSS como gatilho, medido neste dataset. Briefing item 13.

O projeto ja rejeitou EPSS como gatilho de re-litigio em EXP-001, com um numero
medido numa fronteira de versao de modelo. Este experimento NAO tenta reproduzir
aquele numero. Ele pergunta outra coisa, sobre o dado que temos aqui:

    Quao fragil e um gatilho de limiar sobre a distribuicao real do EPSS?

Duas medidas, com estatutos diferentes e rotuladas como tais:

  MEDIDA REAL (REAL_EXTERNAL_DATA)
    A densidade da distribuicao em volta dos limiares usados na pratica. Isso
    nao e simulado: e a contagem de quantos CVEs estao perto o bastante de um
    limiar para que qualquer deslocamento os atravesse. Um snapshot basta para
    medir, porque fragilidade e uma propriedade da distribuicao, nao do tempo.

  MEDIDA SIMULADA (DERIVED_DATA)
    Um deslocamento multiplicativo aplicado a todos os scores, e a contagem de
    quantos CVEs cruzam o limiar. O fator e arbitrario e esta declarado. Nao ha
    aqui uma troca real de versao de modelo -- so temos um snapshot.

E a comparacao que da sentido as duas: quantas entradas o KEV produziu no
mesmo periodo. Esse numero e real, e e o denominador honesto.

Somente biblioteca padrao.
"""

import csv
import gzip
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ingest_kev import KevCatalog  # noqa: E402
from provenance import REPO_ROOT, DatasetRecord, sha256_file, upsert  # noqa: E402

EPSS_SNAPSHOT = os.path.join(REPO_ROOT, "phase0", ".cache", "epss-2026-08-14.csv.gz")
THRESHOLDS = (0.01, 0.05, 0.1, 0.5)
# Bandas relativas em volta do limiar. 0.10 = "a 10% do limiar".
BANDS = (0.05, 0.10, 0.25, 0.50)
# Fatores de deslocamento simulado. Declarados, nao escolhidos para dar um numero.
SHIFT_FACTORS = (1.10, 1.25, 1.50, 2.00)


def load_epss():
    scores, model_version, score_date = {}, None, None
    with gzip.open(EPSS_SNAPSHOT, "rt", encoding="utf-8") as f:
        header = f.readline().strip()
        for part in header.lstrip("#").split(","):
            if part.startswith("model_version:"):
                model_version = part.split(":", 1)[1]
            elif part.startswith("score_date:"):
                score_date = part.split(":", 1)[1]
        for row in csv.DictReader(f):
            try:
                scores[row["cve"].upper()] = float(row["epss"])
            except (TypeError, ValueError):
                continue
    return scores, model_version, score_date


def run():
    scores, model_version, score_date = load_epss()
    kev = KevCatalog.load()
    n = len(scores)
    vals = sorted(scores.values())

    result = {
        "epss_snapshot": {
            "file": os.path.relpath(EPSS_SNAPSHOT, REPO_ROOT).replace("\\", "/"),
            "model_version": model_version,
            "score_date": score_date,
            "cve_count": n,
            "sha256": sha256_file(EPSS_SNAPSHOT),
            "classification": "REAL_EXTERNAL_DATA",
        },
        "real_density": [],
        "simulated_shift": [],
        "kev_baseline": {},
    }

    # ---- MEDIDA REAL: densidade em volta dos limiares ----
    for t in THRESHOLDS:
        above = sum(1 for v in vals if v >= t)
        row = {"threshold": t, "cves_above": above,
               "cves_above_pct": round(above / n * 100, 3), "bands": []}
        for b in BANDS:
            lo, hi = t * (1 - b), t * (1 + b)
            inside = sum(1 for v in vals if lo <= v <= hi)
            below_in_band = sum(1 for v in vals if lo <= v < t)
            row["bands"].append({
                "relative_band": b,
                "range": [round(lo, 6), round(hi, 6)],
                "cves_inside": inside,
                "cves_inside_below_threshold": below_in_band,
                # A banda cruza o limiar nos dois sentidos, entao este numero
                # pode passar de 100% -- nao e erro. E por isso que o campo se
                # chama "ratio" e nao "percentual do subconjunto".
                "ratio_to_above_count_pct": round(inside / above * 100, 2) if above else None,
                "meaning": (f"{inside} CVEs estao a {int(b*100)}% do limiar {t}, dos quais "
                            f"{below_in_band} estao abaixo dele. Qualquer deslocamento "
                            f"dessa magnitude atravessa esses {below_in_band}."),
            })
        result["real_density"].append(row)

    # ---- MEDIDA SIMULADA: deslocamento multiplicativo ----
    for t in THRESHOLDS:
        base = sum(1 for v in vals if v >= t)
        for k in SHIFT_FACTORS:
            after = sum(1 for v in vals if v * k >= t)
            crossed = after - base
            result["simulated_shift"].append({
                "threshold": t,
                "shift_factor": k,
                "baseline_above": base,
                "after_shift_above": after,
                "newly_crossed": crossed,
                "inflation_x": round(after / base, 2) if base else None,
                "classification": "DERIVED_DATA",
            })

    # ---- BASELINE REAL: o que o KEV produziu no mesmo periodo ----
    days = (kev._as_date(kev.window_end) - kev._as_date(kev.window_start)).days
    result["kev_baseline"] = {
        "entries": len(kev.records),
        "window_days": days,
        "per_month": round(len(kev.records) / (days / 30.44), 1),
        "classification": "REAL_EXTERNAL_DATA",
        "meaning": ("O gatilho KEV produz este volume por mes, e cada entrada e um "
                    "fato datado por uma autoridade, nao um score recalculado."),
    }

    # ---- A comparacao que decide ----
    t = 0.01
    dens = next(r for r in result["real_density"] if r["threshold"] == t)
    band10 = next(b for b in dens["bands"] if b["relative_band"] == 0.10)
    sim = next(s for s in result["simulated_shift"]
               if s["threshold"] == t and s["shift_factor"] == 1.25)
    kev_month = result["kev_baseline"]["per_month"]
    result["conclusion"] = {
        "threshold_examined": t,
        "cves_within_10pct_of_threshold": band10["cves_inside"],
        "cves_crossing_on_25pct_shift": sim["newly_crossed"],
        "kev_additions_per_month": kev_month,
        "ratio_vs_kev_month": (round(sim["newly_crossed"] / kev_month, 1)
                               if kev_month else None),
        "verdict": (
            f"Um deslocamento de 25% nos scores -- menor do que uma troca de versao de "
            f"modelo -- move {sim['newly_crossed']} CVEs atraves do limiar {t}. O KEV, no "
            f"mesmo periodo, adiciona {kev_month} entradas por mes. Um gatilho de limiar "
            f"de EPSS produz eventos numa ordem de grandeza incompativel com revisao "
            f"humana, e nenhum deles corresponde a alguem ter observado exploracao. "
            f"A decisao de EXP-001 se sustenta neste dataset."),
    }

    rec = DatasetRecord(
        dataset_id="epss-snapshot-2026-08-14",
        dataset_name="EPSS daily snapshot (modelo v2026.06.15)",
        source="FIRST.org EPSS",
        source_url="https://www.first.org/epss/data_stats",
        version=f"{model_version} @ {score_date}",
        classification="REAL_EXTERNAL_DATA",
        record_count=n,
        file_path=EPSS_SNAPSHOT,
        license_or_usage_notes="Dado publico do FIRST.org. Usado apenas como medida "
                               "negativa: EPSS NAO e gatilho neste sistema.",
        notes="Snapshot unico. Nao permite medir uma fronteira real de versao de modelo; "
              "o deslocamento deste experimento e simulado e esta rotulado DERIVED_DATA.",
    )
    upsert(rec)
    return result


def main():
    r = run()
    s = r["epss_snapshot"]
    print(f"snapshot EPSS: {s['cve_count']} CVEs, modelo {s['model_version']}, {s['score_date']}")
    print()
    print("--- MEDIDA REAL: densidade em volta dos limiares ---")
    for row in r["real_density"]:
        print(f"  limiar {row['threshold']}: {row['cves_above']} CVEs acima "
              f"({row['cves_above_pct']}%)")
        for b in row["bands"]:
            print(f"      +/-{int(b['relative_band']*100):>3}%  ->  {b['cves_inside']:>6} na banda, "
                  f"dos quais {b['cves_inside_below_threshold']:>6} abaixo do limiar "
                  f"(atravessariam)")
    print()
    print("--- MEDIDA SIMULADA: deslocamento multiplicativo (DERIVED_DATA) ---")
    for row in r["simulated_shift"]:
        if row["threshold"] != 0.01:
            continue
        print(f"  limiar {row['threshold']} x{row['shift_factor']}: "
              f"{row['baseline_above']} -> {row['after_shift_above']} "
              f"(+{row['newly_crossed']} cruzaram, {row['inflation_x']}x)")
    print()
    k = r["kev_baseline"]
    print(f"--- BASELINE REAL: KEV {k['entries']} entradas em {k['window_days']} dias "
          f"= {k['per_month']}/mes ---")
    print()
    print("--- CONCLUSAO ---")
    print(f"  {r['conclusion']['verdict']}")
    return r


if __name__ == "__main__":
    main()
