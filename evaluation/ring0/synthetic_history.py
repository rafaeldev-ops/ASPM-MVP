#!/usr/bin/env python3
"""
Historico de decisoes SINTETICO -- briefing item 11.

Isto NAO e o historico de decisoes de nenhuma organizacao. Nao existe cliente,
nao existe analista, e nenhuma linha aqui pode ser lida como "uma empresa
decidiu isso". Todo registro sai marcado `SYNTHETIC_DATA` e o dataset e
gravado com essa classificacao no manifesto.

O que e real e o que e fabricado, linha por linha:

    CVE, data de entrada no KEV, uso em ransomware   -> REAL (CISA)
    a decisao, a data dela, a razao, quem fechou     -> FABRICADO

O gerador e deterministico (seed fixa) para o experimento ser reexecutavel,
e monta os quatro casos que o motor precisa distinguir:

    A. fechado ANTES da entrada no KEV      -> deve virar candidato
    B. fechado DEPOIS da entrada no KEV     -> closed_despite, NAO candidato
    C. fechado, CVE nunca entrou na janela  -> nao candidato, estado incerto
    D. fechado como corrigido               -> fora do escopo por definicao

Somente biblioteca padrao.
"""

import os
import random
import sys
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from decision_debt import Decision, as_date  # noqa: E402
from ingest_kev import KevCatalog  # noqa: E402
from provenance import DatasetRecord, write_processed  # noqa: E402

SEED = 20260824
DATASET = "synthetic_decision_history.json"

# Razoes de fechamento. Pesos escolhidos para o experimento ter os dois piles
# que o produto separa -- nao sao uma medicao de nada. Nenhuma organizacao foi
# observada para produzir estes numeros.
REASONS = [("false_positive", 0.45), ("risk_accepted", 0.20),
           ("wont_fix", 0.15), ("mitigated", 0.10), ("fixed", 0.10)]


def pick_reason(rng):
    x, acc = rng.random(), 0.0
    for name, w in REASONS:
        acc += w
        if x <= acc:
            return name
    return REASONS[-1][0]


def generate(kev, n_per_bucket=120, cutoff=None):
    """Gera o historico. `cutoff` e o 'hoje' do experimento."""
    rng = random.Random(SEED)
    cutoff = as_date(cutoff or kev.window_end)
    window_start = as_date(kev.window_start)
    decisions = []
    entries = sorted(kev.records, key=lambda r: r["date_added"])

    # --- Bucket A: fechado ANTES da entrada no KEV (divida de decisao) ---
    # So serve entrada cuja data deixa espaco para uma decisao anterior dentro
    # da janela. Fechar fora da janela tornaria o estado as-of indeterminavel.
    eligible_a = [r for r in entries
                  if (as_date(r["date_added"]) - window_start).days >= 30]
    for r in rng.sample(eligible_a, min(n_per_bucket, len(eligible_a))):
        added = as_date(r["date_added"])
        max_gap = (added - window_start).days - 1
        gap = rng.randint(1, max(1, min(max_gap, 300)))
        decisions.append(Decision(
            decision_id=f"SYN-A-{len(decisions)+1:04d}",
            cve_id=r["cve_id"],
            decided_at=added - timedelta(days=gap),
            reason=pick_reason(rng),
            classification="SYNTHETIC_DATA",
            decided_by="synthetic-analyst",
            notes="bucket A: fechada antes da entrada no KEV",
        ))

    # --- Bucket B: fechado DEPOIS da entrada no KEV (closed_despite) ---
    eligible_b = [r for r in entries if (cutoff - as_date(r["date_added"])).days >= 2]
    for r in rng.sample(eligible_b, min(n_per_bucket, len(eligible_b))):
        added = as_date(r["date_added"])
        gap = rng.randint(1, max(1, min((cutoff - added).days, 200)))
        decisions.append(Decision(
            decision_id=f"SYN-B-{len(decisions)+1:04d}",
            cve_id=r["cve_id"],
            decided_at=added + timedelta(days=gap),
            reason=pick_reason(rng),
            classification="SYNTHETIC_DATA",
            decided_by="synthetic-analyst",
            notes="bucket B: fechada depois da entrada no KEV",
        ))

    # --- Bucket C: CVE fora da janela do catalogo ---
    # CVEs plausiveis que nao estao neste dataset de 12 meses. O motor deve
    # dizer "nao sei", nao "nunca entrou".
    for i in range(n_per_bucket):
        year = rng.choice([2019, 2020, 2021, 2022, 2023])
        cve = f"CVE-{year}-{rng.randrange(1000, 40000)}"
        if cve in kev.by_cve:
            continue
        decisions.append(Decision(
            decision_id=f"SYN-C-{len(decisions)+1:04d}",
            cve_id=cve,
            decided_at=window_start + timedelta(days=rng.randrange(0, 300)),
            reason=pick_reason(rng),
            classification="SYNTHETIC_DATA",
            decided_by="synthetic-analyst",
            notes="bucket C: CVE fora da janela do catalogo",
        ))

    decisions.sort(key=lambda d: (d.decided_at, d.decision_id))
    return decisions, cutoff


def persist(decisions, cutoff, kev_dataset_id):
    rec = DatasetRecord(
        dataset_id="synthetic-decision-history-v1",
        dataset_name="Historico de decisoes sintetico para o experimento de divida de decisao",
        source="gerado por evaluation/ring0/synthetic_history.py",
        source_url="",
        version=f"seed={SEED} cutoff={cutoff.isoformat()}",
        classification="SYNTHETIC_DATA",
        record_count=len(decisions),
        derived_from=[kev_dataset_id],
        license_or_usage_notes="Sem licenca: dado fabricado.",
        notes=(
            "NAO SAO DECISOES DE ANALISTA REAL. Nenhuma organizacao foi observada. "
            "Os CVEs e as datas de entrada no KEV sao reais (CISA); a decisao, a data "
            "dela e a razao sao fabricadas para exercitar o motor. A distribuicao de "
            "razoes de fechamento nao mede nada sobre o mundo."),
    )
    path = write_processed(DATASET, [d.to_dict() for d in decisions], rec)
    return path, rec


def main():
    kev = KevCatalog.load()
    decisions, cutoff = generate(kev)
    path, rec = persist(decisions, cutoff, "kev-12m-2025-08-24_2026-08-23")
    buckets = {}
    for d in decisions:
        buckets[d.decision_id.split("-")[1]] = buckets.get(d.decision_id.split("-")[1], 0) + 1
    print(f"  decisoes sinteticas : {len(decisions)}")
    print(f"  por bucket          : {buckets}")
    print(f"  cutoff ('hoje')     : {cutoff}")
    print(f"  classificacao       : {rec.classification}")
    print(f"  gravado em          : {os.path.relpath(path)}")


if __name__ == "__main__":
    main()
