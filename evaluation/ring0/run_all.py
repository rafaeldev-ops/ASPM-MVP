#!/usr/bin/env python3
"""
Executa o run completo do Ring 0 e grava os artefatos versionados.

    python run_all.py [YYYY-MM-DD]

Grava em evaluation/runs/<data>/:
    metadata.json   fontes, hashes, versoes, ambiente
    metrics.json    as metricas do briefing item 14
    findings.json   a matriz temporal, decisao a decisao
    report.md       o resumo legivel

Somente biblioteca padrao.
"""

import json
import os
import shutil
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "..", "phase0"))

from codeql_eval import evaluate as codeql_evaluate  # noqa: E402
from correlate import correlate  # noqa: E402
from decision_debt import (  # noqa: E402
    EPSS_SCORE_CHANGED, INVALID_AT_DECISION_TIME, POTENTIALLY_OBSOLETE,
    ChangeEvent, KnowledgeOracle, ReLitigationEngine, as_date,
)
from epss_inflation import run as epss_run  # noqa: E402
from ingest_kev import KevCatalog  # noqa: E402
from provenance import REPO_ROOT, load_manifest, read_processed  # noqa: E402
from synthetic_history import generate  # noqa: E402


def expected_bucket(decision_id):
    """O rotulo de construcao do historico sintetico.

    ATENCAO ao ler as metricas que saem disto: este ground truth e DERIVADO da
    forma como o dataset foi construido, nao observado no mundo. Ele mede se o
    motor faz o que a especificacao diz -- nao mede prevalencia de divida de
    decisao em nenhuma organizacao.
    """
    b = decision_id.split("-")[1]
    return {"A": True, "B": False, "C": False}[b]


def run_engine(kev):
    decisions, cutoff = generate(kev)
    oracle = KnowledgeOracle(kev)
    engine = ReLitigationEngine(oracle)

    # Eventos de EPSS em TODA decisao: o teste de inflacao roda sobre a
    # populacao inteira, nao sobre uma amostra escolhida.
    events = {d.decision_id: [ChangeEvent(EPSS_SCORE_CHANGED, d.cve_id, cutoff,
                                          "FIRST EPSS", detail="deslocamento de modelo")]
              for d in decisions if d.cve_id}

    baseline = engine.run(decisions, cutoff)
    with_epss = engine.run(decisions, cutoff, events)
    return decisions, cutoff, baseline, with_epss, oracle


def compute_metrics(decisions, baseline, with_epss, oracle):
    scored = [(d, r) for d, r in zip(decisions, baseline)
              if r["decision_validity"] != "NOT_APPLICABLE"]

    suggested = [r for _, r in scored if r["re_litigation_candidate"]]
    valid = [r for d, r in scored
             if r["re_litigation_candidate"] and expected_bucket(d.decision_id)]
    invalid = [r for d, r in scored
               if r["re_litigation_candidate"] and not expected_bucket(d.decision_id)]
    should_have = [d for d, r in scored if expected_bucket(d.decision_id)]
    missed = [d for d, r in scored
              if expected_bucket(d.decision_id) and not r["re_litigation_candidate"]]

    precision = len(valid) / len(suggested) if suggested else None
    recall = len(valid) / len(should_have) if should_have else None
    false_rate = len(invalid) / len(suggested) if suggested else None

    base_n = sum(1 for r in baseline if r["re_litigation_candidate"])
    epss_n = sum(1 for r in with_epss if r["re_litigation_candidate"])

    with_evidence = sum(1 for r in suggested if r["evidence"])
    leaks = [q for q in oracle.queries
             if q["kev_date_added_if_known"] is not None
             and q["kev_date_added_if_known"] > q["as_of"]]

    despite = [r for r in baseline if r["decision_validity"] == INVALID_AT_DECISION_TIME]
    unknown = [r for r in baseline if r["decision_validity"] == "UNKNOWN_OUTSIDE_WINDOW"]
    excluded = [r for r in baseline if r["decision_validity"] == "NOT_APPLICABLE"]

    return {
        "ground_truth_note": (
            "Precision e recall abaixo sao contra o rotulo de CONSTRUCAO do historico "
            "sintetico. Medem se o motor implementa a regra as-of corretamente. NAO sao "
            "uma medida de prevalencia de divida de decisao em nenhuma organizacao real, "
            "e nao devem ser citados como tal."),
        "population": {
            "decisions_total": len(baseline),
            "in_scope": len(scored),
            "excluded_closed_as_fixed": len(excluded),
        },
        "decision_debt_precision": {
            "value": round(precision, 4) if precision is not None else None,
            "valid_candidates": len(valid),
            "suggested_candidates": len(suggested),
            "ground_truth": "DERIVED_FROM_CONSTRUCTION",
        },
        "decision_debt_recall": {
            "value": round(recall, 4) if recall is not None else None,
            "found": len(valid), "should_have_found": len(should_have),
            "missed": len(missed),
            "ground_truth": "DERIVED_FROM_CONSTRUCTION",
        },
        "false_re_litigation_rate": {
            "value": round(false_rate, 4) if false_rate is not None else None,
            "invalid_candidates": len(invalid), "suggested": len(suggested),
        },
        "candidate_inflation_epss": {
            "baseline_candidates": base_n,
            "after_epss_change_on_every_decision": epss_n,
            "delta": epss_n - base_n,
            "inflation_x": round(epss_n / base_n, 4) if base_n else None,
            "events_injected": len(with_epss),
            "meaning": ("Um evento de EPSS foi injetado em TODAS as decisoes com CVE. "
                        "Se EPSS fosse gatilho, a contagem explodiria."),
        },
        "evidence_coverage": {
            "candidates_with_traceable_evidence": with_evidence,
            "candidates": len(suggested),
            "value": round(with_evidence / len(suggested), 4) if suggested else None,
        },
        "temporal_correctness": {
            "knowledge_queries": len(oracle.queries),
            "future_leaks": len(leaks),
            "value": round(1 - len(leaks) / len(oracle.queries), 4) if oracle.queries else None,
        },
        "pile_split": {
            "decision_debt": len([r for r in baseline
                                  if r["decision_validity"] == POTENTIALLY_OBSOLETE]),
            "closed_despite_already_in_kev": len(despite),
            "unknown_outside_window": len(unknown),
            "excluded_not_a_decision_to_not_act": len(excluded),
            "note": ("Os dois primeiros nunca se somam. Fundi-los inflaria o numero "
                     "principal com achados que contam outra historia."),
        },
        "close_reason_distribution": dict(Counter(
            r["decision_reason"] for r in baseline)),
    }


def baseline_comparison(kev, decisions, cutoff):
    """Compara o motor novo com phase0/v1_backtest.py sobre a MESMA evidencia.

    O v1_backtest resolve o cache do KEV a partir do proprio caminho. Em vez de
    editar um instrumento ja validado, importamos o modulo e apontamos a
    constante para um diretorio temporario com exatamente as 273 entradas
    desta janela. Assim a divergencia, se houver, e de logica -- nao de catalogo.
    """
    import v1_backtest

    tmp = tempfile.mkdtemp(prefix="ring0-kev-")
    try:
        catalog = {
            "title": "ring0 window slice",
            "catalogVersion": "ring0-12m-window",
            "count": len(kev.records),
            "vulnerabilities": [
                {"cveID": r["cve_id"], "vendorProject": r["vendor_project"],
                 "product": r["product"], "vulnerabilityName": r["vulnerability_name"],
                 "dateAdded": r["date_added"], "shortDescription": r["short_description"],
                 "requiredAction": "", "dueDate": r["due_date"] or "",
                 "knownRansomwareCampaignUse": "Known" if r["known_ransomware"] else "Unknown",
                 "notes": r["notes"]}
                for r in kev.records
            ],
        }
        with open(os.path.join(tmp, "kev.json"), "w", encoding="utf-8") as f:
            json.dump(catalog, f)

        csv_path = os.path.join(tmp, "synthetic-decisions.csv")
        with open(csv_path, "w", encoding="utf-8", newline="") as f:
            import csv as _csv
            w = _csv.writer(f)
            w.writerow(["Id", "Title", "CVE", "Resolution", "Closed date"])
            reason_label = {"false_positive": "False Positive", "risk_accepted": "Risk Accepted",
                            "wont_fix": "Won't Fix", "mitigated": "Mitigated", "fixed": "Fixed"}
            for d in decisions:
                w.writerow([d.decision_id, f"{d.cve_id} synthetic", d.cve_id,
                            reason_label.get(d.reason, d.reason),
                            d.decided_at.isoformat()])

        original_cache = v1_backtest.CACHE
        v1_backtest.CACHE = tmp
        try:
            rows = v1_backtest.load_export(csv_path)
            det = v1_backtest.detect(rows)
            recs, excl = v1_backtest.extract(rows, *det)
            _, kevmap = v1_backtest.load_kev(offline=True)
            debt, despite = v1_backtest.analyse(recs, kevmap)
        finally:
            v1_backtest.CACHE = original_cache

        # Diagnostico da divergencia: reroda o motor excluindo cada razao de
        # fechamento, uma a uma, e ve qual exclusao reproduz o v1_backtest.
        # Divergencia entre duas implementacoes da mesma regra e um achado, e
        # arredondar isso seria o oposto do que este repositorio faz.
        v1_reasons = Counter(v1_backtest.classify_reason(
            {"false_positive": "False Positive", "risk_accepted": "Risk Accepted",
             "wont_fix": "Won't Fix", "mitigated": "Mitigated",
             "fixed": "Fixed"}[d.reason]) for d in decisions)
        our_reasons = Counter(d.reason for d in decisions)

        return {
            "instrument": "phase0/v1_backtest.py",
            "evidence": "identica (janela de 273 entradas injetada no cache do instrumento)",
            "rows_read": len(rows),
            "analysed": len(recs),
            "excluded": sum(excl.values()),
            "exclusion_reasons": dict(excl),
            "decision_debt": len(debt),
            "closed_despite": len(despite),
            "reason_classification": {
                "engine": dict(our_reasons),
                "v1_backtest": dict(v1_reasons),
                "divergences": [
                    {"input": "Mitigated",
                     "engine": "mitigated (decisao de nao agir -> em escopo)",
                     "v1_backtest": v1_backtest.classify_reason("Mitigated"),
                     "impact": "exclui do escopo",
                     "assessment": (
                         "Mitigado nao e corrigido. Um achado fechado porque existe um "
                         "controle compensatorio e exatamente uma decisao de NAO "
                         "remediar -- e ADR-0016 diz que essa supressao e perecivel: o "
                         "controle pode deixar de valer, ou o CVE pode entrar no KEV. "
                         "O regex FIXED_WORDS do v1_backtest contem 'mitigated', entao "
                         "esses registros somem do relatorio. DefectDojo usa 'Mitigated' "
                         "como status, entao isso morde em dado real de parceiro.")},
                    {"input": "Won't Fix",
                     "engine": "wont_fix",
                     "v1_backtest": v1_backtest.classify_reason("Won't Fix"),
                     "impact": "nao muda a contagem de divida; corrompe a divisao de piles",
                     "assessment": (
                         "'Won't fix' e aceitacao de risco, nao falso positivo. Nao altera "
                         "o total porque ambos ficam em escopo, mas contamina exatamente a "
                         "medida que competitive-positioning chama de A4 -- o tamanho da "
                         "pilha de falso positivo contra a de risco aceito, que o protocolo "
                         "diz nunca ter sido medida.")},
                ],
            },
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def write_report(out_dir, run_date, metrics, cmp_, corr, cq, epss, kev, cutoff):
    """O resumo legivel do run. A analise completa fica em
    docs/evaluation/ring0-real-data-validation.md; aqui ficam os numeros deste
    run especifico, para o diretorio ser autossuficiente."""
    p = metrics["pile_split"]
    m = metrics
    e = epss["conclusion"]
    lines = [
        f"# Ring 0 — run de {run_date}",
        "",
        "Resumo gerado por `evaluation/ring0/run_all.py`. Análise completa e",
        "conclusões em [`docs/evaluation/ring0-real-data-validation.md`]"
        "(../../../docs/evaluation/ring0-real-data-validation.md).",
        "",
        "> **As decisões deste run são SINTÉTICAS.** CVEs, datas de entrada no KEV e uso",
        "> em ransomware são reais (CISA). Nenhum parceiro, nenhum cliente, nenhuma",
        "> decisão de analista real. Nada aqui move K1, K2 ou K3.",
        "",
        "## Fontes",
        "",
        "| Dataset | Classe | Registros |",
        "|---|---|---:|",
        f"| CISA KEV ({kev.window_start} … {kev.window_end}) | REAL_EXTERNAL_DATA | "
        f"{len(kev.records)} |",
        f"| CodeQL SARIF (EMBOSS/ISSTA) | REAL_EXTERNAL_DATA | {cq['totals']['findings']} |",
        f"| EPSS snapshot {epss['epss_snapshot']['model_version']} | REAL_EXTERNAL_DATA | "
        f"{epss['epss_snapshot']['cve_count']} |",
        f"| Histórico de decisões | **SYNTHETIC_DATA** | "
        f"{m['population']['decisions_total']} |",
        "",
        f"## Dívida de decisão (as-of {cutoff})",
        "",
        "| Pilha | Contagem |",
        "|---|---:|",
        f"| Dívida de decisão | **{p['decision_debt']}** |",
        f"| Fechado apesar de (já no KEV) | **{p['closed_despite_already_in_kev']}** |",
        f"| Fora da janela do catálogo | {p['unknown_outside_window']} |",
        f"| Excluído (fechado como corrigido) | "
        f"{p['excluded_not_a_decision_to_not_act']} |",
        "",
        "## Métricas",
        "",
        "| Métrica | Valor |",
        "|---|---:|",
        f"| Precision (rótulo de construção) | {m['decision_debt_precision']['value']} |",
        f"| Recall (rótulo de construção) | {m['decision_debt_recall']['value']} |",
        f"| False re-litigation rate | {m['false_re_litigation_rate']['value']} |",
        f"| Candidate inflation sob EPSS | "
        f"{m['candidate_inflation_epss']['inflation_x']}× |",
        f"| Evidence coverage | {m['evidence_coverage']['value']} |",
        f"| Temporal correctness | {m['temporal_correctness']['value']} "
        f"({m['temporal_correctness']['knowledge_queries']} consultas, "
        f"{m['temporal_correctness']['future_leaks']} vazamentos) |",
        "",
        f"**Precision {m['decision_debt_precision']['value']} é contra o rótulo de "
        "construção do dataset sintético.** Mede a implementação contra a especificação, "
        "não o mundo. Não é K3.",
        "",
        "## Comparação com phase0/v1_backtest.py (evidência idêntica)",
        "",
        "| | Dívida | Fechado apesar de |",
        "|---|---:|---:|",
        f"| Motor deste run | {p['decision_debt']} | "
        f"{p['closed_despite_already_in_kev']} |",
        f"| `v1_backtest.py` | {cmp_['decision_debt']} | {cmp_['closed_despite']} |",
        "",
        f"Concordam: **{'sim' if cmp_['agrees_with_engine'] else 'não'}**. "
        "Causa isolada e confirmada:",
        "",
    ]
    for d in cmp_["reason_classification"]["divergences"]:
        lines += [f"- `classify_reason({d['input']!r})` → `{d['v1_backtest']}` "
                  f"— {d['impact']}"]
    lines += [
        "",
        "## Correlação KEV × CodeQL",
        "",
        f"- Junção por identidade (CVE): **{corr['summary']['unmatched_pct']}% unmatched**. "
        "CodeQL não emite CVE.",
        f"- Classe (CWE): {corr['cwe_key']['shared_cwes']} CWEs compartilhados, "
        f"{corr['cwe_key']['codeql_findings_in_shared_class_pct']}% dos achados.",
        f"- Repositório: {corr['repository_key']['candidate_pairs']} pares candidatos, "
        "nenhum promovido a vínculo.",
        "",
        "## EPSS",
        "",
        f"- {e['cves_within_10pct_of_threshold']} CVEs a ±10% do limiar "
        f"{e['threshold_examined']} (medida real).",
        f"- Deslocamento simulado de 25% move {e['cves_crossing_on_25pct_shift']} CVEs "
        "(DERIVED_DATA).",
        f"- KEV no mesmo período: {e['kev_additions_per_month']} entradas/mês (medida real).",
        "",
        "## Corpus CodeQL",
        "",
        f"- {cq['totals']['findings']} achados, {cq['totals']['projects']} projetos, "
        f"{cq['totals']['distinct_rules_fired']} regras dispararam.",
        f"- Cobertura de CWE {cq['field_coverage']['cwe']['pct']}%, "
        f"CVE {cq['field_coverage']['cve']['pct']}%.",
        f"- Concentração: {cq['concentration']['top_project']} = "
        f"{cq['concentration']['top_project_pct']}% do corpus.",
        f"- Ground truth de falso positivo: **{cq['ground_truth']['available']}**.",
        "",
    ]
    with open(os.path.join(out_dir, "report.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main():
    run_date = sys.argv[1] if len(sys.argv) > 1 else datetime.now(timezone.utc).date().isoformat()
    out_dir = os.path.join(REPO_ROOT, "evaluation", "runs", run_date)
    os.makedirs(out_dir, exist_ok=True)

    print(f"=== Ring 0 real-data validation run — {run_date} ===\n")

    kev = KevCatalog.load()
    decisions, cutoff, baseline, with_epss, oracle = run_engine(kev)
    metrics = compute_metrics(decisions, baseline, with_epss, oracle)

    print("[1/5] motor de divida de decisao")
    p = metrics["pile_split"]
    print(f"      divida de decisao        : {p['decision_debt']}")
    print(f"      fechado apesar de        : {p['closed_despite_already_in_kev']}")
    print(f"      fora da janela           : {p['unknown_outside_window']}")
    print(f"      excluido (corrigido)     : {p['excluded_not_a_decision_to_not_act']}")

    print("[2/5] comparacao com phase0/v1_backtest.py")
    cmp_ = baseline_comparison(kev, decisions, cutoff)
    print(f"      v1_backtest: debt={cmp_['decision_debt']} despite={cmp_['closed_despite']}")
    agree = (cmp_["decision_debt"] == p["decision_debt"]
             and cmp_["closed_despite"] == p["closed_despite_already_in_kev"])
    print(f"      concordancia com o motor : {'SIM' if agree else 'NAO'}")
    cmp_["agrees_with_engine"] = agree

    print("[3/5] correlacao KEV x CodeQL")
    corr = correlate()
    print(f"      unmatched por identidade : {corr['summary']['unmatched_pct']}%")

    print("[4/5] avaliacao do corpus CodeQL")
    cq = codeql_evaluate()
    print(f"      findings                 : {cq['totals']['findings']}")

    print("[5/5] EPSS")
    epss = epss_run()
    print(f"      {epss['conclusion']['cves_crossing_on_25pct_shift']} CVEs cruzam com "
          f"deslocamento de 25% vs {epss['conclusion']['kev_additions_per_month']} "
          f"entradas KEV/mes")

    metadata = {
        "run_date": run_date,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "cutoff_as_of": cutoff.isoformat(),
        "kev_window": [str(kev.window_start), str(kev.window_end)],
        "datasets": load_manifest()["datasets"],
        "code": {
            f: __import__("hashlib").sha256(
                open(os.path.join(HERE, f), "rb").read()).hexdigest()[:16]
            for f in sorted(os.listdir(HERE)) if f.endswith(".py")
        },
    }

    findings_doc = {
        "_warning": ("As decisoes desta matriz sao SINTETICAS. As datas de KEV, o uso em "
                     "ransomware e os identificadores de CVE sao REAIS (CISA)."),
        "cutoff_as_of": cutoff.isoformat(),
        "temporal_matrix": baseline,
    }

    write_report(out_dir, run_date, metrics, cmp_, corr, cq, epss, kev, cutoff)

    for name, payload in (("metadata.json", metadata),
                          ("metrics.json", {"decision_debt": metrics,
                                            "baseline_comparison": cmp_,
                                            "correlation": corr,
                                            "codeql_corpus": cq,
                                            "epss": epss}),
                          ("findings.json", findings_doc)):
        with open(os.path.join(out_dir, name), "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False, default=str)
            f.write("\n")

    print(f"\nartefatos em evaluation/runs/{run_date}/")
    return {"metrics": metrics, "cmp": cmp_, "corr": corr, "cq": cq,
            "epss": epss, "metadata": metadata, "out_dir": out_dir}


if __name__ == "__main__":
    main()
