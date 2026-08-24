#!/usr/bin/env python3
"""
Avaliacao do corpus CodeQL -- briefing item 17.

Mede o que da para medir sobre a NOSSA normalizacao usando dado real, e diz
com todas as letras o que NAO da para medir.

O que NAO da para medir aqui, e a razao:

    falso positivo / defeito confirmado / relevancia de seguranca

O artefato do ISSTA contem a analise manual dos autores? Nao em formato
legivel por maquina. O zip traz `OSSEmbeddedResults/` com os SARIF, um
`embedded-repos.json` com a lista de repositorios, e dois PDFs (o paper e o
relatorio da survey). Os 709 defeitos do titulo do paper estao no PDF, em
prosa e tabelas -- nao ha arquivo de labels.

Portanto NAO EXISTE ground truth de falso positivo neste run, e qualquer
precisao que fosse reportada sobre isso seria inventada. O briefing item 17
manda verificar a estrutura antes de converter analise manual em ground truth:
verificado, e a resposta e que nao da.

Somente biblioteca padrao.
"""

import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from provenance import read_processed  # noqa: E402


def evaluate():
    prov, findings = read_processed("codeql_emboss_findings.json")
    n = len(findings)

    # --- Cobertura de campos: o que a fonte de fato entrega ---
    fields = ("repository", "commit", "file", "line", "rule", "message",
              "severity", "cwe", "cve", "security_severity", "precision")
    coverage = {}
    for f_name in fields:
        present = sum(1 for f in findings
                      if f.get(f_name) not in (None, "", [], {}))
        coverage[f_name] = {"present": present, "pct": round(present / n * 100, 2)}

    # --- Deduplicacao ---
    by_fp = Counter(f["fingerprint"] for f in findings)
    exact_dupes = {k: v for k, v in by_fp.items() if v > 1}
    dupe_records = sum(v for v in exact_dupes.values())
    basis = Counter(f["fingerprint_basis"] for f in findings)

    # Mesma regra + mesmo arquivo + mesma linha, dentro do mesmo projeto+commit:
    # deveria ser o mesmo achado. Se a contagem difere da de fingerprint, o
    # fingerprint esta separando coisas que sao a mesma.
    loc_key = Counter((f["project"], f["commit"], f["source_rule_id"], f["file"], f["line"])
                      for f in findings)
    loc_dupes = sum(v - 1 for v in loc_key.values() if v > 1)

    # --- Classificacao por regra ---
    sec = sum(1 for f in findings if f["is_security_rule"])
    with_sec_sev = sum(1 for f in findings if f["security_severity"])
    levels = Counter(f["severity"] or "unspecified" for f in findings)
    precisions = Counter(f["precision"] or "unspecified" for f in findings)
    rules = Counter(f["source_rule_id"] for f in findings)

    # --- Concentracao: um projeto domina? ---
    per_project = Counter(f["project"] for f in findings)
    top1 = per_project.most_common(1)[0]
    top5_sum = sum(v for _, v in per_project.most_common(5))

    # --- Agrupamento por CWE ---
    cwe_counts = Counter()
    for f in findings:
        for c in f["cwe"]:
            cwe_counts[c] += 1
    no_cwe = sum(1 for f in findings if not f["cwe"])

    return {
        "provenance": {"dataset_id": prov["dataset_id"], "sha256": prov["file_sha256"],
                       "classification": prov["classification"]},
        "totals": {
            "findings": n,
            "projects": len(per_project),
            "commits": len({(f["project"], f["commit"]) for f in findings}),
            "distinct_rules_fired": len(rules),
        },
        "field_coverage": coverage,
        "dedup": {
            "distinct_fingerprints": len(by_fp),
            "fingerprints_with_collisions": len(exact_dupes),
            "records_in_collisions": dupe_records,
            "collision_pct": round(dupe_records / n * 100, 2),
            "fingerprint_basis": dict(basis),
            "location_level_duplicates": loc_dupes,
            "note": ("Colisao de fingerprint aqui NAO e prova de duplicata: o "
                     "partialFingerprint do CodeQL e por linha, entao dois achados "
                     "distintos da mesma regra na mesma linha colidem legitimamente. "
                     "O numero e reportado como o que e -- uma taxa de colisao do "
                     "esquema de identidade, nao uma taxa de duplicatas reais."),
        },
        "classification": {
            "security_tagged_rule_findings": sec,
            "security_tagged_pct": round(sec / n * 100, 2),
            "with_security_severity": with_sec_sev,
            "with_security_severity_pct": round(with_sec_sev / n * 100, 2),
            "levels": dict(levels),
            "precisions": dict(precisions),
        },
        "concentration": {
            "top_project": top1[0],
            "top_project_findings": top1[1],
            "top_project_pct": round(top1[1] / n * 100, 2),
            "top5_pct": round(top5_sum / n * 100, 2),
            "note": ("Concentracao alta significa que qualquer metrica agregada sobre "
                     "este corpus descreve principalmente um punhado de projetos. "
                     "Reportar so a media esconderia isso."),
        },
        "grouping": {
            "distinct_cwes": len(cwe_counts),
            "findings_without_cwe": no_cwe,
            "findings_without_cwe_pct": round(no_cwe / n * 100, 2),
            "top_cwes": cwe_counts.most_common(10),
            "top_rules": rules.most_common(10),
        },
        "ground_truth": {
            "available": False,
            "reason": ("O artefato Zenodo nao traz labels de analise manual em formato "
                       "legivel por maquina. Ha os SARIF, `embedded-repos.json` (a lista "
                       "de 300 repositorios buscados) e dois PDFs. Os 709 defeitos "
                       "confirmados do paper estao em prosa. Sem arquivo de labels, nao "
                       "existe ground truth de falso positivo neste run."),
            "consequence": ("Nenhuma metrica de precisao/recall sobre falso positivo do "
                            "CodeQL e reportada. As metricas acima sao sobre parsing, "
                            "normalizacao e identidade -- propriedades do nosso codigo, "
                            "verificaveis contra o dado real."),
        },
    }


def main():
    import json
    r = evaluate()
    t = r["totals"]
    print(f"findings: {t['findings']} | projetos: {t['projects']} | "
          f"commits: {t['commits']} | regras que dispararam: {t['distinct_rules_fired']}")
    print()
    print("--- cobertura de campo (o que a fonte realmente entrega) ---")
    for k, v in r["field_coverage"].items():
        bar = "#" * int(v["pct"] / 5)
        print(f"  {k:<20} {v['pct']:>6.2f}%  {bar}")
    print()
    d = r["dedup"]
    print("--- deduplicacao / identidade ---")
    print(f"  fingerprints distintos      : {d['distinct_fingerprints']}")
    print(f"  com colisao                 : {d['fingerprints_with_collisions']} "
          f"({d['collision_pct']}% dos registros)")
    print(f"  base do fingerprint         : {d['fingerprint_basis']}")
    print(f"  duplicatas por localizacao  : {d['location_level_duplicates']}")
    print()
    c = r["classification"]
    print("--- classificacao ---")
    print(f"  regra com tag security      : {c['security_tagged_rule_findings']} "
          f"({c['security_tagged_pct']}%)")
    print(f"  com security-severity       : {c['with_security_severity']} "
          f"({c['with_security_severity_pct']}%)")
    print(f"  niveis                      : {c['levels']}")
    print()
    cc = r["concentration"]
    print("--- concentracao ---")
    print(f"  maior projeto: {cc['top_project']} com {cc['top_project_findings']} "
          f"({cc['top_project_pct']}%); top5 = {cc['top5_pct']}%")
    print()
    g = r["grouping"]
    print(f"--- agrupamento: {g['distinct_cwes']} CWEs, "
          f"{g['findings_without_cwe_pct']}% dos achados sem CWE ---")
    print()
    print("--- GROUND TRUTH ---")
    print(f"  disponivel: {r['ground_truth']['available']}")
    print(f"  {r['ground_truth']['reason']}")
    return r


if __name__ == "__main__":
    main()
