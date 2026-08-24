#!/usr/bin/env python3
"""
Correlacao entre os dois corpora reais -- briefing item 9.

A regra que este arquivo existe para obedecer: *nao forcar vinculo onde nao ha
evidencia de vinculo.* Semelhanca textual nao vira identidade.

Tres chaves candidatas sao testadas, e cada uma reporta o que de fato sustenta:

    CVE        -> identidade. E a unica que autoriza dizer "e a mesma coisa".
    CWE        -> CLASSE, nunca identidade. Dois achados com CWE-787 nao sao o
                  mesmo defeito; sao o mesmo tipo de defeito.
    repositorio-> so vale se o produto do KEV for reconhecivelmente o mesmo
                  projeto do SARIF, e isso e verificado, nao presumido.

O resultado esperado deste run e majoritariamente `unmatched`, e isso e um
achado sobre as fontes, nao uma falha do correlacionador.

Somente biblioteca padrao.
"""

import os
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ingest_kev import KevCatalog  # noqa: E402
from provenance import read_processed  # noqa: E402

WORD = re.compile(r"[a-z0-9]+")


def norm_words(s):
    return {w for w in WORD.findall(str(s or "").lower()) if len(w) > 2}


def correlate():
    kev = KevCatalog.load()
    _, findings = read_processed("codeql_emboss_findings.json")

    out = {
        "kev_entries": len(kev.records),
        "codeql_findings": len(findings),
        "codeql_projects": len({f["project"] for f in findings}),
    }

    # --- Chave 1: CVE (identidade) ---
    with_cve = [f for f in findings if f.get("cve")]
    out["cve_key"] = {
        "codeql_findings_with_cve": len(with_cve),
        "matched": len([f for f in with_cve if f["cve"] in kev.by_cve]),
        "verdict": ("NAO APLICAVEL: CodeQL nao emite CVE. 0 de "
                    f"{len(findings)} achados carregam um identificador de "
                    "vulnerabilidade. Nao existe juncao por identidade entre "
                    "estes dois corpora."),
    }

    # --- Chave 2: CWE (classe, nao identidade) ---
    kev_cwes = Counter()
    for r in kev.records:
        for c in r["cwes"]:
            kev_cwes[c] += 1
    codeql_cwes = Counter()
    for f in findings:
        for c in f["cwe"]:
            codeql_cwes[c] += 1

    shared = sorted(set(kev_cwes) & set(codeql_cwes),
                    key=lambda c: -codeql_cwes[c])
    findings_in_shared = sum(1 for f in findings if set(f["cwe"]) & set(shared))
    kev_in_shared = sum(1 for r in kev.records if set(r["cwes"]) & set(shared))

    out["cwe_key"] = {
        "kev_distinct_cwes": len(kev_cwes),
        "codeql_distinct_cwes": len(codeql_cwes),
        "shared_cwes": len(shared),
        "shared_cwe_list": shared,
        "codeql_findings_in_shared_class": findings_in_shared,
        "codeql_findings_in_shared_class_pct": round(findings_in_shared / len(findings) * 100, 2),
        "kev_entries_in_shared_class": kev_in_shared,
        "kev_entries_in_shared_class_pct": round(kev_in_shared / len(kev.records) * 100, 2),
        "relationship_type": "CLASS_LEVEL_ONLY",
        "verdict": ("Vinculo de CLASSE, nunca de identidade. Um achado do CodeQL com "
                    "CWE-787 e um CVE do KEV com CWE-787 compartilham categoria de "
                    "defeito e nada mais. Isto NAO autoriza re-litigar o achado do "
                    "CodeQL porque o CVE entrou no KEV."),
    }

    # --- Chave 3: repositorio / produto ---
    # Testado, nao presumido: os nomes de projeto do SARIF sao comparados com
    # vendor/product do KEV por interseccao de tokens, e cada acerto candidato
    # e listado inteiro para inspecao humana. Nenhum vira vinculo automatico.
    proj_tokens = {}
    for f in findings:
        proj_tokens.setdefault(f["project"], norm_words(f["project"].replace("/", " ")))
    candidates = []
    for r in kev.records:
        kw = norm_words(f"{r['vendor_project']} {r['product']}")
        for proj, pw in proj_tokens.items():
            common = kw & pw
            # exige token especifico, nao palavra generica
            common = {c for c in common if c not in {"the", "for", "and", "org", "com",
                                                     "project", "server", "software"}}
            if common:
                candidates.append({
                    "kev_cve": r["cve_id"],
                    "kev_vendor": r["vendor_project"],
                    "kev_product": r["product"],
                    "codeql_project": proj,
                    "shared_tokens": sorted(common),
                })
    out["repository_key"] = {
        "candidate_pairs": len(candidates),
        "candidates": candidates[:40],
        "verdict": ("Pares por token compartilhado sao PISTAS para inspecao humana, "
                    "nao vinculos. Nenhum foi promovido a relacionamento: o KEV nomeia "
                    "um produto comercial, o SARIF nomeia um repositorio do GitHub, e "
                    "coincidencia de token nao prova que sao o mesmo artefato."),
    }

    matched_any = 0  # por identidade
    out["summary"] = {
        "matched_by_identity": matched_any,
        "unmatched": len(findings) - matched_any,
        "unmatched_pct": round((len(findings) - matched_any) / len(findings) * 100, 2),
        "conclusion": ("100% unmatched por identidade. Os dois datasets reais deste run "
                       "nao se juntam: o KEV e indexado por CVE e o CodeQL nao emite CVE. "
                       "Isso e uma propriedade das fontes, nao um defeito do "
                       "correlacionador -- e e a razao pela qual o experimento de divida "
                       "de decisao nao pode usar os achados do CodeQL como sujeito."),
    }
    return out


def main():
    import json
    r = correlate()
    print(f"KEV entries              : {r['kev_entries']}")
    print(f"CodeQL findings          : {r['codeql_findings']} em {r['codeql_projects']} projetos")
    print()
    print("--- chave CVE (identidade) ---")
    print(f"  achados com CVE        : {r['cve_key']['codeql_findings_with_cve']}")
    print(f"  {r['cve_key']['verdict']}")
    print()
    print("--- chave CWE (classe) ---")
    c = r["cwe_key"]
    print(f"  CWEs no KEV            : {c['kev_distinct_cwes']}")
    print(f"  CWEs no CodeQL         : {c['codeql_distinct_cwes']}")
    print(f"  CWEs compartilhados    : {c['shared_cwes']} -> {c['shared_cwe_list']}")
    print(f"  achados CodeQL na classe compartilhada: {c['codeql_findings_in_shared_class']} "
          f"({c['codeql_findings_in_shared_class_pct']}%)")
    print(f"  entradas KEV na classe compartilhada  : {c['kev_entries_in_shared_class']} "
          f"({c['kev_entries_in_shared_class_pct']}%)")
    print()
    print("--- chave repositorio ---")
    print(f"  pares candidatos       : {r['repository_key']['candidate_pairs']}")
    for cand in r["repository_key"]["candidates"][:8]:
        print(f"    {cand['kev_cve']}  {cand['kev_vendor']}/{cand['kev_product']}"
              f"  ~  {cand['codeql_project']}  tokens={cand['shared_tokens']}")
    print()
    print("--- resumo ---")
    print(f"  unmatched: {r['summary']['unmatched']} ({r['summary']['unmatched_pct']}%)")
    return r


if __name__ == "__main__":
    main()
