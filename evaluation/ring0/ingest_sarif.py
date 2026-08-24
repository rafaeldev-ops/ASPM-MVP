#!/usr/bin/env python3
"""
Ingestao dos resultados SARIF do CodeQL -- artefato ISSTA 2025 / EMBOSS.

Le direto do zip em datasets/raw/ (que nunca e modificado nem extraido),
levanta o formato antes de normalizar, e grava um dataset canonico com
proveniencia.

    python ingest_sarif.py --survey   # levanta o corpus, nao grava nada
    python ingest_sarif.py            # normaliza e grava

Duas regras que este arquivo respeita e que sao faceis de violar:

1. Campo que nao existe na fonte vira None, nunca um valor inferido. CodeQL
   nao emite CVE; inventar um por semelhanca de texto seria fabricar a chave
   de juncao do experimento inteiro.

2. Nada do original e descartado. `raw_source_reference` aponta para o
   arquivo, o indice do run e o indice do result -- da para voltar ao SARIF
   e reler a linha exata.

Somente biblioteca padrao.
"""

import hashlib
import json
import os
import re
import sys
import zipfile
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from provenance import RAW_DIR, DatasetRecord, sha256_file, write_processed  # noqa: E402

ARTIFACT = os.path.join(RAW_DIR, "issta2025-artifact.zip")
RESULTS_PREFIX = "issta2025-artifact/OSSEmbeddedResults/"
SARIF_DATASET = "codeql_emboss_findings.json"

SOURCE_URL = "https://zenodo.org/records/15200316"
CWE_TAG = re.compile(r"external/cwe/cwe-(\d+)", re.I)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def sarif_members(z):
    """Os SARIF de resultado, ignorando cache de ferramenta que veio junto."""
    return sorted(e for e in z.namelist()
                  if e.startswith(RESULTS_PREFIX)
                  and e.endswith(".sarif")
                  and "mypy_cache" not in e)


def parse_path(member):
    """OSSEmbeddedResults/{owner}/{repo}/{commit}/{file}.sarif

    A proveniencia de repositorio e commit esta no caminho, e e real -- nao
    precisa ser inferida de dentro do SARIF.
    """
    parts = member[len(RESULTS_PREFIX):].split("/")
    if len(parts) != 4:
        return None
    owner, repo, commit, fname = parts
    return {
        "owner": owner,
        "repo": repo,
        "project": f"{owner}/{repo}",
        "commit": commit,
        "sarif_file": fname,
        "filtered": fname.endswith("-filtered.sarif"),
    }


def rule_index(run):
    """id da regra -> metadados uteis, do bloco tool.driver.rules."""
    out = {}
    for rule in run.get("tool", {}).get("driver", {}).get("rules", []) or []:
        props = rule.get("properties", {}) or {}
        tags = props.get("tags", []) or []
        cwes = sorted({f"CWE-{m.group(1)}" for t in tags for m in [CWE_TAG.search(t)] if m},
                      key=lambda c: int(c.split("-")[1]))
        out[rule.get("id")] = {
            "name": rule.get("name") or rule.get("id"),
            "short_description": (rule.get("shortDescription") or {}).get("text"),
            "tags": tags,
            "cwes": cwes,
            "precision": props.get("precision"),
            "problem_severity": props.get("problem.severity"),
            "security_severity": props.get("security-severity"),
            "default_level": (rule.get("defaultConfiguration") or {}).get("level"),
            # A convencao do CodeQL: uma regra e de seguranca quando carrega a
            # tag `security`. Nao inferimos por nome nem por CWE.
            "is_security": "security" in [t.lower() for t in tags],
        }
    return out


def primary_location(result):
    locs = result.get("locations") or []
    if not locs:
        return None, None, None
    phys = (locs[0] or {}).get("physicalLocation") or {}
    art = phys.get("artifactLocation") or {}
    region = phys.get("region") or {}
    return art.get("uri"), region.get("startLine"), region.get("startColumn")


def fingerprint(project, commit, rule_id, uri, line, result):
    """Identidade estavel do finding.

    Prefere o partialFingerprint do proprio CodeQL, que sobrevive a
    deslocamento de linha. Sem ele, cai para a tupla de localizacao -- e o
    campo `fingerprint_basis` registra qual das duas foi usada, porque as duas
    nao tem a mesma forca e misturar isso silenciosamente corromperia qualquer
    medida de deduplicacao.
    """
    pf = (result.get("partialFingerprints") or {}).get("primaryLocationLineHash")
    basis = "codeql_partial_fingerprint" if pf else "location_tuple"
    key = f"{project}|{commit}|{rule_id}|{uri}|{pf or line}"
    return hashlib.sha256(key.encode()).hexdigest()[:32], basis


def survey():
    z = zipfile.ZipFile(ARTIFACT)
    members = sarif_members(z)
    print(f"arquivos SARIF          : {len(members)}")

    projects, commits = set(), set()
    tools, sarif_versions = Counter(), Counter()
    total_results = 0
    rules_seen, rule_hits = {}, Counter()
    levels, precisions, sev_present = Counter(), Counter(), Counter()
    cwe_hits, has_cve, no_location = Counter(), 0, 0
    fix_info = 0
    per_project = Counter()
    filtered_files = []

    for m in members:
        meta = parse_path(m)
        if not meta:
            print(f"  AVISO: caminho fora do padrao esperado: {m}")
            continue
        if meta["filtered"]:
            filtered_files.append(m)
        projects.add(meta["project"])
        commits.add((meta["project"], meta["commit"]))
        doc = json.loads(z.read(m).decode("utf-8"))
        sarif_versions[doc.get("version")] += 1
        for run in doc.get("runs", []):
            drv = run.get("tool", {}).get("driver", {})
            tools[f"{drv.get('name')} {drv.get('semanticVersion') or drv.get('version')}"] += 1
            ridx = rule_index(run)
            rules_seen.update(ridx)
            results = run.get("results", []) or []
            total_results += len(results)
            per_project[meta["project"]] += len(results)
            for res in results:
                rid = res.get("ruleId")
                rule_hits[rid] += 1
                meta_rule = ridx.get(rid, {})
                levels[res.get("level") or meta_rule.get("default_level") or "unspecified"] += 1
                precisions[meta_rule.get("precision") or "unspecified"] += 1
                sev_present["security-severity presente" if meta_rule.get("security_severity")
                            else "sem security-severity"] += 1
                for c in meta_rule.get("cwes", []):
                    cwe_hits[c] += 1
                uri, line, _ = primary_location(res)
                if not uri:
                    no_location += 1
                blob = json.dumps(res)
                if CVE_RE.search(blob):
                    has_cve += 1
                if res.get("fixes"):
                    fix_info += 1

    print(f"projetos (owner/repo)   : {len(projects)}")
    print(f"pares projeto+commit    : {len(commits)}")
    print(f"versoes SARIF           : {dict(sarif_versions)}")
    print(f"ferramentas             : {dict(tools)}")
    print(f"findings (results)      : {total_results}")
    print(f"regras distintas no tool: {len(rules_seen)}")
    print(f"regras que dispararam   : {len(rule_hits)}")
    print(f"arquivos -filtered      : {len(filtered_files)} -> {filtered_files}")
    print()
    print(f"niveis                  : {dict(levels)}")
    print(f"precisao das regras     : {dict(precisions)}")
    print(f"security-severity       : {dict(sev_present)}")
    print(f"findings sem localizacao: {no_location}")
    print(f"findings com info de fix: {fix_info}")
    print(f"findings citando um CVE : {has_cve}")
    sec_rules = [r for r in rules_seen.values() if r["is_security"]]
    print(f"regras com tag security : {len(sec_rules)} de {len(rules_seen)}")
    print()
    print(f"CWEs distintos          : {len(cwe_hits)}")
    print("top 12 CWE              :")
    for c, n in cwe_hits.most_common(12):
        print(f"    {c:<12} {n}")
    print("top 8 regras            :")
    for r, n in rule_hits.most_common(8):
        print(f"    {r:<45} {n}")
    print("top 5 projetos por volume:")
    for p, n in per_project.most_common(5):
        print(f"    {p:<45} {n}")


def ingest():
    z = zipfile.ZipFile(ARTIFACT)
    members = sarif_members(z)
    findings = []
    dupe_probe = defaultdict(int)

    for m in members:
        meta = parse_path(m)
        if not meta:
            continue
        doc = json.loads(z.read(m).decode("utf-8"))
        for run_i, run in enumerate(doc.get("runs", [])):
            drv = run.get("tool", {}).get("driver", {})
            tool = f"{drv.get('name')} {drv.get('semanticVersion') or drv.get('version')}"
            ridx = rule_index(run)
            for res_i, res in enumerate(run.get("results", []) or []):
                rid = res.get("ruleId")
                rule = ridx.get(rid, {})
                uri, line, col = primary_location(res)
                fp, basis = fingerprint(meta["project"], meta["commit"], rid, uri, line, res)
                dupe_probe[fp] += 1
                findings.append({
                    "finding_id": f"{meta['project']}@{meta['commit'][:12]}#{fp[:12]}",
                    "source_system": "codeql-sarif-issta2025",
                    "source_rule_id": rid,
                    "repository": meta["project"],
                    "project": meta["project"],
                    "commit": meta["commit"],
                    "file": uri,
                    "line": line,
                    "column": col,
                    "rule": rule.get("name") or rid,
                    "rule_short_description": rule.get("short_description"),
                    "message": (res.get("message") or {}).get("text"),
                    "severity": res.get("level") or rule.get("default_level"),
                    "problem_severity": rule.get("problem_severity"),
                    "security_severity": rule.get("security_severity"),
                    "precision": rule.get("precision"),
                    "is_security_rule": rule.get("is_security", False),
                    "cwe": rule.get("cwes") or [],
                    # CodeQL nao emite CVE. Nao ha inferencia aqui: o campo
                    # existe, e e None, e isso e a resposta honesta.
                    "cve": None,
                    "tool": tool,
                    "fingerprint": fp,
                    "fingerprint_basis": basis,
                    # O artefato e um snapshot unico: nao ha duas varreduras
                    # do mesmo repositorio, entao first/last seen nao existem.
                    "first_seen": None,
                    "last_seen": None,
                    "has_fix_info": bool(res.get("fixes")),
                    "raw_source_reference": {
                        "zip": os.path.basename(ARTIFACT),
                        "member": m,
                        "run_index": run_i,
                        "result_index": res_i,
                    },
                })

    dupes = sum(1 for v in dupe_probe.values() if v > 1)
    rec = DatasetRecord(
        dataset_id="codeql-emboss-issta2025",
        dataset_name="CodeQL SARIF sobre repositorios EMBOSS (artefato ISSTA 2025)",
        source="Zenodo — ISSTA 2025 artifact, purs3lab/ISSTA-2025-EMBOSS-Artifact",
        source_url=SOURCE_URL,
        version="zenodo record 15200316 (2025-04-11)",
        classification="REAL_EXTERNAL_DATA",
        record_count=len(findings),
        file_path=ARTIFACT,
        license_or_usage_notes=(
            "Artefato academico publico. O registro Zenodo nao declara licenca explicita "
            "(metadata.license = null); usado aqui como dado de pesquisa citado."),
        notes=(
            f"Lido direto do zip, que nao foi extraido nem modificado. "
            f"{len(members)} arquivos SARIF. Fingerprints colidentes: {dupes}. "
            f"CodeQL nao emite CVE: o campo cve e None em 100% dos registros, por construcao."),
    )
    path = write_processed(SARIF_DATASET, findings, rec)
    print(f"  findings normalizados: {len(findings)}")
    print(f"  fingerprints repetidos: {dupes}")
    print(f"  gravado em            : {os.path.relpath(path)}")
    return findings


if __name__ == "__main__":
    if "--survey" in sys.argv:
        survey()
    else:
        ingest()
