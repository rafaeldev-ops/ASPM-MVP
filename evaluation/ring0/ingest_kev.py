#!/usr/bin/env python3
"""
Ingestao do CISA KEV -- R0-3, na fatia que o Ring 0 precisa.

Le o dataset real de 12 meses em datasets/raw/, valida o schema, normaliza, e
grava um snapshot com hash e proveniencia em datasets/processed/.

O que este modulo tem que responder, e e a razao de existir (briefing item 6):

    Quando este CVE entrou no KEV?
    Qual era seu estado num dado snapshot?
    Ele estava no KEV ANTES da decisao?
    Ele entrou no KEV DEPOIS da decisao?

A ultima pergunta e o produto inteiro. As duas anteriores sao o que impede a
resposta de ser uma leitura as-of-hoje disfarcada.

    python ingest_kev.py            # ingere e grava o snapshot
    python ingest_kev.py --verify   # so revalida o que ja foi gravado

Somente biblioteca padrao.
"""

import csv
import json
import os
import sys
from collections import Counter
from datetime import date, datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from provenance import (  # noqa: E402
    RAW_DIR, DatasetRecord, read_processed, sha256_file, write_processed,
)

KEV_CSV = os.path.join(RAW_DIR, "cisa_kev_12_months_2025-08-24_to_2026-08-23.csv")
KEV_JSON = os.path.join(RAW_DIR, "cisa_kev_12_months_2025-08-24_to_2026-08-23.json")
KEV_SNAPSHOT = "kev_12m_snapshot.json"

SOURCE_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

# Campos que o schema do KEV garante. A ausencia de qualquer um destes nao e
# um campo faltando -- e o arquivo nao ser um export de KEV.
REQUIRED = ("cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded")
OPTIONAL = ("shortDescription", "requiredAction", "dueDate",
            "knownRansomwareCampaignUse", "notes", "cwes")


class SchemaError(Exception):
    pass


def parse_kev_date(s):
    """KEV usa ISO puro. Nao ha heuristica aqui de proposito: uma data que nao
    parseia num feed autoritativo e um erro de schema, nao um campo sujo."""
    if not s or not str(s).strip():
        return None
    return datetime.strptime(str(s).strip(), "%Y-%m-%d").date()


def load_raw():
    """Le o CSV e o JSON e exige que concordem.

    Os dois arquivos sao a mesma informacao em dois formatos. Se divergirem,
    um deles esta corrompido, e descobrir isso agora custa uma comparacao --
    descobrir depois custa um resultado errado que parece certo.
    """
    with open(KEV_CSV, encoding="utf-8-sig", newline="") as f:
        csv_rows = list(csv.DictReader(f))

    with open(KEV_JSON, encoding="utf-8") as f:
        raw = json.load(f)
    if isinstance(raw, dict):
        for k in ("vulnerabilities", "records", "entries", "data"):
            if isinstance(raw.get(k), list):
                raw = raw[k]
                break
    if not isinstance(raw, list):
        raise SchemaError("JSON do KEV nao e uma lista nem tem uma lista conhecida dentro")

    if len(csv_rows) != len(raw):
        raise SchemaError(f"CSV tem {len(csv_rows)} linhas e JSON tem {len(raw)}")

    csv_ids = sorted(r["cveID"] for r in csv_rows)
    json_ids = sorted(r["cveID"] for r in raw)
    if csv_ids != json_ids:
        raise SchemaError("CSV e JSON do KEV nao contem o mesmo conjunto de cveID")

    return csv_rows, raw


def validate(rows):
    problems = []
    seen = Counter()
    for i, r in enumerate(rows):
        for field in REQUIRED:
            if field not in r or not str(r.get(field, "")).strip():
                problems.append(f"linha {i}: campo obrigatorio ausente/vazio: {field}")
        cve = str(r.get("cveID", "")).strip()
        if not cve.upper().startswith("CVE-"):
            problems.append(f"linha {i}: cveID nao parece um CVE: {cve!r}")
        seen[cve] += 1
        try:
            parse_kev_date(r.get("dateAdded"))
        except ValueError as e:
            problems.append(f"linha {i} ({cve}): dateAdded invalido: {e}")

    dupes = {k: v for k, v in seen.items() if v > 1}
    if dupes:
        problems.append(f"cveID duplicado no feed: {dupes}")
    return problems


def normalize(rows):
    """Normaliza SEM descartar o original.

    CLAUDE.md secao 24: nunca destruir informacao especifica da fonte porque o
    schema canonico nao a representa. `raw` carrega a linha inteira.
    """
    out = []
    for r in rows:
        cwes = [c.strip() for c in str(r.get("cwes", "") or "").replace(";", ",").split(",")
                if c.strip()]
        ransom = str(r.get("knownRansomwareCampaignUse", "") or "").strip().lower()
        out.append({
            "cve_id": str(r["cveID"]).strip().upper(),
            "vendor_project": str(r.get("vendorProject", "") or "").strip(),
            "product": str(r.get("product", "") or "").strip(),
            "vulnerability_name": str(r.get("vulnerabilityName", "") or "").strip(),
            "date_added": parse_kev_date(r.get("dateAdded")).isoformat(),
            "due_date": (parse_kev_date(r.get("dueDate")).isoformat()
                         if r.get("dueDate") else None),
            # "known" e o unico valor que a CISA usa para afirmar uso em
            # ransomware. "Unknown" quer dizer nao sabemos, nao "nao".
            "known_ransomware": ransom == "known",
            "ransomware_field_raw": r.get("knownRansomwareCampaignUse"),
            "cwes": cwes,
            "short_description": str(r.get("shortDescription", "") or "").strip(),
            "notes": str(r.get("notes", "") or "").strip(),
            "raw": r,
        })
    out.sort(key=lambda x: (x["date_added"], x["cve_id"]))
    return out


class KevCatalog:
    """O catalogo carregado, com as consultas temporais do briefing item 6.

    Toda consulta exige uma data. Nao existe metodo que responda "esta no KEV?"
    sem um as-of -- e a ausencia desse metodo e proposital.
    """

    def __init__(self, records, provenance=None):
        self.records = records
        self.provenance = provenance
        self.by_cve = {r["cve_id"]: r for r in records}
        dates = [r["date_added"] for r in records]
        self.window_start = min(dates) if dates else None
        self.window_end = max(dates) if dates else None

    @classmethod
    def load(cls):
        prov, records = read_processed(KEV_SNAPSHOT)
        return cls(records, prov)

    @staticmethod
    def _as_date(d):
        if isinstance(d, datetime):
            return d.date()
        if isinstance(d, date):
            return d
        return datetime.strptime(str(d)[:10], "%Y-%m-%d").date()

    def date_added(self, cve_id):
        """Quando este CVE entrou no KEV? None se nao esta neste catalogo."""
        r = self.by_cve.get(str(cve_id).upper())
        return self._as_date(r["date_added"]) if r else None

    def state_as_of(self, cve_id, as_of):
        """O estado do CVE no snapshot daquele dia.

        Retorna IN_KEV, NOT_IN_KEV ou UNKNOWN_OUTSIDE_WINDOW.

        A terceira e a que impede a mentira mais facil deste experimento: este
        dataset cobre 12 meses. Um CVE ausente dele pode nunca ter entrado no
        KEV, ou ter entrado antes da janela. Responder NOT_IN_KEV nos dois
        casos e afirmar algo que o dado nao sustenta.
        """
        as_of = self._as_date(as_of)
        added = self.date_added(cve_id)
        if added is None:
            return "UNKNOWN_OUTSIDE_WINDOW"
        if as_of < self._as_date(self.window_start):
            return "UNKNOWN_OUTSIDE_WINDOW"
        return "IN_KEV" if added <= as_of else "NOT_IN_KEV"

    def was_in_kev_before(self, cve_id, decision_date):
        """Ja estava no KEV no dia da decisao? (o pile "fechado apesar de")"""
        return self.state_as_of(cve_id, decision_date) == "IN_KEV"

    def entered_kev_after(self, cve_id, decision_date):
        """Entrou no KEV depois da decisao? (o pile "divida de decisao")"""
        added = self.date_added(cve_id)
        if added is None:
            return False
        return added > self._as_date(decision_date)

    def entries_between(self, start, end):
        s, e = self._as_date(start), self._as_date(end)
        return [r for r in self.records if s <= self._as_date(r["date_added"]) <= e]


def ingest():
    csv_rows, json_rows = load_raw()
    problems = validate(csv_rows)
    if problems:
        for p in problems[:20]:
            print(f"  SCHEMA: {p}")
        raise SchemaError(f"{len(problems)} problemas de schema no KEV")

    records = normalize(csv_rows)
    rec = DatasetRecord(
        dataset_id="kev-12m-2025-08-24_2026-08-23",
        dataset_name="CISA Known Exploited Vulnerabilities Catalog — janela de 12 meses",
        source="CISA",
        source_url=SOURCE_URL,
        version="window 2025-08-24..2026-08-23",
        classification="REAL_EXTERNAL_DATA",
        record_count=len(records),
        license_or_usage_notes=(
            "Dado publico do governo dos EUA (CISA). Uso publico. Nao contem export de "
            "scanner de organizacao privada nem decisoes historicas de analista."),
        notes=(
            f"Ingerido de dois arquivos que foram exigidos a concordar. "
            f"sha256 CSV={sha256_file(KEV_CSV)} sha256 JSON={sha256_file(KEV_JSON)}"),
    )
    path = write_processed(KEV_SNAPSHOT, records, rec)

    cat = KevCatalog(records, rec.to_dict())
    ransom = sum(1 for r in records if r["known_ransomware"])
    with_cwe = sum(1 for r in records if r["cwes"])
    print(f"  KEV ingerido: {len(records)} entradas")
    print(f"  janela      : {cat.window_start} .. {cat.window_end}")
    print(f"  ransomware  : {ransom} ({ransom/len(records)*100:.1f}%)")
    print(f"  com CWE     : {with_cwe} ({with_cwe/len(records)*100:.1f}%)")
    print(f"  vendors     : {len({r['vendor_project'] for r in records})}")
    print(f"  gravado em  : {os.path.relpath(path)}")
    return cat


def verify():
    cat = KevCatalog.load()
    print(f"  snapshot: {cat.provenance['record_count']} registros, "
          f"sha256 {cat.provenance['file_sha256'][:16]}...")
    print(f"  janela  : {cat.window_start} .. {cat.window_end}")
    print(f"  classe  : {cat.provenance['classification']}")
    return cat


if __name__ == "__main__":
    if "--verify" in sys.argv:
        verify()
    else:
        ingest()
