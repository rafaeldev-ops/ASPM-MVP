#!/usr/bin/env python3
"""
Proveniencia de dataset para a validacao do Ring 0.

Regra que este modulo existe para tornar mecanica, nao opcional:

    Todo registro que entra no experimento carrega de onde veio, quando foi
    lido, e o hash do arquivo de onde saiu.

E a classificacao da origem e obrigatoria e explicita:

    REAL_EXTERNAL_DATA  -- veio de uma fonte externa real (CISA KEV, SARIF do
                           CodeQL). Nao foi produzido por nos.
    DERIVED_DATA        -- calculado por uma regra deste experimento a partir
                           de dado real. Nao e observacao, e conclusao nossa.
    SYNTHETIC_DATA      -- fabricado para o experimento. NAO e o que uma
                           organizacao real decidiu, e nunca pode ser lido
                           como se fosse.

Nao existe default. Quem escreve um dataset escolhe a classificacao, porque a
classe errada em silencio e exatamente o modo de falha que este arquivo tenta
impedir -- CLAUDE.md secao 8 (evidencia carrega proveniencia) e o item 3 do
briefing do Ring 0.

Somente biblioteca padrao.
"""

import hashlib
import json
import os
from datetime import datetime, timezone

CLASSIFICATIONS = ("REAL_EXTERNAL_DATA", "DERIVED_DATA", "SYNTHETIC_DATA")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RAW_DIR = os.path.join(REPO_ROOT, "datasets", "raw")
PROCESSED_DIR = os.path.join(REPO_ROOT, "datasets", "processed")
METADATA_DIR = os.path.join(REPO_ROOT, "datasets", "metadata")
MANIFEST_PATH = os.path.join(METADATA_DIR, "manifest.json")


def utc_now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_file(path, chunk=1 << 20):
    """SHA-256 em streaming: os artefatos aqui chegam a 95MB."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def md5_file(path, chunk=1 << 20):
    """Existe so para conferir contra o checksum publicado pelo Zenodo."""
    h = hashlib.md5()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


class DatasetRecord:
    """Um registro de dataset. Os campos sao os exigidos pelo briefing, item 2."""

    def __init__(self, dataset_id, dataset_name, source, source_url, version,
                 classification, record_count, file_path=None, file_sha256=None,
                 license_or_usage_notes="", derived_from=None, notes="",
                 content_sha256=None):
        if classification not in CLASSIFICATIONS:
            raise ValueError(
                f"classification deve ser uma de {CLASSIFICATIONS}, veio {classification!r}")

        self.dataset_id = dataset_id
        self.dataset_name = dataset_name
        self.source = source
        self.source_url = source_url
        self.retrieved_at = utc_now_iso()
        self.version = version
        self.classification = classification
        self.record_count = record_count
        self.file_path = file_path
        self.file_sha256 = file_sha256 or (sha256_file(file_path) if file_path else None)
        # Hash SO dos registros, sem o bloco de proveniencia. O file_sha256 de um
        # dataset processado muda a cada execucao porque `retrieved_at` esta
        # dentro do arquivo -- o que torna aquele hash inutil para verificar
        # conteudo. Este e o hash que responde "o dado e o mesmo?".
        self.content_sha256 = content_sha256
        self.license_or_usage_notes = license_or_usage_notes
        # De quais dataset_ids este derivou. Vazio para dado externo real.
        self.derived_from = list(derived_from or [])
        self.notes = notes

    def to_dict(self):
        return {
            "dataset_id": self.dataset_id,
            "dataset_name": self.dataset_name,
            "source": self.source,
            "source_url": self.source_url,
            "retrieved_at": self.retrieved_at,
            "version": self.version,
            "classification": self.classification,
            "record_count": self.record_count,
            "file_path": (os.path.relpath(self.file_path, REPO_ROOT).replace("\\", "/")
                          if self.file_path else None),
            "file_sha256": self.file_sha256,
            "content_sha256": self.content_sha256,
            "license_or_usage_notes": self.license_or_usage_notes,
            "derived_from": self.derived_from,
            "notes": self.notes,
        }


def load_manifest():
    if not os.path.exists(MANIFEST_PATH):
        return {"generated_at": None, "datasets": []}
    with open(MANIFEST_PATH, encoding="utf-8") as f:
        return json.load(f)


def upsert(record):
    """Idempotente por dataset_id: reingerir o mesmo dataset substitui a entrada,
    nao duplica. O briefing (item 6) exige idempotencia na ingestao."""
    m = load_manifest()
    m["datasets"] = [d for d in m["datasets"] if d["dataset_id"] != record.dataset_id]
    m["datasets"].append(record.to_dict())
    m["datasets"].sort(key=lambda d: d["dataset_id"])
    m["generated_at"] = utc_now_iso()
    os.makedirs(METADATA_DIR, exist_ok=True)
    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(m, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return record


def write_processed(filename, payload, record):
    """Grava um dataset processado e registra sua proveniencia no manifesto.

    O arquivo carrega o bloco `_provenance` dentro dele: um dataset processado
    que perde o manifesto ainda diz de onde veio.
    """
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    path = os.path.join(PROCESSED_DIR, filename)

    # Hash do conteudo ANTES de embutir a proveniencia, e em forma canonica
    # (chaves ordenadas, sem espaco). E este o numero que reexecutar o pipeline
    # tem que reproduzir; o file_sha256 nao reproduz, porque `retrieved_at`
    # muda a cada run. Descoberto testando a reprodutibilidade, nao presumido.
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    record.content_sha256 = sha256_bytes(canonical.encode("utf-8"))

    body = {"_provenance": record.to_dict(), "records": payload}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(body, f, indent=2, ensure_ascii=False, default=str)
        f.write("\n")
    record.file_path = path
    record.file_sha256 = sha256_file(path)
    upsert(record)
    return path


def read_processed(filename):
    path = os.path.join(PROCESSED_DIR, filename)
    with open(path, encoding="utf-8") as f:
        body = json.load(f)
    return body["_provenance"], body["records"]
