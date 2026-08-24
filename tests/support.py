"""
Apoio aos testes.

Sem pytest de proposito: o repositorio nao tem suite nem CI, e a regra do
`phase0/` vale aqui -- um instrumento que precisa de instalacao e um instrumento
que nao roda. `unittest` e stdlib e ja esta na maquina.

Este modulo tem que ser importado ANTES de qualquer coisa de `app.`: a engine do
SQLAlchemy e criada no import de `app.db`, a partir de `SDIP_DB_PATH`. Definir a
variavel depois nao teria efeito, e os testes escreveriam no banco de verdade.
"""

import os
import tempfile

_TMP = os.path.join(tempfile.gettempdir(), "sdip-tests")
os.makedirs(_TMP, exist_ok=True)
os.environ.setdefault("SDIP_DB_PATH", os.path.join(_TMP, "test.db"))
os.environ.setdefault("SDIP_AI_PROVIDER", "null")

import sys  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


def fresh_session():
    """Um banco limpo por caso de teste. Cada chamada zera tudo."""
    from app.db import Base, SessionLocal, engine
    from app.domain import models  # noqa: F401  (registra as tabelas)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    return SessionLocal()


def make_asset(session, identifier="svc-teste", **kw):
    from app.application.ingestion import upsert_asset
    a = upsert_asset(session, identifier, name=identifier,
                     source_system="teste", **kw)
    session.flush()
    return a


def make_finding(session, asset=None, **kw):
    from app.domain.models import Finding
    from app.application.ingestion import fingerprint_of
    defaults = {
        "org_id": "org-local", "source_system": "teste",
        "title": kw.pop("title", "achado de teste"),
    }
    defaults.update(kw)
    defaults.setdefault("fingerprint", fingerprint_of(
        defaults["title"], defaults.get("cve"), id(defaults)))
    f = Finding(**defaults)
    f.asset = asset
    session.add(f)
    session.flush()
    return f


def kev_available():
    from app.application import knowledge
    return bool(knowledge.kev().by_cve)


def a_kev_cve(offset=0, ransomware=None):
    """Um CVE REAL do catalogo, escolhido por posicao e nao por nome.

    Escolher pelo nome amarraria o teste a uma entrada continuar existindo no
    catalogo; escolher por posicao amarra so ao catalogo nao estar vazio.
    """
    from app.application import knowledge
    entries = sorted((e for e in knowledge.kev().by_cve.values() if e["date_added"]),
                     key=lambda e: e["date_added"])
    if ransomware is not None:
        entries = [e for e in entries if e["known_ransomware"] is ransomware]
    return entries[offset % len(entries)] if entries else None
