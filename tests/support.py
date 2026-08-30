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


# --------------------------------------------------------------------------
# Servidores falsos, para exercitar os adaptadores sem rede
# --------------------------------------------------------------------------

import json as _json
import socket as _socket
import threading as _threading
import time as _time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def free_port():
    with _socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class FakeServer:
    """Servidor programavel em 127.0.0.1.

    O **contador de requisicoes** e o que torna "nenhuma transmissao acidental"
    verificavel: um teste de privacidade afirma que ele fica em zero.
    """

    def __init__(self):
        self.requests = []          # [(caminho, corpo)]
        self.routes = {}            # caminho -> (status, corpo, atraso)
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self._srv = None
        self._thread = None

    def route(self, path, status=200, body=None, delay=0.0, times=None):
        self.routes[path] = {"status": status, "body": body, "delay": delay,
                             "times": times, "used": 0}
        return self

    def json_route(self, path, payload, status=200, delay=0.0, times=None):
        return self.route(path, status, _json.dumps(payload), delay, times)

    @property
    def count(self):
        return len(self.requests)

    def start(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _serve(self, body_in=None):
                # O teste de timeout desiste enquanto ainda escrevemos. Isso e o
                # comportamento esperado -- nao vale poluir a saida com o
                # traceback do socket abortado.
                try:
                    self._serve_inner(body_in)
                except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
                    pass

            def _serve_inner(self, body_in=None):
                outer.requests.append((self.path, body_in))
                spec = outer.routes.get(self.path)
                if spec is None:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b"{}")
                    return
                if spec["delay"]:
                    _time.sleep(spec["delay"])
                status = spec["status"]
                # `times` permite 429-depois-200 sem estado no teste
                if spec["times"] is not None and spec["used"] >= spec["times"]:
                    status = 200
                spec["used"] += 1
                payload = (spec["body"] or "{}").encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_GET(self):
                self._serve()

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                self._serve(self.rfile.read(n).decode("utf-8", "replace") if n else "")

        self._srv = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self._thread = _threading.Thread(target=self._srv.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        if self._srv:
            self._srv.shutdown()
            self._srv.server_close()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()


def ollama_ok(payload):
    """Resposta bem-formada do /api/chat."""
    return {"model": "fake", "message": {"content": _json.dumps(payload)},
            "prompt_eval_count": 10, "eval_count": 20, "done_reason": "stop"}


def openai_ok(payload):
    return {"model": "fake", "choices": [
        {"message": {"content": _json.dumps(payload)}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 20}}


def analysis_payload(evidence_ids=(), reason=""):
    return {"summary": "resumo de teste",
            "risk_explanation": "explicacao de teste",
            "recommended_action": "acao de teste",
            "recommended_reason": reason,
            "evidence_ids": list(evidence_ids),
            "contradicting_evidence_ids": [],
            "uncertainty_reasons": []}


def configure_ai(session, **values):
    """Grava configuracao e limpa o cache do provider."""
    from app.application import ai
    from app.application.ai import settings as cfg
    cfg.save(session, values)
    session.commit()
    ai.reset()


def a_finding_with_evidence(session):
    """Um achado com ativo, evidencia real de KEV e avaliacao calculada."""
    from app.application import correlation, prioritization
    entry = a_kev_cve(0)
    if entry is None:
        return None
    asset = make_asset(session, "svc-teste", criticality="critical",
                       environment="prod", internet_facing=True)
    f = make_finding(session, asset, cve=entry["cve_id"], title="achado de teste",
                     package_name="openssl", package_version="3.0.7",
                     fixed_version="3.0.8", severity="critical")
    correlation.correlate(session)
    correlation.enrich(session)
    prioritization.prioritize_all(session)
    session.flush()
    return f
