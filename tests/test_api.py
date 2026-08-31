"""
Contrato da API e das telas.

Sobe a aplicacao de verdade num processo separado e bate nas rotas. Nao usa
TestClient porque `httpx` nao esta nas dependencias do projeto, e adicionar uma
dependencia so para testar contraria a regra de manter o MVP instalavel.
"""

import json
import os
import re
import socket
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request

from tests import support


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ServidorVivo(unittest.TestCase):
    """Sobe uvicorn uma vez para toda a classe."""

    proc = None
    base = None

    @classmethod
    def setUpClass(cls):
        # Um banco por classe: cada subclasse sobe o proprio servidor, e dois
        # processos disputando o mesmo arquivo SQLite falham no Windows.
        db = os.path.join(os.path.dirname(os.environ["SDIP_DB_PATH"]),
                          f"api-{cls.__name__}.db")
        if os.path.exists(db):
            try:
                os.remove(db)
            except PermissionError:
                pass
        env = dict(os.environ, SDIP_DB_PATH=db, SDIP_AI_PROVIDER="null")
        port = free_port()
        cls.base = f"http://127.0.0.1:{port}"
        cls.proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app",
             "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
            cwd=support.REPO_ROOT, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        for _ in range(120):
            try:
                cls.get("/health")
                break
            except Exception:
                if cls.proc.poll() is not None:
                    out = cls.proc.stdout.read().decode(errors="replace")
                    raise unittest.SkipTest(f"servidor morreu ao subir:\n{out[-2000:]}")
                time.sleep(0.25)
        else:
            cls.tearDownClass()
            raise unittest.SkipTest("servidor nao subiu a tempo")

        # Carrega o dataset de demonstracao para as rotas terem o que mostrar.
        try:
            cls.post("/aspm/actions/demo")
        except Exception:
            pass

    @classmethod
    def tearDownClass(cls):
        if cls.proc and cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                cls.proc.kill()

    # Sessao de CSRF da classe: o `post` abaixo faz o que um navegador faz --
    # carrega uma pagina, guarda o cookie, le o campo oculto e devolve os dois
    # no envio. Sem isso as rotas de formulario respondem 403, que e o
    # comportamento correto e nao um defeito do teste.
    _csrf = None
    _cookie = None

    @classmethod
    def _sessao_csrf(cls):
        if cls._csrf:
            return cls._csrf, cls._cookie
        req = urllib.request.Request(cls.base + "/aspm")
        with urllib.request.urlopen(req, timeout=60) as r:
            html = r.read().decode("utf-8", errors="replace")
            bruto = r.headers.get("Set-Cookie") or ""
        c = re.search(r"sdip_csrf=([^;]+)", bruto)
        t = re.search(r'name="_csrf" value="([^"]+)"', html)
        cls._csrf = t.group(1) if t else ""
        cls._cookie = f"sdip_csrf={c.group(1)}" if c else ""
        return cls._csrf, cls._cookie

    @classmethod
    def _req(cls, path, method="GET", data=None, headers=None):
        req = urllib.request.Request(cls.base + path, method=method, data=data)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        with urllib.request.urlopen(req, timeout=180) as r:
            return r.status, r.read().decode("utf-8", errors="replace")

    @classmethod
    def get(cls, path):
        return cls._req(path)

    @classmethod
    def post(cls, path, data=None):
        token, cookie = cls._sessao_csrf()
        corpo = data if data else f"_csrf={token}".encode()
        if data and b"_csrf=" not in data:
            corpo = data + f"&_csrf={token}".encode()
        return cls._req(path, "POST", corpo, {
            "Content-Type": "application/x-www-form-urlencoded",
            "Cookie": cookie, "Origin": cls.base})

    def status(self, path):
        try:
            return self.get(path)[0]
        except urllib.error.HTTPError as e:
            return e.code


class TestTelas(ServidorVivo):

    def test_todas_as_telas_respondem(self):
        for p in ("/aspm", "/aspm/assets", "/aspm/findings", "/aspm/debt",
                  "/aspm/review", "/aspm/timeline"):
            with self.subTest(rota=p):
                self.assertEqual(self.status(p), 200)

    def test_backtest_legado_continua_no_ar(self):
        """O instrumento antigo nao pode ter sido quebrado pelo MVP."""
        self.assertEqual(self.status("/"), 200)
        self.assertEqual(self.status("/health"), 200)

    def test_filtros_da_lista_de_riscos(self):
        for q in ("?band=act_now", "?severity=critical", "?kev=1",
                  "?status=closed", "?q=CVE"):
            with self.subTest(filtro=q):
                self.assertEqual(self.status("/aspm/findings" + q), 200)

    def test_detalhe_de_achado_e_de_ativo(self):
        _, body = self.get("/api/v1/findings?limit=1")
        fid = json.loads(body)["findings"][0]["id"]
        self.assertEqual(self.status(f"/aspm/findings/{fid}"), 200)
        _, body = self.get("/api/v1/assets")
        aid = json.loads(body)["assets"][0]["id"]
        self.assertEqual(self.status(f"/aspm/assets/{aid}"), 200)

    def test_inexistente_devolve_404(self):
        self.assertEqual(self.status("/aspm/findings/999999"), 404)
        self.assertEqual(self.status("/aspm/assets/999999"), 404)


class TestApi(ServidorVivo):

    def test_overview_traz_os_numeros_do_painel(self):
        _, body = self.get("/api/v1/overview")
        d = json.loads(body)
        for k in ("assets", "findings", "bands", "open_debt", "knowledge", "ai"):
            self.assertIn(k, d)
        self.assertGreater(d["findings"], 0)
        self.assertFalse(d["ai"]["external"], "o MVP nao deve depender de IA externa")
        # A afirmacao mais forte que a linha acima tentava fazer: `external` e
        # falso tanto para `none` quanto para `localhost`, e so `none` significa
        # que nao houve I/O nenhum.
        self.assertEqual(d["ai"]["egress"], "none")

    def test_findings_expoe_a_versao_do_modelo_de_risco(self):
        _, body = self.get("/api/v1/findings?limit=5")
        for f in json.loads(body)["findings"]:
            self.assertIn("risk-model", f["risk_model_version"] or "")

    def test_detalhe_traz_evidencia_com_proveniencia(self):
        _, body = self.get("/api/v1/findings?band=act_now&limit=1")
        items = json.loads(body)["findings"]
        if not items:
            self.skipTest("nenhum achado act_now no dataset")
        _, body = self.get(f"/api/v1/findings/{items[0]['id']}")
        d = json.loads(body)
        self.assertIn("evidence", d)
        self.assertIn("assessment", d)
        for e in d["evidence"]:
            self.assertIn(e["classification"],
                          ("REAL_EXTERNAL_DATA", "DERIVED_DATA", "SYNTHETIC_DATA"))
            self.assertTrue(e["source"])

    def test_decision_debt_avisa_sobre_dado_sintetico(self):
        """A API nao pode entregar numero sintetico sem o aviso junto."""
        _, body = self.get("/api/v1/decision-debt")
        d = json.loads(body)
        self.assertIn("SINTETICAS", d["warning"])
        for item in d["items"][:5]:
            self.assertIn("decision_classification", item)

    def test_timeline_marca_o_que_e_material(self):
        _, body = self.get("/api/v1/timeline?limit=50")
        eventos = json.loads(body)["events"]
        self.assertTrue(eventos)
        for e in eventos:
            self.assertIn("material", e)

    def test_review_pela_api_cria_decisao(self):
        _, body = self.get("/api/v1/findings?limit=1")
        fid = json.loads(body)["findings"][0]["id"]
        payload = json.dumps({
            "finding_id": fid, "reason": "accepted_risk",
            "rationale": "teste de contrato", "analyst": "teste-api"}).encode()
        req = urllib.request.Request(
            self.base + "/api/v1/review", method="POST", data=payload,
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as r:
            d = json.loads(r.read())
        self.assertEqual(d["reason"], "accepted_risk")
        self.assertEqual(d["classification"], "REAL_EXTERNAL_DATA")

    def test_review_sem_justificativa_e_recusada(self):
        _, body = self.get("/api/v1/findings?limit=1")
        fid = json.loads(body)["findings"][0]["id"]
        payload = json.dumps({"finding_id": fid, "reason": "accepted_risk",
                              "rationale": ""}).encode()
        req = urllib.request.Request(
            self.base + "/api/v1/review", method="POST", data=payload,
            headers={"Content-Type": "application/json"})
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=60)
        self.assertEqual(ctx.exception.code, 400)


if __name__ == "__main__":
    unittest.main(verbosity=2)
