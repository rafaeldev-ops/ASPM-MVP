"""
CSRF no servidor local.

O teste que importa nao e "o formulario funciona": e **o ataque nao funciona**.
Cada caso abaixo simula uma pagina remota dirigindo o navegador do usuario
contra `127.0.0.1`, que e a ameaca que este controle existe para impedir.

O caso mais caro tem nome: trocar o provider de IA para um externo e disparar
analise. Seria egresso de dado de seguranca para um terceiro escolhido pelo
atacante, a partir de uma aba aberta.
"""

import json
import re
import unittest
import urllib.error
import urllib.request

from tests import support  # noqa: F401
from tests.test_api import ServidorVivo

from app.interfaces.security import origem_local


class TestOrigemLocal(unittest.TestCase):
    """A funcao pura, antes do servidor."""

    def test_aceita_esta_maquina(self):
        for url in ("http://127.0.0.1:8000", "http://localhost:8000/aspm",
                    "http://127.0.0.1:9999/x", "http://[::1]:8000"):
            with self.subTest(url=url):
                self.assertTrue(origem_local(url))

    def test_recusa_o_resto(self):
        for url in ("https://evil.example", "http://192.168.0.10:8000",
                    "http://127.0.0.1.evil.com", "http://localhost.evil.com",
                    "https://sub.127.0.0.1.nip.io"):
            with self.subTest(url=url):
                self.assertFalse(origem_local(url), f"{url} passou")

    def test_recusa_origem_opaca(self):
        """`null` vem de iframe sandbox e de `data:`. Nao da para provar
        procedencia, entao nao passa."""
        for valor in ("null", "", None):
            self.assertFalse(origem_local(valor))


class TestCsrfVivo(ServidorVivo):
    """Contra o servidor de verdade, com os cabecalhos que um navegador manda."""

    def _pedir(self, path, dados=b"", cabecalhos=None, metodo="POST"):
        req = urllib.request.Request(self.base + path, data=dados, method=metodo)
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        for k, v in (cabecalhos or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")

    def _token_e_cookie(self):
        """Faz o que o navegador faz: carrega a pagina, guarda o cookie, le o
        campo oculto."""
        req = urllib.request.Request(self.base + "/aspm")
        with urllib.request.urlopen(req, timeout=20) as r:
            html = r.read().decode("utf-8", "replace")
            bruto = r.headers.get("Set-Cookie") or ""
        cookie = re.search(r"sdip_csrf=([^;]+)", bruto)
        campo = re.search(r'name="_csrf" value="([^"]+)"', html)
        self.assertTrue(cookie, "o servidor nao emitiu o cookie")
        self.assertTrue(campo, "a pagina nao trouxe o campo oculto")
        return campo.group(1), f"sdip_csrf={cookie.group(1)}"

    # ---------------- o ataque ----------------

    def test_pagina_remota_nao_consegue_disparar_acao(self):
        codigo, corpo = self._pedir(
            "/aspm/actions/demo", cabecalhos={"Origin": "https://evil.example"})
        self.assertEqual(codigo, 403)
        self.assertIn("origem", corpo.lower())

    def test_pagina_remota_nao_consegue_trocar_o_provider_de_ia(self):
        """O caso mais caro: egresso para um terceiro escolhido pelo atacante."""
        carga = b"provider=openai&base_url=https%3A%2F%2Fevil.example%2Fv1"
        codigo, _ = self._pedir("/aspm/actions/settings/ai", carga,
                                {"Origin": "https://evil.example"})
        self.assertEqual(codigo, 403)

        _, body = self.get("/api/v1/settings/ai")
        self.assertEqual(json.loads(body)["provider"], "null",
                         "a configuracao mudou apesar da recusa")

    def test_referer_de_fora_tambem_e_recusado(self):
        """Navegador antigo pode mandar so `Referer`."""
        codigo, _ = self._pedir("/aspm/actions/demo",
                                cabecalhos={"Referer": "https://evil.example/x"})
        self.assertEqual(codigo, 403)

    def test_origem_opaca_e_recusada(self):
        codigo, _ = self._pedir("/aspm/actions/demo", cabecalhos={"Origin": "null"})
        self.assertEqual(codigo, 403)

    def test_host_parecido_nao_engana(self):
        """`127.0.0.1.evil.com` resolve para o atacante e contem a string toda."""
        codigo, _ = self._pedir(
            "/aspm/actions/demo",
            cabecalhos={"Origin": "http://127.0.0.1.evil.com"})
        self.assertEqual(codigo, 403)

    def test_api_tambem_e_protegida_e_responde_json(self):
        codigo, corpo = self._pedir(
            "/api/v1/findings/1/analyze", b"{}",
            {"Origin": "https://evil.example", "Content-Type": "application/json"})
        self.assertEqual(codigo, 403)
        self.assertIn("detail", json.loads(corpo))

    # ---------------- o token, segunda camada ----------------

    def test_mesma_origem_sem_token_nao_passa(self):
        """Cobre o navegador que nao mandasse `Origin`: a origem sozinha nao
        basta para as rotas de formulario."""
        codigo, _ = self._pedir("/aspm/actions/demo",
                                cabecalhos={"Origin": self.base})
        self.assertEqual(codigo, 403)

    def test_token_de_outra_sessao_nao_passa(self):
        token, _ = self._token_e_cookie()
        outro, cookie = self._token_e_cookie()
        codigo, _ = self._pedir(
            "/aspm/actions/demo", f"_csrf={token}xx".encode(),
            {"Origin": self.base, "Cookie": cookie})
        self.assertEqual(codigo, 403)

    # ---------------- o caminho legitimo ----------------

    def test_o_formulario_da_propria_tela_funciona(self):
        token, cookie = self._token_e_cookie()
        codigo, _ = self._pedir(
            "/aspm/actions/demo", f"_csrf={token}".encode(),
            {"Origin": self.base, "Cookie": cookie})
        self.assertIn(codigo, (200, 303),
                      "o caminho legitimo quebrou -- controle que atrapalha o "
                      "usuario vira controle desligado")

    def test_toda_tela_entrega_o_campo(self):
        """Uma tela sem o campo e um botao que nao funciona mais."""
        for path in ("/aspm", "/aspm/findings", "/aspm/review",
                     "/aspm/settings", "/aspm/timeline", "/"):
            with self.subTest(path=path):
                _, html = self.get(path)
                if "<form" in html and 'method="post"' in html.lower():
                    self.assertIn('name="_csrf"', html, f"{path} tem form sem token")

    def test_script_sem_navegador_continua_usando_a_api(self):
        """Decisao registrada em `security.py`: sem `Origin` nao e navegador, e
        um script local ja abre o banco direto -- bloquear nao tira capacidade
        nenhuma do atacante e custa a API."""
        _, body = self.get("/api/v1/overview")
        self.assertGreater(json.loads(body)["findings"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
