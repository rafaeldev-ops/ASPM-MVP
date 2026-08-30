"""
Selecao de provider, disponibilidade e modos de falha.

Servidores falsos em 127.0.0.1, sem rede de verdade e sem dependencia nova. O
**contador de requisicoes** do servidor falso e o que torna verificavel a parte
que mais importa: quantas vezes -- e se -- alguma coisa foi enviada.
"""

import os
import unittest

from tests import support
from tests.support import (
    FakeServer, analysis_payload, configure_ai, fresh_session, ollama_ok,
    openai_ok,
)

from app.application import ai
from app.application.ai import contract, prompt, redaction, service
from app.application.ai.context import build_context
from app.application.ai.provider import EgressClass
from app.application.ai.providers.ollama import NotLoopbackError, OllamaProvider


class BaseAI(unittest.TestCase):
    def setUp(self):
        ai.reset()
        self.s = fresh_session()
        self._env = dict(os.environ)
        os.environ.pop("SDIP_AI_PROVIDER", None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)
        ai.reset()
        self.s.close()

    def finding(self):
        f = support.a_finding_with_evidence(self.s)
        if f is None:
            self.skipTest("catalogo KEV indisponivel")
        return f


class TestSelecao(BaseAI):

    def test_padrao_e_determinismo_sem_egresso(self):
        info = ai.provider_info(self.s)
        self.assertEqual(info["provider"], "null")
        self.assertEqual(info["egress"], "none")
        self.assertFalse(info["external"])

    def test_teto_de_tres_providers(self):
        """O mecanismo que sustenta a entrada WON'T do backlog (ADR-0018 §1).

        Um quarto provider exige editar a ADR e este teste no mesmo commit.
        """
        self.assertEqual(len(ai.registry()), 3)
        self.assertEqual(set(ai.registry()), {"null", "ollama", "openai"})

    def test_troca_vale_sem_reiniciar(self):
        """A regressao do global `_active`, que lia o ambiente uma vez e
        memoizava para sempre."""
        self.assertEqual(ai.get_provider(self.s).name, "null")
        configure_ai(self.s, provider="ollama")
        self.assertEqual(ai.get_provider(self.s).name, "ollama")
        configure_ai(self.s, provider="null")
        self.assertEqual(ai.get_provider(self.s).name, "null")

    def test_ambiente_vence_o_banco(self):
        configure_ai(self.s, provider="openai")
        os.environ["SDIP_AI_PROVIDER"] = "null"
        ai.reset()
        self.assertEqual(ai.get_provider(self.s).name, "null")

    def test_nome_desconhecido_cai_para_null_e_fica_registrado(self):
        configure_ai(self.s, provider="gemini")
        info = ai.provider_info(self.s)
        self.assertEqual(info["provider"], "null")
        self.assertEqual(info["requested"], "gemini")

    def test_egresso_por_provider(self):
        self.assertIs(ai.registry()["null"].egress, EgressClass.NONE)
        self.assertIs(ai.registry()["ollama"].egress, EgressClass.LOCALHOST)
        self.assertIs(ai.registry()["openai"].egress, EgressClass.THIRD_PARTY)
        self.assertFalse(ai.registry()["ollama"](None).is_external)
        self.assertTrue(ai.registry()["openai"](None).is_external)


class TestDisponibilidade(BaseAI):

    def test_runtime_indisponivel_nao_derruba(self):
        with FakeServer() as srv:
            pass  # sobe e derruba: a porta fica morta
        configure_ai(self.s, provider="ollama", base_url=srv.base, model="x")
        status = ai.get_provider(self.s).status()
        self.assertFalse(status.available)
        self.assertIn("runtime", status.detail.lower())

    def test_ollama_sem_modelo_baixado(self):
        with FakeServer() as srv:
            srv.json_route("/api/version", {"version": "0.1"})
            srv.json_route("/api/tags", {"models": []})
            configure_ai(self.s, provider="ollama", base_url=srv.base)
            status = ai.get_provider(self.s).status()
        self.assertFalse(status.available)
        self.assertIn("modelo", status.detail.lower())

    def test_ollama_lista_modelos(self):
        with FakeServer() as srv:
            srv.json_route("/api/version", {"version": "0.9"})
            srv.json_route("/api/tags", {"models": [{"name": "a"}, {"name": "b"}]})
            configure_ai(self.s, provider="ollama", base_url=srv.base)
            status = ai.get_provider(self.s).status()
        self.assertTrue(status.available)
        self.assertEqual(status.models, ("a", "b"))

    def test_provider_info_nao_sonda(self):
        """Ele esta no caminho quente (`/aspm`, `/api/v1/overview`).

        Se sondasse, toda renderizacao do painel pagaria o timeout de um runtime
        morto. O segundo acesso tem que vir do cache.
        """
        with FakeServer() as srv:
            srv.json_route("/api/version", {"version": "1"})
            srv.json_route("/api/tags", {"models": [{"name": "m"}]})
            configure_ai(self.s, provider="ollama", base_url=srv.base, model="m")
            ai.provider_info(self.s)
            antes = srv.count
            for _ in range(5):
                ai.provider_info(self.s)
            self.assertEqual(srv.count, antes, "provider_info sondou mais de uma vez")

    def test_openai_sem_chave(self):
        configure_ai(self.s, provider="openai", model="gpt-x")
        status = ai.get_provider(self.s).status()
        self.assertFalse(status.available)
        self.assertIn("chave", status.detail.lower())


class TestLoopback(BaseAI):
    """`localhost` e verificado, nao declarado."""

    def test_recusa_host_nao_loopback(self):
        p = OllamaProvider(_settings(base_url="http://example.com:11434", model="m"))
        with self.assertRaises(NotLoopbackError):
            p._assert_loopback()

    def test_aceita_loopback(self):
        p = OllamaProvider(_settings(base_url="http://127.0.0.1:11434", model="m"))
        self.assertTrue(p._assert_loopback())

    def test_ignora_http_proxy(self):
        """A armadilha do proxy.

        Com HTTP_PROXY apontando para o servidor A e o Ollama para o B, o pedido
        tem que chegar em B. Se saisse pelo proxy, o dado deixaria a maquina
        enquanto a interface exibe o selo `local`.
        """
        f = self.finding()
        with FakeServer() as proxy, FakeServer() as ollama:
            proxy.json_route("/", {})
            ollama.json_route("/api/chat", ollama_ok(analysis_payload()))
            os.environ["HTTP_PROXY"] = proxy.base
            os.environ["http_proxy"] = proxy.base
            configure_ai(self.s, provider="ollama", base_url=ollama.base, model="m")
            service.analyze_finding(self.s, f, confirmed_egress="localhost")
            self.assertGreaterEqual(ollama.count, 1, "o Ollama nao recebeu o pedido")
            self.assertEqual(proxy.count, 0, "o pedido saiu pelo proxy corporativo")


class TestFalhas(BaseAI):

    def _run(self, srv_setup, provider="ollama", **cfg):
        f = self.finding()
        with FakeServer() as srv:
            srv_setup(srv)
            configure_ai(self.s, provider=provider, base_url=srv.base,
                         model="m", **cfg)
            rec = service.analyze_finding(self.s, f)
            return rec, srv

    def test_modelo_invalido_faz_uma_requisicao_so(self):
        rec, srv = self._run(lambda s: s.route("/api/chat", status=404))
        self.assertEqual(rec.outcome, contract.UNAVAILABLE)
        chat = [r for r in srv.requests if r[0] == "/api/chat"]
        self.assertEqual(len(chat), 1, "404 nao pode ser repetido: nao muda nada "
                                       "e cada tentativa e outro egresso")

    def test_timeout(self):
        rec, _ = self._run(
            lambda s: s.json_route("/api/chat", ollama_ok(analysis_payload()), delay=1.0),
            timeout_s="0.3")
        self.assertEqual(rec.outcome, contract.TIMEOUT)

    def test_resposta_malformada(self):
        rec, _ = self._run(lambda s: s.route(
            "/api/chat", body='{"message":{"content":"isto nao e json"}}'))
        self.assertEqual(rec.outcome, contract.MALFORMED)

    def test_openai_recusa(self):
        f = self.finding()
        with FakeServer() as srv:
            srv.json_route("/chat/completions", {
                "choices": [{"message": {"refusal": "nao posso"},
                             "finish_reason": "stop"}]})
            os.environ["SDIP_OPENAI_API_KEY"] = "sk-teste-0000000000000000000"
            configure_ai(self.s, provider="openai", base_url=srv.base, model="m")
            rec = service.analyze_finding(self.s, f)
        self.assertEqual(rec.outcome, contract.REFUSED)

    def test_openai_choices_vazio_nao_vira_indexerror(self):
        """O bug que a ADR-0015 §6 nomeia: indexar `choices[0]` sem olhar."""
        f = self.finding()
        with FakeServer() as srv:
            srv.json_route("/chat/completions", {"choices": []})
            os.environ["SDIP_OPENAI_API_KEY"] = "sk-teste-0000000000000000000"
            configure_ai(self.s, provider="openai", base_url=srv.base, model="m")
            rec = service.analyze_finding(self.s, f)
        self.assertEqual(rec.outcome, contract.MALFORMED)

    def test_retry_so_onde_deve(self):
        f = self.finding()
        with FakeServer() as srv:
            srv.json_route("/chat/completions", openai_ok(analysis_payload()),
                           status=429, times=1)
            os.environ["SDIP_OPENAI_API_KEY"] = "sk-teste-0000000000000000000"
            configure_ai(self.s, provider="openai", base_url=srv.base, model="m")
            rec = service.analyze_finding(self.s, f)
            self.assertGreaterEqual(rec.attempts, 2)

        with FakeServer() as srv:
            srv.route("/chat/completions", status=401)
            configure_ai(self.s, provider="openai", base_url=srv.base, model="m")
            rec = service.analyze_finding(self.s, f)
            self.assertEqual(rec.outcome, contract.UNAVAILABLE)
            self.assertEqual(len([r for r in srv.requests
                                  if r[0] == "/chat/completions"]), 1)

    def test_analise_falha_tambem_e_gravada(self):
        """Registrar so sucesso destruiria a taxa de recusa -- que a ADR-0015 §2
        diz poder ser o criterio que decide o fornecedor."""
        rec, _ = self._run(lambda s: s.route("/api/chat", status=500))
        self.assertIsNotNone(rec.id)
        self.assertFalse(rec.ok)
        self.assertTrue(rec.error_detail)


class TestPrompt(BaseAI):

    def test_prefixo_e_byte_estavel(self):
        """ADR-0015 §5: nada de data, id ou nome interpolado no system prompt."""
        h1 = prompt.prompt_hash()
        h2 = prompt.prompt_hash()
        self.assertEqual(h1, h2)
        self.assertNotIn("2026", prompt.SYSTEM_PROMPT)

    def test_system_prompt_nao_vem_do_banco(self):
        """ADR-0007: o system prompt nunca e montado a partir de conteudo do banco."""
        f = self.finding()
        ctx = build_context(self.s, f)
        red = redaction.redact(ctx, egress=EgressClass.NONE)
        msgs = prompt.build_messages(red)
        system = msgs[0]["content"]
        for probe in (f.title, f.cve or "zzz", "svc-teste"):
            self.assertNotIn(probe, system)
        self.assertIn("NAO CONFIAVEL", msgs[1]["content"])


def _settings(**kw):
    from app.application.ai.settings import AISettings
    return AISettings(**kw)


if __name__ == "__main__":
    unittest.main(verbosity=2)
