"""
A fronteira de redacao.

Modulo separado de proposito: estas provas precisam ser legiveis como artefato de
seguranca isolado, porque e o que uma revisao de seguranca de cliente vai pedir
para ver.

A ADR-0011 impoe a fronteira por tipo, verificada por MyPy strict. Este
repositorio nao tem MyPy, nem lint, nem CI -- entao o portao de build nao existe,
e o substituto e estrutural. Os testes abaixo sao o que prova que o substituto
funciona.
"""

import json
import os
import unittest

from tests import support
from tests.support import (
    FakeServer, analysis_payload, configure_ai, fresh_session, ollama_ok,
)

from app.application import ai
from app.application.ai import contract, detectors, redaction, service
from app.application.ai.context import FindingContext, build_context
from app.application.ai.provider import AnalysisRequest, EgressClass
from app.application.ai.providers import REGISTRY

# Canarios: strings unicas que so podem aparecer se um campo proibido vazar.
CANARY_RAW = "CANARIO-RAWJSON-b7f3e1a94c2d"
CANARY_RATIONALE = "CANARIO-RATIONALE-4d8a91fe07b2"
CANARY_PATH = "config/prod-db-password.env"


class BasePriv(unittest.TestCase):
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

    def finding(self, **extra):
        f = support.a_finding_with_evidence(self.s)
        if f is None:
            self.skipTest("catalogo KEV indisponivel")
        f.raw_json = json.dumps({"scanner_row": CANARY_RAW, "tudo": "mais"})
        f.file_path = CANARY_PATH
        for k, v in extra.items():
            setattr(f, k, v)
        self.s.flush()
        return f


class TestCamposProibidos(BasePriv):

    def test_raw_json_nunca_entra(self):
        """O maior portador de segredo do banco. Nenhum tier, nenhum provider,
        nem o local."""
        f = self.finding()
        ctx = build_context(self.s, f)
        for egress in EgressClass:
            red = redaction.redact(ctx, egress=egress)
            blob = json.dumps(red.payload, default=str)
            self.assertNotIn(CANARY_RAW, blob, f"raw_json vazou em {egress.value}")
        self.assertNotIn(CANARY_RAW, repr(ctx))
        self.assertNotIn(CANARY_RAW, str(ctx))

    def test_raw_json_nao_chega_ao_registro(self):
        f = self.finding()
        rec = service.analyze_finding(self.s, f, confirmed_egress="none")
        self.s.flush()
        blob = " ".join(str(getattr(rec, c.name) or "")
                        for c in rec.__table__.columns)
        self.assertNotIn(CANARY_RAW, blob)

    def test_rationale_do_analista_fica_fora(self):
        from app.domain.models import Decision
        f = self.finding()
        f.decisions.append(Decision(
            org_id=f.org_id, reason="false_positive",
            rationale=CANARY_RATIONALE, classification="SYNTHETIC_DATA"))
        self.s.flush()
        ctx = build_context(self.s, f)
        red = redaction.redact(ctx, egress=EgressClass.LOCALHOST)
        self.assertNotIn(CANARY_RATIONALE, json.dumps(red.payload, default=str))

    def test_caminho_completo_so_como_forma_no_externo(self):
        f = self.finding()
        ctx = build_context(self.s, f)

        local = redaction.redact(ctx, egress=EgressClass.LOCALHOST)
        self.assertEqual(local.payload["file_basename"], "prod-db-password.env")

        externo = redaction.redact(ctx, egress=EgressClass.THIRD_PARTY)
        blob = json.dumps(externo.payload, default=str)
        self.assertIsNone(externo.payload["file_basename"])
        self.assertNotIn(CANARY_PATH, blob)
        self.assertIn("depth=", externo.payload["file_path_shape"])

    def test_nenhum_campo_de_contexto_carrega_codigo(self):
        campos = set(FindingContext.__dataclass_fields__)
        for proibido in ("snippet", "code", "raw", "content"):
            achados = [c for c in campos if proibido in c]
            self.assertEqual(achados, [], f"campo suspeito: {achados}")


class TestDetector(BasePriv):

    def test_padroes_conhecidos(self):
        casos = {
            "AKIAIOSFODNN7EXAMPLE": "aws_access_key",
            "ghp_" + "a" * 36: "github_token",
            "sk-" + "b" * 32: "openai_key",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc": "jwt",
            "postgres://user:senha@host/db": "connection_string",
            "-----BEGIN RSA PRIVATE KEY-----": "private_key",
        }
        for texto, esperado in casos.items():
            with self.subTest(texto=texto[:18]):
                nomes = [h[0] for h in detectors.scan(texto)]
                self.assertIn(esperado, nomes)

    def test_nao_dispara_em_dado_normal(self):
        """**O teste que decide se este portao sobrevive ao contato com usuario.**

        Detector que dispara em dado legitimo vira ruido, ruido vira controle
        desligado, e controle desligado e pior que controle nenhum.
        """
        legitimos = [
            "CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q", "CWE-787", "1.2.11", "v3.0.8",
            "a" * 64,                                     # hash sha-256 hex
            "35ab1a5c44686eb0bfabd56d0a5491d8f9e79480009e6d440e37cf597c06d020",
            "2026-08-24", "openssl", "act_now", "risk-model.md-4.2+exp-002",
        ]
        for texto in legitimos:
            with self.subTest(texto=texto[:24]):
                self.assertEqual(detectors.scan(texto), [],
                                 f"falso positivo em {texto[:40]}")

    def test_evidencia_real_produz_zero_deteccao(self):
        """Um conjunto realista de KEV + EPSS nao pode disparar nada."""
        f = self.finding()
        ctx = build_context(self.s, f)
        for e in ctx.evidence:
            with self.subTest(tipo=e.type):
                self.assertEqual(detectors.scan(json.dumps(e.facts, default=str)), [],
                                 f"detector disparou em evidencia {e.type}")

    def test_marcador_tipado_sem_o_valor(self):
        texto = "chave AKIAIOSFODNN7EXAMPLE no arquivo"
        limpo, nomes = detectors.redact_text(texto)
        self.assertIn("[REDIGIDO:aws_access_key]", limpo)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", limpo)
        self.assertEqual(nomes, ["aws_access_key"])


class TestPortao(BasePriv):

    def test_segredo_com_egresso_externo_bloqueia_sem_enviar(self):
        """Falha fechado, e o contador do servidor falso fica em **zero**."""
        f = self.finding(description="token de deploy: ghp_" + "z" * 36)
        with FakeServer() as srv:
            srv.json_route("/chat/completions", {})
            os.environ["SDIP_OPENAI_API_KEY"] = "sk-teste-0000000000000000000"
            configure_ai(self.s, provider="openai", base_url=srv.base, model="m")
            rec = service.analyze_finding(self.s, f)
            self.assertEqual(rec.outcome, contract.BLOCKED_REDACTION)
            self.assertEqual(srv.count, 0,
                             "houve requisicao apesar do bloqueio")

    def test_egresso_local_redige_e_segue(self):
        f = self.finding(description="token de deploy: ghp_" + "z" * 36)
        ctx = build_context(self.s, f)
        red = redaction.redact(ctx, egress=EgressClass.LOCALHOST)
        self.assertTrue(red.redactions)
        self.assertIn("[REDIGIDO:", red.payload["description"])
        self.assertNotIn("ghp_", json.dumps(red.payload, default=str))

    def test_redacao_registra_campo_e_detector_nunca_o_valor(self):
        f = self.finding(description="AKIAIOSFODNN7EXAMPLE")
        ctx = build_context(self.s, f)
        red = redaction.redact(ctx, egress=EgressClass.LOCALHOST)
        self.assertTrue(red.redactions)
        for r in red.redactions:
            self.assertIn("field_path", r)
            self.assertIn("detector", r)
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", json.dumps(r))

    def test_contexto_cru_nao_chega_a_provider(self):
        f = self.finding()
        ctx = build_context(self.s, f)
        provider = ai.get_provider(self.s)
        with self.assertRaises(TypeError):
            provider.analyze(AnalysisRequest(ctx, {}, provider.settings))

    def test_contexto_nao_e_serializavel(self):
        f = self.finding()
        ctx = build_context(self.s, f)
        with self.assertRaises(TypeError):
            json.dumps(ctx)
        import pickle
        with self.assertRaises(TypeError):
            pickle.dumps(ctx)

    def test_nenhum_provider_sobrescreve_analyze(self):
        """Substituto estrutural do MyPy strict que a ADR-0011 pressupoe."""
        for name, cls in REGISTRY.items():
            with self.subTest(provider=name):
                self.assertNotIn("analyze", cls.__dict__,
                                 f"{name} sobrescreveu o portao de tipo")

    def test_tier_efetivo_e_o_minimo(self):
        for egress in EgressClass:
            self.assertEqual(redaction.effective_tier("scrubbed", egress), "no_code")


class TestNaoMoveNada(BasePriv):

    def test_nenhum_outcome_altera_a_banda(self):
        """Inclusive o sucesso. A IA sintetiza; ela nao decide."""
        f = self.finding()
        antes = (f.band, f.ordering_score, f.risk_model_version)

        cenarios = [
            ("sucesso", lambda s: s.json_route(
                "/api/chat", ollama_ok(analysis_payload()))),
            ("500", lambda s: s.route("/api/chat", status=500)),
            ("malformada", lambda s: s.route(
                "/api/chat", body='{"message":{"content":"prosa"}}')),
        ]
        for nome, setup in cenarios:
            with self.subTest(cenario=nome):
                with FakeServer() as srv:
                    setup(srv)
                    configure_ai(self.s, provider="ollama", base_url=srv.base,
                                 model="m")
                    service.analyze_finding(self.s, f)
                self.s.refresh(f)
                self.assertEqual((f.band, f.ordering_score, f.risk_model_version),
                                 antes, f"a banda mudou no cenario {nome}")

    def test_null_provider_nao_faz_io(self):
        """A pagina precisa abrir mesmo com a rede quebrada."""
        import urllib.request
        original = urllib.request.urlopen

        def explode(*a, **kw):
            raise AssertionError("houve I/O no caminho deterministico")

        f = self.finding()
        urllib.request.urlopen = explode
        try:
            rec = service.analyze_finding(self.s, f, confirmed_egress="none")
            self.assertEqual(rec.outcome, contract.OK)
        finally:
            urllib.request.urlopen = original


class TestFundamentacao(BasePriv):

    def _com_resposta(self, payload):
        f = self.finding()
        with FakeServer() as srv:
            srv.json_route("/api/chat", ollama_ok(payload))
            configure_ai(self.s, provider="ollama", base_url=srv.base, model="m")
            return service.analyze_finding(self.s, f), f

    def test_id_alucinado_rejeita_a_resposta_inteira(self):
        rec, _ = self._com_resposta(analysis_payload(evidence_ids=[999999]))
        self.assertEqual(rec.outcome, contract.REJECTED_UNGROUNDED)
        self.assertEqual(rec.evidence_ids, [])

    def test_id_existente_mas_descartado_tambem_e_rejeitado(self):
        """Existir no banco nao basta: tem que ter sido entregue ao modelo.

        Orcamento apertado ate alguma evidencia sobrar de fora -- e o id dessa
        continua sendo alucinacao em relacao ao que o modelo viu.
        """
        f = self.finding()
        ctx = build_context(self.s, f, budget_chars=1)
        self.assertTrue(ctx.evidence_dropped, "o orcamento nao descartou nada")
        fora = [d["id"] for d in ctx.evidence_dropped]
        self.assertTrue(set(fora).isdisjoint(ctx.evidence_ids))

        red = redaction.redact(ctx, egress=EgressClass.NONE)
        validado = contract.validate(analysis_payload(evidence_ids=fora[:1]), red)
        self.assertEqual(validado.outcome, contract.REJECTED_UNGROUNDED)

    def test_confianca_e_deterministica_e_nao_vem_do_modelo(self):
        """ADR-0007 §2 e ADR-0010 §1 vencem o briefing neste ponto."""
        from app.application.ai.prompt import OUTPUT_SCHEMA
        self.assertNotIn("confidence", OUTPUT_SCHEMA["properties"])
        rec, _ = self._com_resposta(analysis_payload())
        self.assertIsNotNone(rec.confidence)
        self.assertEqual(rec.confidence_model_version,
                         contract.CONFIDENCE_MODEL_VERSION)
        self.assertTrue(0.0 <= rec.confidence <= 1.0)

    def test_proveniencia_nao_esta_no_schema(self):
        """Se estivesse, o modelo poderia mentir sobre a propria identidade."""
        from app.application.ai.prompt import OUTPUT_SCHEMA
        for campo in ("provider", "model", "timestamp", "created_at", "egress"):
            self.assertNotIn(campo, OUTPUT_SCHEMA["properties"])

    def test_sintetico_e_marcado(self):
        from app.domain.models import Decision
        f = self.finding()
        f.decisions.append(Decision(
            org_id=f.org_id, reason="false_positive", rationale="r",
            classification="SYNTHETIC_DATA"))
        self.s.flush()
        rec = service.analyze_finding(self.s, f, confirmed_egress="none")
        self.assertTrue(rec.contains_synthetic)


if __name__ == "__main__":
    unittest.main(verbosity=2)
