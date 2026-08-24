"""
Fluxo ponta a ponta do MVP.

    Import -> Asset -> Finding -> Correlation -> Priority -> Evidence ->
    Remediation -> Monitoring -> Review

E os nove casos da demonstracao (briefing 25), verificados sobre o dataset de
demonstracao real.
"""

import unittest

from tests import support
from tests.support import fresh_session

from app.application import (
    decision_debt, demo, knowledge, pipeline, remediation, review,
)


class TestFluxoCompleto(unittest.TestCase):
    """Um lote importado percorre o pipeline inteiro."""

    def setUp(self):
        self.s = fresh_session()

    def tearDown(self):
        self.s.close()

    def test_import_ate_revisao(self):
        rows = [
            {"id": "F1", "repository": "org/api", "title": "openssl vulneravel",
             "cve": "CVE-2021-44228", "package": "openssl",
             "version": "3.0.7", "fixed_version": "3.0.8",
             "severity": "critical", "cvss": "9.8"},
            {"id": "F2", "repository": "org/web", "title": "openssl vulneravel",
             "cve": "CVE-2021-44228", "package": "openssl",
             "version": "3.0.7", "fixed_version": "3.0.8", "severity": "critical"},
            {"id": "F3", "repository": "org/api", "title": "buffer overflow",
             "rule_id": "cpp/overflow", "file": "src/a.c", "line": "42",
             "severity": "high"},
        ]
        assets = [
            {"identifier": "org/api", "criticality": "critical",
             "environment": "prod", "internet_facing": "true", "owner": "time-a"},
            {"identifier": "org/web", "criticality": "medium",
             "environment": "prod", "internet_facing": "false"},
        ]

        out = pipeline.run_import(self.s, rows, "scanner-teste", "run e2e",
                                  asset_rows=assets)

        # 1. Asset Discovery
        self.assertEqual(out["assets"]["created"], 2)
        # 2. Finding Ingestion
        self.assertEqual(out["ingestion"]["created"], 3)
        # 3. Risk Correlation — F1 e F2 sao a mesma vulnerabilidade
        self.assertEqual(out["correlation"]["multi_member_groups"], 1)
        # 4. Prioritization
        self.assertEqual(out["prioritization"]["scored"], 3)
        # 5. Remediation
        self.assertEqual(out["remediation"]["generated"], 3)
        self.assertGreaterEqual(out["remediation"]["by_confidence"].get("verified", 0), 2)
        # 6. Continuous Monitoring
        self.assertEqual(out["changes"].get("finding_new"), 3)

        from sqlalchemy import select
        from app.domain.models import Finding
        f1 = self.s.scalars(select(Finding).where(
            Finding.source_finding_id == "F1")).one()

        # 7. Evidence
        self.assertTrue(f1.evidence, "achado sem evidencia anexada")
        # 8. Explicabilidade
        self.assertTrue(f1.assessment.get("reasons"))
        # 9. Analyst Review
        d = review.submit_review(self.s, f1.id, "accepted_risk",
                                 "aceito ate a janela de manutencao", "ana")
        self.assertEqual(d.classification, "REAL_EXTERNAL_DATA")
        self.assertEqual(f1.status, "closed")

    def test_reimport_detecta_fechamento_e_reabertura(self):
        rows = [{"id": "F1", "repository": "org/r", "title": "a", "cve": "CVE-2020-1"},
                {"id": "F2", "repository": "org/r", "title": "b", "cve": "CVE-2020-2"}]
        pipeline.run_import(self.s, rows, "scanner", "run1")
        out2 = pipeline.run_import(self.s, rows[:1], "scanner", "run2")
        self.assertEqual(out2["changes"].get("finding_closed"), 1)
        out3 = pipeline.run_import(self.s, rows, "scanner", "run3")
        self.assertEqual(out3["changes"].get("finding_reopened"), 1)


class TestDemonstracao(unittest.TestCase):
    """Os nove casos do briefing, sobre o dataset de demonstracao."""

    @classmethod
    def setUpClass(cls):
        if not knowledge.kev().by_cve:
            raise unittest.SkipTest("catalogo KEV indisponivel")
        cls.s = fresh_session()
        cls.result = demo.build(cls.s)

    @classmethod
    def tearDownClass(cls):
        cls.s.close()

    def test_caso_1_ativo_critico_com_achado_grave(self):
        from sqlalchemy import select
        from app.domain.models import Asset
        criticos = self.s.scalars(select(Asset).where(
            Asset.criticality == "critical")).all()
        self.assertTrue(criticos)
        com_urgencia = [a for a in criticos
                        if any(f.band == "act_now" for f in a.findings)]
        self.assertTrue(com_urgencia, "nenhum ativo critico com achado urgente")

    def test_caso_2_correlacao_entre_ocorrencias(self):
        self.assertGreaterEqual(self.result["correlation"]["multi_member_groups"], 1)
        self.assertGreaterEqual(self.result["correlation"]["duplicates_absorbed"], 1)

    def test_caso_3_kev_indica_exploracao_conhecida(self):
        self.assertGreaterEqual(self.result["enrichment"]["kev_evidence"], 1)

    def test_caso_4_prioridade_sobe_com_kev(self):
        from sqlalchemy import select
        from app.domain.models import Finding
        com_kev = self.s.scalars(select(Finding).where(
            Finding.assessment_json.like('%"kev_listed"%'))).all()
        self.assertTrue(com_kev)
        for f in com_kev[:10]:
            self.assertIn(f.band, ("act_now", "act_soon"),
                          f"{f.cve} com KEV mas banda {f.band}")
            self.assertEqual(f.assessment["non_suppressible"], "kev_listed")

    def test_caso_5_evidencia_com_proveniencia(self):
        from sqlalchemy import select
        from app.domain.models import Evidence
        evs = self.s.scalars(select(Evidence)).all()
        self.assertTrue(evs)
        for e in evs[:20]:
            self.assertIn(e.classification,
                          ("REAL_EXTERNAL_DATA", "DERIVED_DATA", "SYNTHETIC_DATA"))
            self.assertTrue(e.source)
            self.assertIsNotNone(e.retrieved_at)

    def test_caso_6_remediacao_com_fonte_e_confianca(self):
        conf = self.result["remediation"]["by_confidence"]
        self.assertGreaterEqual(conf.get("verified", 0), 1)
        self.assertGreaterEqual(conf.get("uncertain", 0), 1,
                                "sem casos 'uncertain' — sinal de que algo esta "
                                "inventando orientacao")
        from sqlalchemy import select
        from app.domain.models import Remediation
        for r in self.s.scalars(select(Remediation)).all()[:20]:
            if r.confidence == "uncertain":
                self.assertIsNone(r.source)
            else:
                self.assertTrue(r.source, f"remediacao {r.confidence} sem fonte")

    def test_caso_7_mudanca_de_contexto_muda_a_prioridade(self):
        antes = dict(self.result["prioritization"]["bands"])
        out = demo.simulate_context_change(self.s)
        self.assertTrue(out["changed"])
        depois = out["reprocess"]["prioritization"]["bands"]
        self.assertNotEqual(antes.get("deprioritize_candidate"),
                            depois.get("deprioritize_candidate"),
                            "promover um ativo a producao exposta nao mudou nada")

    def test_caso_8_divida_de_decisao_detectada(self):
        st = self.result["decision_debt"]
        self.assertGreaterEqual(st["decision_debt"], 1)
        self.assertGreaterEqual(st["closed_despite"], 1)
        abertas = decision_debt.open_debt(self.s)
        self.assertTrue(abertas)
        for d in abertas[:5]:
            self.assertTrue(d.explanation)
            self.assertIsNotNone(d.event_date)
            self.assertEqual(d.decision.classification, "SYNTHETIC_DATA")

    def test_caso_9_analista_revisa_e_a_fila_encolhe(self):
        fila = review.review_queue(self.s)
        self.assertTrue(fila)
        alvo = next(i for i in fila if i["kind"] == "decision_debt")
        antes = len(decision_debt.open_debt(self.s))
        review.submit_review(self.s, alvo["finding"].id, "accepted_risk",
                             "revisto apos entrada no KEV", "analista-teste",
                             resolves_debt_id=alvo["debt"].id)
        self.assertEqual(len(decision_debt.open_debt(self.s)), antes - 1)


class TestHonestidadeDoDataset(unittest.TestCase):
    """O que impede o dataset de demonstracao de ser apresentado como real."""

    @classmethod
    def setUpClass(cls):
        if not knowledge.kev().by_cve:
            raise unittest.SkipTest("catalogo KEV indisponivel")
        cls.s = fresh_session()
        demo.build(cls.s)

    @classmethod
    def tearDownClass(cls):
        cls.s.close()

    def test_toda_decisao_do_demo_e_marcada_sintetica(self):
        from sqlalchemy import select
        from app.domain.models import Decision
        for d in self.s.scalars(select(Decision).where(
                Decision.source_system == "demo-seed")).all():
            self.assertEqual(d.classification, "SYNTHETIC_DATA")

    def test_evidencia_do_kev_e_marcada_real(self):
        from sqlalchemy import select
        from app.domain.models import Evidence
        for e in self.s.scalars(select(Evidence).where(
                Evidence.source == "CISA KEV")).all()[:10]:
            self.assertEqual(e.classification, "REAL_EXTERNAL_DATA")

    def test_o_manifesto_declara_o_que_e_fabricado(self):
        import json
        import os
        path = os.path.join(demo.DEMO_DIR, "manifest.json")
        if not os.path.exists(path):
            self.skipTest("manifesto nao gravado neste ambiente")
        with open(path, encoding="utf-8") as f:
            m = json.load(f)
        self.assertIn("FABRICADOS", m["warning"])
        classes = {c["classification"] for c in m["components"]}
        self.assertIn("SYNTHETIC_DATA", classes)
        self.assertIn("REAL_EXTERNAL_DATA", classes)


class TestIaOpcional(unittest.TestCase):
    """O MVP tem que funcionar sem nenhuma chamada externa."""

    def test_provider_padrao_nao_e_externo(self):
        from app.application import ai
        info = ai.provider_info()
        self.assertFalse(info["external"])

    def test_sintese_funciona_sem_modelo(self):
        from app.application import ai
        out = ai.get_provider().summarize_risk({
            "title": "achado", "asset_name": "svc",
            "assessment": {"band_label": "Agir agora",
                           "reasons": ["exploracao ativa conhecida"],
                           "decision_points": {}, "ineligibility_reasons": []},
            "remediation": {"action": "atualizar", "confidence": "verified"},
            "evidence_ids": [1, 2]})
        self.assertTrue(out["summary"])
        self.assertIn("exploracao ativa conhecida", out["risk_explanation"])
        self.assertEqual(out["evidence_ids"], ["1", "2"])

    def test_saida_invalida_do_modelo_nao_derruba_a_tela(self):
        from app.application import ai
        out = ai.validate_ai_output("isto nao e um dicionario")
        self.assertEqual(out["summary"], "")
        self.assertTrue(out["uncertainty_reasons"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
