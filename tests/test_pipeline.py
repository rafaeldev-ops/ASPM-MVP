"""
Integracao: ingestao, correlacao, priorizacao, remediacao e monitoramento
contra um banco de verdade.
"""

import unittest

from tests import support
from tests.support import fresh_session, make_asset, make_finding

from app.application import (
    correlation, ingestion, monitoring, prioritization, remediation,
)
from app.domain.enums import ChangeKind, RemediationConfidence


class TestAssetDiscovery(unittest.TestCase):

    def setUp(self):
        self.s = fresh_session()

    def tearDown(self):
        self.s.close()

    def test_import_de_ativos(self):
        rows = [
            {"identifier": "api-pagamentos", "type": "service",
             "criticality": "critical", "environment": "prod",
             "internet_facing": "true", "owner": "time-a"},
            {"identifier": "batch-relatorios", "type": "service",
             "criticality": "low", "environment": "staging",
             "internet_facing": "false"},
        ]
        r = ingestion.import_assets(self.s, rows, "csv-teste")
        self.assertEqual(r["created"], 2)

        from sqlalchemy import select
        from app.domain.models import Asset
        a = self.s.scalars(select(Asset).where(
            Asset.identifier == "api-pagamentos")).one()
        self.assertEqual(a.criticality, "critical")
        self.assertTrue(a.internet_facing)

    def test_reimport_e_idempotente(self):
        rows = [{"identifier": "api-x", "criticality": "high"}]
        ingestion.import_assets(self.s, rows, "csv")
        r2 = ingestion.import_assets(self.s, rows, "csv")
        self.assertEqual(r2["created"], 0)
        self.assertEqual(r2["updated"], 1)

    def test_update_nao_apaga_valor_conhecido_com_none(self):
        """Um export mais pobre nao pode degradar o que ja se sabia."""
        ingestion.import_assets(self.s, [{"identifier": "a", "criticality": "high",
                                          "owner": "time-a"}], "rico")
        ingestion.import_assets(self.s, [{"identifier": "a"}], "pobre")
        from sqlalchemy import select
        from app.domain.models import Asset
        a = self.s.scalars(select(Asset).where(Asset.identifier == "a")).one()
        self.assertEqual(a.criticality, "high")
        self.assertEqual(a.owner, "time-a")

    def test_ativo_descoberto_a_partir_do_achado(self):
        """A maior parte dos exports nomeia o repositorio; criar o ativo dali e
        o que evita exigir um inventario que a organizacao nao tem."""
        rows = [{"id": "F1", "repository": "org/repo-novo", "title": "algo",
                 "cve": "CVE-2021-44228"}]
        ingestion.import_findings(self.s, rows, "scanner")
        from sqlalchemy import select
        from app.domain.models import Asset
        a = self.s.scalars(select(Asset).where(
            Asset.identifier == "org/repo-novo")).one_or_none()
        self.assertIsNotNone(a)

    def test_criticidade_ausente_fica_nula_e_nao_inventada(self):
        ingestion.import_assets(self.s, [{"identifier": "sem-crit"}], "csv")
        from sqlalchemy import select
        from app.domain.models import Asset
        a = self.s.scalars(select(Asset).where(Asset.identifier == "sem-crit")).one()
        self.assertIsNone(a.criticality)


class TestFindingIngestion(unittest.TestCase):

    def setUp(self):
        self.s = fresh_session()

    def tearDown(self):
        self.s.close()

    def test_ingestao_idempotente_por_fingerprint(self):
        rows = [{"id": "F1", "repository": "org/r", "title": "x",
                 "cve": "CVE-2021-44228", "package": "log4j"}]
        r1 = ingestion.import_findings(self.s, rows, "trivy")
        r2 = ingestion.import_findings(self.s, rows, "trivy")
        self.assertEqual(r1["created"], 1)
        self.assertEqual(r2["created"], 0)
        self.assertEqual(r2["updated"], 1)

    def test_raw_preserva_a_linha_original(self):
        """CLAUDE.md 24: nada da fonte e destruido."""
        rows = [{"id": "F1", "repository": "org/r", "title": "x",
                 "campo_exotico_do_scanner": "valor que o modelo nao representa"}]
        ingestion.import_findings(self.s, rows, "scanner")
        from sqlalchemy import select
        from app.domain.models import Finding
        f = self.s.scalars(select(Finding)).one()
        self.assertEqual(f.raw["campo_exotico_do_scanner"],
                         "valor que o modelo nao representa")

    def test_parse_sarif(self):
        doc = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "CodeQL", "semanticVersion": "2.13.1",
                                    "rules": [{
                                        "id": "cpp/overflow",
                                        "shortDescription": {"text": "Estouro de buffer"},
                                        "properties": {
                                            "tags": ["security", "external/cwe/cwe-787"],
                                            "security-severity": "8.1"},
                                        "defaultConfiguration": {"level": "error"}}]}},
                "results": [{
                    "ruleId": "cpp/overflow",
                    "message": {"text": "buffer estourado"},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "src/a.c"},
                        "region": {"startLine": 42}}}]}]}]}
        import json
        rows = ingestion.parse_sarif(json.dumps(doc))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["file"], "src/a.c")
        self.assertEqual(rows[0]["line"], 42)
        self.assertIn("CWE-787", rows[0]["cwe"])
        self.assertEqual(rows[0]["severity"], "error")

    def test_sarif_nao_produz_cve(self):
        """O achado do Ring 0: CodeQL nao emite CVE. Inventar um seria fabricar
        a chave de juncao do sistema inteiro."""
        import json
        doc = {"runs": [{"tool": {"driver": {"name": "CodeQL", "rules": []}},
                         "results": [{"ruleId": "cpp/x", "message": {"text": "y"},
                                      "locations": []}]}]}
        rows = ingestion.parse_sarif(json.dumps(doc))
        ingestion.import_findings(self.s, rows, "codeql")
        from sqlalchemy import select
        from app.domain.models import Finding
        f = self.s.scalars(select(Finding)).one()
        self.assertIsNone(f.cve)


class TestCorrelacao(unittest.TestCase):

    def setUp(self):
        self.s = fresh_session()

    def tearDown(self):
        self.s.close()

    def test_mesma_vuln_em_ativos_diferentes_forma_um_grupo(self):
        a1 = make_asset(self.s, "svc-a")
        a2 = make_asset(self.s, "svc-b")
        make_finding(self.s, a1, cve="CVE-2021-44228", package_name="log4j",
                     title="log4j em svc-a")
        make_finding(self.s, a2, cve="CVE-2021-44228", package_name="log4j",
                     title="log4j em svc-b")
        r = correlation.correlate(self.s)
        self.assertEqual(r["multi_member_groups"], 1)
        self.assertEqual(r["duplicates_absorbed"], 1)

    def test_agrupar_nao_apaga_membros(self):
        """Fusao irreversivel e proibida: cada achado continua inteiro."""
        a = make_asset(self.s, "svc")
        f1 = make_finding(self.s, a, cve="CVE-2021-1", package_name="p", title="t1")
        f2 = make_finding(self.s, a, cve="CVE-2021-1", package_name="p", title="t2")
        correlation.correlate(self.s)
        self.assertEqual(f1.group_id, f2.group_id)
        from sqlalchemy import func, select
        from app.domain.models import Finding
        self.assertEqual(self.s.scalar(select(func.count(Finding.id))), 2)

    def test_base_de_correlacao_e_registrada(self):
        a = make_asset(self.s, "svc")
        make_finding(self.s, a, cve="CVE-2021-1", package_name="p", title="t")
        correlation.correlate(self.s)
        from sqlalchemy import select
        from app.domain.models import FindingGroup
        g = self.s.scalars(select(FindingGroup)).one()
        self.assertEqual(g.correlation_basis, correlation.BASIS_CVE_PACKAGE)

    def test_cves_diferentes_nao_sao_agrupados(self):
        a = make_asset(self.s, "svc")
        make_finding(self.s, a, cve="CVE-2021-1", package_name="p", title="t1")
        make_finding(self.s, a, cve="CVE-2021-2", package_name="p", title="t2")
        r = correlation.correlate(self.s)
        self.assertEqual(r["multi_member_groups"], 0)

    @unittest.skipUnless(support.kev_available(), "catalogo KEV indisponivel")
    def test_enriquecimento_anexa_evidencia_com_proveniencia(self):
        entry = support.a_kev_cve(0)
        a = make_asset(self.s, "svc")
        f = make_finding(self.s, a, cve=entry["cve_id"], title="t")
        correlation.correlate(self.s)
        r = correlation.enrich(self.s)
        self.assertGreaterEqual(r["kev_evidence"], 1)
        kev_ev = [e for e in f.evidence if e.evidence_type == "kev_listing"]
        self.assertEqual(len(kev_ev), 1)
        self.assertEqual(kev_ev[0].classification, "REAL_EXTERNAL_DATA")
        self.assertEqual(kev_ev[0].source_authority, "authoritative")
        self.assertIsNotNone(kev_ev[0].observed_at)

    @unittest.skipUnless(support.kev_available(), "catalogo KEV indisponivel")
    def test_enriquecimento_e_idempotente(self):
        entry = support.a_kev_cve(1)
        a = make_asset(self.s, "svc")
        f = make_finding(self.s, a, cve=entry["cve_id"], title="t")
        correlation.enrich(self.s)
        correlation.enrich(self.s)
        kev_ev = [e for e in f.evidence if e.evidence_type == "kev_listing"]
        self.assertEqual(len(kev_ev), 1, "evidencia duplicou ao reenriquecer")


class TestPriorizacao(unittest.TestCase):

    def setUp(self):
        self.s = fresh_session()

    def tearDown(self):
        self.s.close()

    @unittest.skipUnless(support.kev_available(), "catalogo KEV indisponivel")
    def test_kev_sobe_a_prioridade(self):
        """Caso 3 e 4 do briefing: o KEV indica exploracao e a prioridade sobe."""
        entry = support.a_kev_cve(0)
        a = make_asset(self.s, "svc-critico", criticality="critical",
                       environment="prod", internet_facing=True)
        com_kev = make_finding(self.s, a, cve=entry["cve_id"], title="com kev")
        sem_kev = make_finding(self.s, a, cve="CVE-2019-9999999", title="sem kev")
        correlation.enrich(self.s)
        prioritization.prioritize_all(self.s)
        self.assertEqual(com_kev.band, "act_now")
        self.assertGreater(com_kev.ordering_score, sem_kev.ordering_score)

    def test_prioridade_e_explicavel(self):
        a = make_asset(self.s, "svc", criticality="high", environment="prod",
                       internet_facing=True)
        f = make_finding(self.s, a, cve="CVE-2020-1", title="t")
        prioritization.prioritize_all(self.s)
        e = prioritization.explain(f)
        self.assertTrue(e["reasons"])
        self.assertIn("exposto a internet em producao", " ".join(e["reasons"]))

    def test_versao_do_modelo_e_gravada(self):
        a = make_asset(self.s, "svc")
        f = make_finding(self.s, a, title="t")
        prioritization.prioritize_all(self.s)
        self.assertIn("risk-model", f.risk_model_version)


class TestRemediacao(unittest.TestCase):

    def setUp(self):
        self.s = fresh_session()

    def tearDown(self):
        self.s.close()

    def test_verified_quando_ha_versao_corrigida(self):
        a = make_asset(self.s, "svc")
        f = make_finding(self.s, a, title="t", package_name="openssl",
                         package_version="3.0.7", fixed_version="3.0.8")
        g = remediation.build_guidance(self.s, f)
        self.assertEqual(g["confidence"], RemediationConfidence.VERIFIED)
        self.assertIn("3.0.8", g["action"])

    @unittest.skipUnless(support.kev_available(), "catalogo KEV indisponivel")
    def test_recommended_quando_ha_advisory_sem_versao(self):
        entry = support.a_kev_cve(2)
        a = make_asset(self.s, "svc")
        f = make_finding(self.s, a, title="t", cve=entry["cve_id"])
        correlation.enrich(self.s)
        g = remediation.build_guidance(self.s, f)
        self.assertEqual(g["confidence"], RemediationConfidence.RECOMMENDED)
        self.assertEqual(g["source"], "CISA KEV")

    def test_uncertain_diz_o_que_falta_em_vez_de_inventar(self):
        """A regra do briefing: nao inventar instrucao de correcao."""
        a = make_asset(self.s, "svc")
        f = make_finding(self.s, a, title="regra de SAST sem CVE",
                         source_rule_id="cpp/x")
        g = remediation.build_guidance(self.s, f)
        self.assertEqual(g["confidence"], RemediationConfidence.UNCERTAIN)
        self.assertIn("Faltam", g["detail"])
        self.assertIsNone(g["source"])

    def test_historical_usa_precedente_da_organizacao(self):
        from app.domain.models import Decision
        a = make_asset(self.s, "svc")
        f1 = make_finding(self.s, a, cve="CVE-2020-5", package_name="p", title="t1")
        f2 = make_finding(self.s, a, cve="CVE-2020-5", package_name="p", title="t2")
        correlation.correlate(self.s)
        f1.decisions.append(Decision(
            org_id="org-local", reason="fixed", rationale="upgrade feito",
            classification="REAL_EXTERNAL_DATA", decided_by="analista"))
        self.s.flush()
        g = remediation.build_guidance(self.s, f2)
        self.assertEqual(g["confidence"], RemediationConfidence.HISTORICAL)
        self.assertIn("historico da organizacao", g["source"])


class TestMonitoramento(unittest.TestCase):

    def setUp(self):
        self.s = fresh_session()

    def tearDown(self):
        self.s.close()

    def test_detecta_novo_fechado_e_reaberto(self):
        rows = [{"id": "F1", "repository": "org/r", "title": "a", "cve": "CVE-2020-1"},
                {"id": "F2", "repository": "org/r", "title": "b", "cve": "CVE-2020-2"}]

        prev = monitoring.capture_state(self.s)
        snap = ingestion.start_snapshot(self.s, "run1", "scanner")
        r1 = ingestion.import_findings(self.s, rows, "scanner", snap)
        c1 = monitoring.detect_changes(self.s, snap, r1["seen_ids"], prev)
        self.assertEqual(c1[ChangeKind.FINDING_NEW.value], 2)

        # Segunda passada sem o F2: ele deve ser detectado como fechado.
        prev = monitoring.capture_state(self.s)
        snap2 = ingestion.start_snapshot(self.s, "run2", "scanner")
        r2 = ingestion.import_findings(self.s, rows[:1], "scanner", snap2)
        c2 = monitoring.detect_changes(self.s, snap2, r2["seen_ids"], prev)
        self.assertEqual(c2[ChangeKind.FINDING_CLOSED.value], 1)

        # Terceira: F2 volta -> reaberto.
        prev = monitoring.capture_state(self.s)
        snap3 = ingestion.start_snapshot(self.s, "run3", "scanner")
        r3 = ingestion.import_findings(self.s, rows, "scanner", snap3)
        c3 = monitoring.detect_changes(self.s, snap3, r3["seen_ids"], prev)
        self.assertEqual(c3[ChangeKind.FINDING_REOPENED.value], 1)

    def test_mudanca_de_severidade_e_registrada(self):
        rows = [{"id": "F1", "repository": "org/r", "title": "a", "severity": "low"}]
        prev = monitoring.capture_state(self.s)
        snap = ingestion.start_snapshot(self.s, "r1", "scanner")
        r = ingestion.import_findings(self.s, rows, "scanner", snap)
        monitoring.detect_changes(self.s, snap, r["seen_ids"], prev)

        rows[0]["severity"] = "critical"
        prev = monitoring.capture_state(self.s)
        snap2 = ingestion.start_snapshot(self.s, "r2", "scanner")
        r2 = ingestion.import_findings(self.s, rows, "scanner", snap2)
        c = monitoring.detect_changes(self.s, snap2, r2["seen_ids"], prev)
        self.assertEqual(c[ChangeKind.SEVERITY_CHANGED.value], 1)

    def test_epss_nao_e_materialidade(self):
        """EPSS nao esta no enum de mudanca. Se estivesse, seria gatilho."""
        self.assertNotIn("epss", [k.value for k in ChangeKind])
        for k in ChangeKind:
            if k.is_material:
                self.assertNotIn("epss", k.value)

    @unittest.skipUnless(support.kev_available(), "catalogo KEV indisponivel")
    def test_evento_de_kev_usa_a_data_da_cisa(self):
        """`occurred_at` e a data em que a CISA listou, nao a data em que
        percebemos -- e isso que permite comparar contra a data da decisao."""
        entry = support.a_kev_cve(0)
        a = make_asset(self.s, "svc")
        make_finding(self.s, a, cve=entry["cve_id"], title="t")
        monitoring.detect_kev_changes(self.s)
        from sqlalchemy import select
        from app.domain.models import ChangeEvent
        ev = self.s.scalars(select(ChangeEvent).where(
            ChangeEvent.kind == ChangeKind.KEV_LISTED.value)).one()
        self.assertEqual(ev.occurred_at.date(), entry["date_added"])
        self.assertTrue(ev.is_material)


if __name__ == "__main__":
    unittest.main(verbosity=2)
