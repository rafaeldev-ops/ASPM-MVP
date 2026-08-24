"""
Divida de decisao e revisao do analista.

O que estes testes protegem e a regra temporal: a evidencia e lida como estava
no dia da decisao, nunca como esta hoje. Errar isso torna o relatorio inutil na
direcao lisonjeira -- todo achado fechado vira divida.
"""

import unittest
from datetime import datetime, timedelta, timezone

from tests import support
from tests.support import fresh_session, make_asset, make_finding

from app.application import decision_debt, knowledge, review
from app.domain.enums import ClosureReason
from app.domain.models import Decision


def dt(d):
    return datetime.combine(d, datetime.min.time(), tzinfo=timezone.utc)


class TestRegraTemporal(unittest.TestCase):

    def setUp(self):
        self.s = fresh_session()
        self.kev = knowledge.kev()
        if not self.kev.by_cve:
            self.skipTest("catalogo KEV indisponivel")
        self.entry = support.a_kev_cve(0)
        self.added = self.entry["date_added"]

    def tearDown(self):
        self.s.close()

    def _decide(self, quando, reason=ClosureReason.FALSE_POSITIVE):
        a = make_asset(self.s, "svc")
        f = make_finding(self.s, a, cve=self.entry["cve_id"], title="t")
        f.decisions.append(Decision(
            org_id="org-local", reason=reason.value, rationale="r",
            decided_at=quando, classification="SYNTHETIC_DATA"))
        self.s.flush()
        return f

    def test_fechado_antes_da_entrada_vira_divida(self):
        f = self._decide(dt(self.added) - timedelta(days=60))
        row = decision_debt.evaluate_decision(f.current_decision, f, self.kev)
        self.assertTrue(row["re_litigation_candidate"])
        self.assertEqual(row["validity"], decision_debt.POTENTIALLY_OBSOLETE)
        self.assertEqual(row["days_after_decision"], 60)

    def test_fechado_depois_da_entrada_nao_e_divida(self):
        """E uma historia diferente e pior: fechado apesar de ja ser sabido."""
        f = self._decide(dt(self.added) + timedelta(days=30))
        row = decision_debt.evaluate_decision(f.current_decision, f, self.kev)
        self.assertFalse(row["re_litigation_candidate"])
        self.assertEqual(row["validity"], decision_debt.INVALID_AT_DECISION_TIME)

    def test_o_estado_as_of_nao_revela_o_futuro(self):
        antes = self.added - timedelta(days=10)
        k = self.kev.knowledge_as_of(self.entry["cve_id"], antes)
        self.assertEqual(k["kev_state"], "NOT_IN_KEV")
        self.assertIsNone(k["kev_date_added_if_known"],
                          "a data de entrada futura vazou para o passado")
        self.assertIsNone(k["known_ransomware_if_known"])

    def test_depois_da_entrada_a_data_passa_a_ser_conhecida(self):
        k = self.kev.knowledge_as_of(self.entry["cve_id"],
                                     self.added + timedelta(days=1))
        self.assertEqual(k["kev_state"], "IN_KEV")
        self.assertEqual(k["kev_date_added_if_known"], self.added.isoformat())

    def test_nenhuma_consulta_do_varredor_revela_data_futura(self):
        """A garantia forte: varre a populacao inteira, nao um caso."""
        for i in range(12):
            e = support.a_kev_cve(i)
            a = make_asset(self.s, f"svc-{i}")
            f = make_finding(self.s, a, cve=e["cve_id"], title=f"t{i}")
            f.decisions.append(Decision(
                org_id="org-local", reason="false_positive", rationale="r",
                decided_at=dt(e["date_added"]) - timedelta(days=30),
                classification="SYNTHETIC_DATA"))
        self.s.flush()
        stats = decision_debt.scan(self.s)
        for row in stats["rows"]:
            k = row["knowledge_as_of_decision"]
            if not k or not k.get("kev_date_added_if_known"):
                continue
            self.assertLessEqual(k["kev_date_added_if_known"], k["as_of"],
                                 f"vazamento temporal em {row['cve']}")

    def test_as_duas_pilhas_nunca_se_somam(self):
        for i in range(10):
            e = support.a_kev_cve(i)
            a = make_asset(self.s, f"svc-{i}")
            f = make_finding(self.s, a, cve=e["cve_id"], title=f"t{i}")
            delta = -40 if i % 2 == 0 else 40
            f.decisions.append(Decision(
                org_id="org-local", reason="accepted_risk", rationale="r",
                decided_at=dt(e["date_added"]) + timedelta(days=delta),
                classification="SYNTHETIC_DATA"))
        self.s.flush()
        st = decision_debt.scan(self.s)
        self.assertEqual(st["decision_debt"], 5)
        self.assertEqual(st["closed_despite"], 5)
        self.assertNotEqual(st["decision_debt"] + st["closed_despite"],
                            st["decision_debt"],
                            "as pilhas nao podem ser apresentadas somadas")


class TestEscopoDaDivida(unittest.TestCase):
    """B2 e B3 no lugar onde importam: quem entra no calculo de divida."""

    def setUp(self):
        self.s = fresh_session()
        self.kev = knowledge.kev()
        if not self.kev.by_cve:
            self.skipTest("catalogo KEV indisponivel")
        self.entry = support.a_kev_cve(3)

    def tearDown(self):
        self.s.close()

    def _com_razao(self, reason):
        a = make_asset(self.s, f"svc-{reason}")
        f = make_finding(self.s, a, cve=self.entry["cve_id"], title=f"t-{reason}")
        f.decisions.append(Decision(
            org_id="org-local", reason=reason, rationale="r",
            decided_at=dt(self.entry["date_added"]) - timedelta(days=45),
            classification="SYNTHETIC_DATA"))
        self.s.flush()
        return decision_debt.evaluate_decision(f.current_decision, f, self.kev)

    def test_mitigado_entra_no_calculo(self):
        """B2: era isto que o instrumento antigo descartava."""
        row = self._com_razao("mitigated")
        self.assertTrue(row["re_litigation_candidate"],
                        "mitigado tem que gerar divida (regressao de B2)")

    def test_wont_fix_entra_no_calculo(self):
        row = self._com_razao("wont_fix")
        self.assertTrue(row["re_litigation_candidate"])

    def test_falso_positivo_e_risco_aceito_entram(self):
        for r in ("false_positive", "accepted_risk"):
            with self.subTest(reason=r):
                self.assertTrue(self._com_razao(r)["re_litigation_candidate"])

    def test_corrigido_fica_fora(self):
        row = self._com_razao("fixed")
        self.assertFalse(row["re_litigation_candidate"])
        self.assertEqual(row["validity"], decision_debt.NOT_APPLICABLE)

    def test_desconhecido_fica_fora(self):
        """Ignorancia nao e decisao. Incluir inflaria o numero principal."""
        row = self._com_razao("unknown")
        self.assertFalse(row["re_litigation_candidate"])


class TestExplicacao(unittest.TestCase):

    def setUp(self):
        self.s = fresh_session()
        self.kev = knowledge.kev()
        if not self.kev.by_cve:
            self.skipTest("catalogo KEV indisponivel")

    def tearDown(self):
        self.s.close()

    def test_a_explicacao_responde_o_que_mudou_e_quando(self):
        e = support.a_kev_cve(4)
        a = make_asset(self.s, "svc")
        f = make_finding(self.s, a, cve=e["cve_id"], title="t")
        f.decisions.append(Decision(
            org_id="org-local", reason="false_positive", rationale="r",
            decided_at=dt(e["date_added"]) - timedelta(days=90),
            classification="SYNTHETIC_DATA"))
        self.s.flush()
        row = decision_debt.evaluate_decision(f.current_decision, f, self.kev)
        self.assertIn(str(e["date_added"]), row["explanation"])
        self.assertIn("90 dias", row["explanation"])
        self.assertTrue(row["evidence"])
        self.assertEqual(row["evidence"][0]["classification"], "REAL_EXTERNAL_DATA")


class TestRevisao(unittest.TestCase):

    def setUp(self):
        self.s = fresh_session()

    def tearDown(self):
        self.s.close()

    def test_revisao_e_append_only(self):
        """ADR-0001: a decisao anterior nunca e sobrescrita."""
        a = make_asset(self.s, "svc")
        f = make_finding(self.s, a, title="t")
        d1 = review.submit_review(self.s, f.id, "false_positive",
                                  "nao alcancavel", "ana")
        d2 = review.submit_review(self.s, f.id, "accepted_risk",
                                  "revisto: e alcancavel", "bruno")
        hist = review.decision_history(self.s, f.id)
        self.assertEqual(len(hist), 2)
        self.assertEqual(d2.supersedes_id, d1.id)
        self.assertTrue(d2.is_review)
        self.assertIsNotNone(self.s.get(Decision, d1.id),
                             "a decisao antiga foi apagada")

    def test_justificativa_e_obrigatoria(self):
        a = make_asset(self.s, "svc")
        f = make_finding(self.s, a, title="t")
        with self.assertRaises(review.ReviewError):
            review.submit_review(self.s, f.id, "false_positive", "   ", "ana")

    def test_razao_invalida_e_recusada(self):
        a = make_asset(self.s, "svc")
        f = make_finding(self.s, a, title="t")
        with self.assertRaises(review.ReviewError):
            review.submit_review(self.s, f.id, "razao-inventada", "r", "ana")

    def test_a_revisao_grava_a_fotografia_do_momento(self):
        a = make_asset(self.s, "svc")
        f = make_finding(self.s, a, cve="CVE-2021-44228", title="t")
        d = review.submit_review(self.s, f.id, "accepted_risk", "r", "ana")
        self.assertIn("kev_state", d.knowledge_snapshot)
        self.assertIn("as_of", d.knowledge_snapshot)

    def test_classificacao_separa_analista_real_de_sintetico(self):
        a = make_asset(self.s, "svc")
        f = make_finding(self.s, a, title="t")
        d = review.submit_review(self.s, f.id, "false_positive", "r", "ana")
        self.assertEqual(d.classification, "REAL_EXTERNAL_DATA")

    def test_revisar_resolve_a_divida_aberta(self):
        from app.domain.models import DecisionDebt
        kev = knowledge.kev()
        if not kev.by_cve:
            self.skipTest("catalogo KEV indisponivel")
        e = support.a_kev_cve(5)
        a = make_asset(self.s, "svc")
        f = make_finding(self.s, a, cve=e["cve_id"], title="t")
        f.decisions.append(Decision(
            org_id="org-local", reason="false_positive", rationale="r",
            decided_at=dt(e["date_added"]) - timedelta(days=30),
            classification="SYNTHETIC_DATA"))
        self.s.flush()
        decision_debt.scan(self.s)
        abertas = decision_debt.open_debt(self.s)
        self.assertEqual(len(abertas), 1)

        review.submit_review(self.s, f.id, "accepted_risk",
                             "revisto apos entrada no KEV", "ana")
        self.assertEqual(len(decision_debt.open_debt(self.s)), 0)
        self.assertTrue(self.s.get(DecisionDebt, abertas[0].id).resolved)


if __name__ == "__main__":
    unittest.main(verbosity=2)
