"""
Regressao de B2 e B3.

Os dois bugs vieram de `phase0/v1_backtest.py` colapsar razoes de fechamento por
regex: `Mitigated` virava `fixed` (e sumia do relatorio) e `Won't Fix` virava
`false_positive` (corrompendo a divisao de pilhas).

Estes testes existem para os dois nao voltarem. Sao a razao pela qual
`app/domain/enums.py` tem seis valores e nao tres.
"""

import unittest

from tests import support  # noqa: F401  (define SDIP_DB_PATH antes de app.*)

from app.domain.enums import ClosureReason, classify_closure_reason


class TestB2Mitigated(unittest.TestCase):
    """B2: mitigado nao e corrigido."""

    def test_mitigated_nao_vira_fixed(self):
        for texto in ("Mitigated", "mitigated", "MITIGADO",
                      "Mitigated - WAF rule applied",
                      "Compensating control in place",
                      "Controle compensatorio ativo",
                      "Workaround aplicado", "Virtual patch"):
            with self.subTest(texto=texto):
                self.assertEqual(classify_closure_reason(texto),
                                 ClosureReason.MITIGATED,
                                 f"{texto!r} nao pode virar 'fixed' (bug B2)")

    def test_mitigated_e_decisao_de_nao_agir(self):
        """O ponto do bug: mitigado tem que ENTRAR no escopo de divida.

        Um achado fechado porque existe controle compensatorio e exatamente a
        decisao de nao remediar, e ADR-0016 diz que essa supressao e perecivel.
        """
        self.assertTrue(ClosureReason.MITIGATED.is_decision_to_not_act)
        self.assertTrue(ClosureReason.MITIGATED.is_perishable)

    def test_fixed_continua_fora_do_escopo(self):
        """O contrapeso: corrigido nao pode entrar. Nao ha decisao a re-litigar."""
        self.assertFalse(ClosureReason.FIXED.is_decision_to_not_act)
        for texto in ("Fixed", "Corrigido", "Patched", "Remediated", "Resolved"):
            with self.subTest(texto=texto):
                self.assertEqual(classify_closure_reason(texto), ClosureReason.FIXED)


class TestB3WontFix(unittest.TestCase):
    """B3: won't fix nao e falso positivo."""

    def test_wont_fix_nao_vira_false_positive(self):
        for texto in ("Won't Fix", "wont fix", "WontFix", "Will not fix",
                      "Nao sera corrigido", "By design", "Out of scope"):
            with self.subTest(texto=texto):
                self.assertEqual(classify_closure_reason(texto),
                                 ClosureReason.WONT_FIX,
                                 f"{texto!r} nao pode virar 'false_positive' (bug B3)")

    def test_false_positive_continua_sendo_reconhecido(self):
        for texto in ("False Positive", "falso positivo", "Not applicable",
                      "Not exploitable", "Invalid", "Dismissed"):
            with self.subTest(texto=texto):
                self.assertEqual(classify_closure_reason(texto),
                                 ClosureReason.FALSE_POSITIVE)

    def test_as_duas_pilhas_sao_distinguiveis(self):
        """A suposicao A4 depende de as pilhas nao se misturarem."""
        self.assertNotEqual(classify_closure_reason("Won't Fix"),
                            classify_closure_reason("False Positive"))
        self.assertNotEqual(classify_closure_reason("Risk Accepted"),
                            classify_closure_reason("False Positive"))


class TestVocabularioCompleto(unittest.TestCase):

    def test_seis_valores_distintos(self):
        self.assertEqual(len(set(ClosureReason)), 6)

    def test_risco_aceito(self):
        for texto in ("Risk Accepted", "Accepted risk", "Risco aceito",
                      "Exception approved", "Waiver", "Deferred"):
            with self.subTest(texto=texto):
                self.assertEqual(classify_closure_reason(texto),
                                 ClosureReason.ACCEPTED_RISK)

    def test_vazio_e_desconhecido_nunca_viram_chute(self):
        """Ignorancia nao pode virar decisao: inflaria o numero principal."""
        for texto in ("", None, "   ", "xyz sem sentido", "12345"):
            with self.subTest(texto=texto):
                self.assertEqual(classify_closure_reason(texto), ClosureReason.UNKNOWN)
        self.assertFalse(ClosureReason.UNKNOWN.is_decision_to_not_act)

    def test_quatro_razoes_entram_no_escopo_de_divida(self):
        no_escopo = {r for r in ClosureReason if r.is_decision_to_not_act}
        self.assertEqual(no_escopo, {
            ClosureReason.MITIGATED, ClosureReason.ACCEPTED_RISK,
            ClosureReason.FALSE_POSITIVE, ClosureReason.WONT_FIX})


class TestDivergenciaComPhase0(unittest.TestCase):
    """Prova que a divergencia com o instrumento antigo e a esperada.

    Este teste importa `phase0/v1_backtest.py` para DOCUMENTAR o comportamento
    antigo, nao para valida-lo. Se o instrumento for corrigido um dia, este
    teste falha e a correcao fica visivel em vez de silenciosa.
    """

    def setUp(self):
        import os
        import sys
        p0 = os.path.join(support.REPO_ROOT, "phase0")
        if p0 not in sys.path:
            sys.path.insert(0, p0)
        try:
            import v1_backtest
            self.v1 = v1_backtest
        except ImportError:
            self.skipTest("phase0/v1_backtest.py indisponivel")

    def test_o_instrumento_antigo_ainda_colapsa_mitigated(self):
        self.assertEqual(self.v1.classify_reason("Mitigated"), "fixed",
                         "Se isto mudou, v1_backtest.py foi corrigido — "
                         "atualize B2 em PROJECT_STATE.md")

    def test_o_novo_vocabulario_diverge_e_isso_e_o_conserto(self):
        self.assertNotEqual(classify_closure_reason("Mitigated").value,
                            self.v1.classify_reason("Mitigated"))
        self.assertNotEqual(classify_closure_reason("Won't Fix").value,
                            self.v1.classify_reason("Won't Fix"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
