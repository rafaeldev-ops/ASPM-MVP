"""
A arvore de risco portada para o app.

Reexecuta as mesmas assercoes que `phase0/v2_riskmodel.py --assert` executa, e
por uma razao especifica: a arvore agora existe em dois lugares (o instrumento
de validacao e o produto). Duas copias da mesma regra divergem em silencio a
menos que algo compare as duas.
"""

import unittest

from tests import support  # noqa: F401

from app.domain import risk
from app.domain.enums import Band


class TestArvoreTotal(unittest.TestCase):
    """As tres assercoes de exp-002, que acharam defeitos reais no documento."""

    def test_arvore_e_total(self):
        """Nenhuma combinacao pode ficar sem banda.

        A versao publicada em risk-model.md deixava 112 de 576 sem regra --
        comportamento indefinido no unico componente cuja justificativa e poder
        ser revisado exaustivamente por um humano.
        """
        combos = list(risk.all_combinations())
        self.assertEqual(len(combos), 720, "o espaco de decisao mudou de tamanho")
        sem_banda = [c for c in combos if risk.band_of(*c)[0] == risk.UNMATCHED]
        self.assertEqual(sem_banda, [], f"{len(sem_banda)} combinacoes sem banda")

    def test_nenhuma_linha_morta(self):
        """Toda linha da arvore tem que ser alcancavel por alguma entrada."""
        alcancadas = {risk.band_of(*c)[1] for c in risk.all_combinations()}
        todas = {row[0] for row in risk.TREE}
        mortas = todas - alcancadas
        self.assertEqual(mortas, set(), f"linhas que nunca disparam: {sorted(mortas)}")

    def test_exploracao_ativa_nunca_e_depriorizada(self):
        """A assercao de seguranca: nada com exploracao ativa pode ser silenciado."""
        for combo in risk.all_combinations():
            if combo[0] != "active":
                continue
            banda, linha = risk.band_of(*combo)
            self.assertNotEqual(banda, "deprioritize_candidate",
                                f"linha {linha} depriorizaria {combo}")


class TestPontosDeDecisao(unittest.TestCase):

    def test_criticidade_nula_falha_fechado(self):
        """Nao saber a criticidade do ativo nao pode baratear o achado."""
        dps = risk.decision_points({"criticality": None})
        self.assertEqual(dps[3], "critical")

    def test_ausencia_de_evidencia_nao_vira_nao_aplicavel(self):
        """`not_applicable` exige sinal positivo; ausencia devolve `unknown`."""
        dps = risk.decision_points({})
        self.assertEqual(dps[2], "unknown")

    def test_kev_leva_exploracao_a_ativa(self):
        self.assertEqual(risk.decision_points({"kev_listed": True})[0], "active")

    def test_staging_e_not_deployed_e_nao_unknown(self):
        """exp-002: descartar um fato que temos como um fato que faltamos e
        como os achados menos importantes de um estate afogam os mais graves."""
        self.assertEqual(risk.decision_points({"environment": "staging"})[1],
                         "not_deployed")

    def test_producao_exposta_e_open(self):
        dps = risk.decision_points({"environment": "prod", "internet_facing": True})
        self.assertEqual(dps[1], "open")


class TestAvaliacao(unittest.TestCase):

    def test_caso_log4shell(self):
        """KEV + producao exposta + aplicavel = agir agora."""
        r = risk.assess({
            "kev_listed": True, "environment": "prod", "internet_facing": True,
            "range_covers_deployed": True, "criticality": "critical"})
        self.assertEqual(r["band"], Band.ACT_NOW.value)
        self.assertEqual(r["non_suppressible"], "kev_listed")
        self.assertFalse(r["auto_deprioritize_eligible"])

    def test_kev_impoe_piso_mesmo_em_ativo_irrelevante(self):
        """O piso de sobreposicao: KEV nunca cai abaixo de act_soon."""
        r = risk.assess({
            "kev_listed": True, "environment": "staging",
            "criticality": "low", "compensating_control": "enforcing"})
        self.assertIn(r["band"], (Band.ACT_NOW.value, Band.ACT_SOON.value))
        self.assertEqual(r["non_suppressible"], "kev_listed")

    def test_caso_depriorizavel(self):
        r = risk.assess({
            "kev_listed": False, "environment": "prod", "internet_facing": False,
            "entry_point_confirmed": False, "range_covers_deployed": True,
            "criticality": "low", "compensating_control": "enforcing"})
        self.assertEqual(r["band"], Band.DEPRIORITIZE_CANDIDATE.value)
        self.assertTrue(r["auto_deprioritize_eligible"])

    def test_criticidade_desconhecida_bloqueia_auto_depriorizacao(self):
        r = risk.assess({"kev_listed": False, "environment": "dev"})
        self.assertIn("criticality_unresolved", r["ineligibility_reasons"])
        self.assertFalse(r["auto_deprioritize_eligible"])

    def test_toda_avaliacao_traz_razoes_legiveis(self):
        """Explicabilidade e requisito, nao enfeite."""
        r = risk.assess({"kev_listed": True, "criticality": "high"})
        self.assertTrue(r["reasons"])
        self.assertTrue(all(isinstance(x, str) and x for x in r["reasons"]))

    def test_versao_do_modelo_e_registrada(self):
        self.assertIn("risk-model", risk.assess({})["model_version"])

    def test_epss_nao_altera_a_banda(self):
        """EPSS e sinal de ORDENACAO. Se ele mudasse a banda, seria gatilho."""
        base = {"kev_listed": False, "environment": "prod", "internet_facing": False,
                "range_covers_deployed": True, "criticality": "medium"}
        baixo = risk.assess({**base, "epss_percentile": 0.01})
        alto = risk.assess({**base, "epss_percentile": 0.99})
        self.assertEqual(baixo["band"], alto["band"],
                         "EPSS nao pode mover a banda — seria gatilho de facto")
        self.assertGreater(alto["ordering_score"], baixo["ordering_score"],
                           "mas deve mover a ordenacao dentro da banda")


class TestParidadeComPhase0(unittest.TestCase):
    """A arvore do app tem que dar a MESMA resposta que a do instrumento."""

    def setUp(self):
        import os
        import sys
        p0 = os.path.join(support.REPO_ROOT, "phase0")
        if p0 not in sys.path:
            sys.path.insert(0, p0)
        try:
            import v2_riskmodel
            self.v2 = v2_riskmodel
        except ImportError:
            self.skipTest("phase0/v2_riskmodel.py indisponivel")

    def test_as_720_combinacoes_dao_a_mesma_banda(self):
        divergencias = []
        for combo in risk.all_combinations():
            minha, _ = risk.band_of(*combo)
            dele, _ = self.v2.band_of(*combo)
            if minha != dele:
                divergencias.append((combo, minha, dele))
        self.assertEqual(divergencias, [],
                         f"{len(divergencias)} combinacoes divergem do instrumento")


if __name__ == "__main__":
    unittest.main(verbosity=2)
