"""
Runner de migracao.

O teste que importa e o do **banco que ja existia**: `create_all()` cria tabela
nova mas nunca altera existente, entao um banco criado antes da coluna nunca a
ganharia sozinho. Testar so em banco novo provaria que `create_all` funciona --
que nunca foi a duvida.
"""

import os
import tempfile
import unittest

from tests import support  # noqa: F401  (SDIP_DB_PATH antes de app.*)

from sqlalchemy import create_engine, text

from app import db_migrations as mig


class TestRunner(unittest.TestCase):

    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db", dir=support._TMP)
        os.close(fd)
        os.unlink(self.path)
        self.engine = create_engine(f"sqlite:///{self.path}")

    def tearDown(self):
        self.engine.dispose()
        try:
            os.unlink(self.path)
        except OSError:
            pass

    def _cols(self, table):
        with self.engine.begin() as c:
            return {r[1] for r in c.execute(text(f"PRAGMA table_info({table})"))}

    def _banco_antigo(self):
        """Um `decisions` sem as colunas da Fase A, como num banco de 2026-08-24."""
        with self.engine.begin() as c:
            c.execute(text(
                "CREATE TABLE decisions ("
                " id INTEGER PRIMARY KEY, org_id VARCHAR(60) NOT NULL,"
                " finding_id INTEGER NOT NULL, reason VARCHAR(30) NOT NULL,"
                " rationale TEXT, classification VARCHAR(30) NOT NULL)"))
            c.execute(text(
                "INSERT INTO decisions (id, org_id, finding_id, reason, rationale,"
                " classification) VALUES (1, 'org-local', 7, 'false_positive',"
                " 'decisao anterior a migracao', 'REAL_EXTERNAL_DATA')"))

    def test_banco_novo_vai_ate_a_versao_corrente(self):
        r = mig.migrate(self.engine)
        self.assertEqual(r["to"], mig.SCHEMA_VERSION)
        self.assertEqual(r["to"], r["expected"])

    def test_rodar_de_novo_nao_faz_nada(self):
        mig.migrate(self.engine)
        r = mig.migrate(self.engine)
        self.assertEqual(r["applied"], [])
        self.assertEqual(r["from"], r["to"])

    def test_banco_antigo_ganha_as_colunas_sem_perder_dado(self):
        self._banco_antigo()
        self.assertNotIn("ai_analysis_id", self._cols("decisions"))

        r = mig.migrate(self.engine)

        self.assertIn(2, r["applied"])
        self.assertIn("ai_analysis_id", self._cols("decisions"))
        self.assertIn("ai_suggested_reason", self._cols("decisions"))

        with self.engine.begin() as c:
            row = c.execute(text(
                "SELECT rationale, ai_analysis_id FROM decisions WHERE id=1")).first()
        self.assertEqual(row[0], "decisao anterior a migracao")
        self.assertIsNone(row[1], "decisao antiga nao pode ganhar vinculo inventado")

    def test_alter_e_idempotente(self):
        self._banco_antigo()
        mig.migrate(self.engine)
        with self.engine.begin() as c:
            self.assertFalse(
                mig.add_column_if_missing(c, "decisions", "ai_analysis_id", "INTEGER"))

    def test_tabela_ausente_nao_levanta(self):
        """Um banco onde a tabela ainda nao existe: a migracao passa reto em vez
        de derrubar a aplicacao no boot."""
        with self.engine.begin() as c:
            self.assertFalse(
                mig.add_column_if_missing(c, "tabela_que_nao_existe", "x", "INTEGER"))

    def test_versoes_sao_ordenadas_e_sem_buraco(self):
        versoes = [v for v, _ in mig.MIGRATIONS]
        self.assertEqual(versoes, sorted(versoes))
        self.assertEqual(versoes, list(range(1, len(versoes) + 1)))
        self.assertEqual(versoes[-1], mig.SCHEMA_VERSION,
                         "SCHEMA_VERSION nao acompanhou a lista MIGRATIONS")

    def test_carimbo_registra_quando_e_o_que(self):
        mig.migrate(self.engine)
        with self.engine.begin() as c:
            linhas = c.execute(text(
                "SELECT version, applied_at, note FROM schema_version "
                "ORDER BY version")).all()
        self.assertEqual(len(linhas), len(mig.MIGRATIONS))
        for v, quando, nota in linhas:
            self.assertTrue(quando)
            self.assertTrue(nota, f"migracao {v} sem nota")


class TestConcordancia(unittest.TestCase):
    """A coluna existe por uma metrica; o teste e sobre a metrica."""

    def setUp(self):
        self.s = support.fresh_session()

    def tearDown(self):
        self.s.close()

    def _decide(self, **kw):
        from app.domain.models import Decision
        return Decision(org_id="org-local", finding_id=1,
                        classification="SYNTHETIC_DATA", **kw)

    def test_sem_sugestao_e_none_e_nao_e_discordancia(self):
        """Colapsar 'nao havia sugestao' em 'discordou' arruinaria a taxa."""
        d = self._decide(reason="false_positive")
        self.assertIsNone(d.agreed_with_ai)

    def test_concordou(self):
        d = self._decide(reason="false_positive",
                         ai_suggested_reason="false_positive")
        self.assertTrue(d.agreed_with_ai)

    def test_discordou(self):
        d = self._decide(reason="wont_fix", ai_suggested_reason="false_positive")
        self.assertFalse(d.agreed_with_ai)

    def test_sugestao_invalida_nao_e_gravada(self):
        """O valor chega do formulario, ou seja, do cliente. Uma categoria
        inventada contaminaria a taxa."""
        from app.application.review import _valid_reason
        self.assertIsNone(_valid_reason("razao_que_nao_existe"))
        self.assertIsNone(_valid_reason(""))
        self.assertEqual(_valid_reason("FALSE_POSITIVE"), "false_positive")


if __name__ == "__main__":
    unittest.main(verbosity=2)
