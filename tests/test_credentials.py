"""
Cofre de credencial.

`credentials.py` e `ctypes` cru contra `advapi32`. Sem um round-trip de verdade
ninguem sabe se as bindings funcionam -- e o modo de falha e silencioso: a chave
some, a analise externa diz "sem chave", e o usuario nao sabe por que.

O teste **escreve no cofre real do usuario**, sob um alvo com nome de teste, e
apaga no `tearDown` inclusive quando a asserção falha. Escrever num cofre falso
provaria que o cofre falso funciona.
"""

import os
import unittest

from tests import support  # noqa: F401  (define SDIP_DB_PATH antes de app.*)

from app.infrastructure import credentials as cred

CHAVE = "teste-round-trip-nao-usar"
SEGREDO = "sk-valor-de-teste-1234567890abcdef"


class TestWindowsCredentialStore(unittest.TestCase):
    """Round-trip contra o Windows Credential Manager de verdade."""

    def setUp(self):
        cred.reset()
        self.store = cred.WindowsCredentialStore()
        if not self.store.available:
            self.skipTest("Credential Manager indisponivel (nao e Windows?)")

    def tearDown(self):
        # Inclusive quando a asserção falha: nao deixar residuo no cofre.
        try:
            self.store.delete(CHAVE)
        except Exception:
            pass
        cred.reset()

    def test_round_trip(self):
        self.store.set(CHAVE, SEGREDO)
        self.assertEqual(self.store.get(CHAVE), SEGREDO)
        self.assertTrue(self.store.has(CHAVE))

    def test_sobrescrita(self):
        self.store.set(CHAVE, SEGREDO)
        self.store.set(CHAVE, SEGREDO + "-novo")
        self.assertEqual(self.store.get(CHAVE), SEGREDO + "-novo")

    def test_apagar_e_idempotente(self):
        self.store.set(CHAVE, SEGREDO)
        self.store.delete(CHAVE)
        self.assertIsNone(self.store.get(CHAVE))
        self.assertFalse(self.store.has(CHAVE))
        self.store.delete(CHAVE)  # de novo, sem levantar

    def test_ausente_devolve_none_em_vez_de_levantar(self):
        self.assertIsNone(self.store.get("chave-que-nunca-existiu-zzz"))

    def test_unicode_e_segredo_longo(self):
        """UTF-16 nos dois sentidos, e o limite de 2560 bytes do blob."""
        valor = "ção-ünïcode-" + "a" * 600
        self.store.set(CHAVE, valor)
        self.assertEqual(self.store.get(CHAVE), valor)

    def test_alvo_e_namespaced(self):
        self.assertTrue(self.store._target(CHAVE).startswith("PrideSecurity/ai/"))


class TestEnvCredentialStore(unittest.TestCase):

    def setUp(self):
        self._env = dict(os.environ)
        cred.reset()

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)
        cred.reset()

    def test_le_do_ambiente(self):
        os.environ["SDIP_OPENAI_API_KEY"] = SEGREDO
        self.assertEqual(cred.EnvCredentialStore().get("openai"), SEGREDO)

    def test_e_somente_leitura(self):
        """Gravar chave em texto plano em disco seria postura pior que a
        variavel de ambiente. O tipo recusa em vez de fingir."""
        with self.assertRaises(cred.CredentialStoreReadOnly):
            cred.EnvCredentialStore().set("openai", SEGREDO)
        with self.assertRaises(cred.CredentialStoreReadOnly):
            cred.EnvCredentialStore().delete("openai")


class TestNaoVaza(unittest.TestCase):

    def test_info_nao_devolve_segredo_nem_parte_dele(self):
        """Nem os ultimos quatro caracteres: divulgacao parcial por zero
        beneficio."""
        os.environ["SDIP_OPENAI_API_KEY"] = SEGREDO
        cred.reset()
        try:
            blob = repr(cred.info())
            self.assertNotIn(SEGREDO, blob)
            self.assertNotIn(SEGREDO[-4:], blob)
        finally:
            os.environ.pop("SDIP_OPENAI_API_KEY", None)
            cred.reset()

    def test_resolve_devolve_a_origem_junto(self):
        os.environ["SDIP_OPENAI_API_KEY"] = SEGREDO
        cred.reset()
        try:
            segredo, origem = cred.resolve("openai")
            self.assertEqual(segredo, SEGREDO)
            self.assertTrue(origem)
            self.assertNotIn(SEGREDO, origem)
        finally:
            os.environ.pop("SDIP_OPENAI_API_KEY", None)
            cred.reset()

    def test_describe_nao_toca_no_valor(self):
        for store in (cred.NullCredentialStore(), cred.EnvCredentialStore()):
            with self.subTest(store=type(store).__name__):
                self.assertNotIn(SEGREDO, repr(store.describe()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
