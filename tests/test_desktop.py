"""
Empacotamento: caminhos e launcher.

O maior risco de congelar um aplicativo Python nao sao imports -- import
quebrado falha alto, na hora. Sao **escritas**: elas falham depois da
instalacao, na maquina de outra pessoa, num caminho que so existe na maquina de
quem empacotou.

Entao o que se testa aqui e a separacao entre as duas raizes, e sobretudo que
nada gravavel cai no diretorio do codigo quando congelado.
"""

import os
import socket
import sys
import unittest

from tests import support  # noqa: F401  (SDIP_DB_PATH antes de app.*)

import launcher
from app import paths


class BasePaths(unittest.TestCase):
    def setUp(self):
        self._env = dict(os.environ)
        self._frozen = getattr(sys, "frozen", None)
        self._meipass = getattr(sys, "_MEIPASS", None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)
        for attr, valor in (("frozen", self._frozen), ("_MEIPASS", self._meipass)):
            if valor is None:
                if hasattr(sys, attr):
                    delattr(sys, attr)
            else:
                setattr(sys, attr, valor)

    def _congelar(self, mei):
        sys.frozen = True
        sys._MEIPASS = mei


class TestDuasRaizes(BasePaths):

    def test_em_desenvolvimento_nao_ha_congelamento(self):
        self.assertFalse(paths.congelado())

    def test_congelado_le_recurso_do_meipass(self):
        self._congelar(r"C:\Temp\_MEI12345")
        self.assertTrue(paths.congelado())
        self.assertEqual(paths.raiz_recursos(), r"C:\Temp\_MEI12345")
        self.assertTrue(paths.recurso("app", "templates").startswith(r"C:\Temp\_MEI12345"))

    def test_congelado_NAO_grava_junto_do_codigo(self):
        """A regressao que este modulo existe para impedir.

        `sys._MEIPASS` e somente leitura. Um banco apontando para la funciona no
        `python launcher.py` e quebra com `PermissionError` no `.exe` instalado.
        """
        mei = r"C:\Temp\_MEI12345"
        self._congelar(mei)
        for var in ("SDIP_DB_PATH", "SDIP_CACHE_DIR", "SDIP_DATA_DIR"):
            os.environ.pop(var, None)

        for caminho in (paths.caminho_do_banco(), paths.diretorio_de_cache(),
                        paths.raiz_dados()):
            with self.subTest(caminho=caminho):
                self.assertFalse(caminho.startswith(mei),
                                 f"caminho gravavel dentro do _MEIPASS: {caminho}")

    def test_congelado_grava_em_localappdata(self):
        self._congelar(r"C:\Temp\_MEI12345")
        os.environ.pop("SDIP_DB_PATH", None)
        os.environ.pop("SDIP_DATA_DIR", None)
        os.environ["LOCALAPPDATA"] = r"C:\Users\alguem\AppData\Local"
        if os.name == "nt":
            self.assertIn("PrideSecurity", paths.caminho_do_banco())
            self.assertTrue(paths.caminho_do_banco().endswith("sdip.db"))

    def test_variaveis_de_ambiente_vencem_tudo(self):
        """E assim que o container aponta para um volume e o teste para um
        temporario. Quebrar isso quebra os dois de uma vez."""
        self._congelar(r"C:\Temp\_MEI12345")
        os.environ["SDIP_DB_PATH"] = r"D:\outro\lugar.db"
        os.environ["SDIP_CACHE_DIR"] = r"D:\outro\cache"
        self.assertEqual(paths.caminho_do_banco(), r"D:\outro\lugar.db")
        self.assertEqual(paths.diretorio_de_cache(), r"D:\outro\cache")

    def test_data_dir_redireciona_a_raiz_inteira(self):
        os.environ["SDIP_DATA_DIR"] = r"D:\portatil"
        self.assertEqual(paths.raiz_dados(), r"D:\portatil")

    def test_descrever_nao_esconde_nada(self):
        """Usuario que nao acha o proprio banco abre chamado."""
        d = paths.descrever()
        for chave in ("congelado", "recursos", "dados", "banco", "cache"):
            self.assertIn(chave, d)


class TestLauncher(BasePaths):

    def test_prefere_8000_quando_livre(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            livre = s.getsockname()[1]
        self.assertEqual(launcher.porta_livre(livre), livre)

    def test_cai_para_outra_porta_quando_ocupada(self):
        """Porta fixa colidiria com qualquer outra coisa na 8000, e o usuario
        nao teria como saber o que aconteceu."""
        with socket.socket() as ocupada:
            ocupada.bind(("127.0.0.1", 0))
            ocupada.listen(1)
            porta = ocupada.getsockname()[1]
            escolhida = launcher.porta_livre(porta)
        self.assertNotEqual(escolhida, porta)
        self.assertGreater(escolhida, 0)

    def test_trava_orfa_nao_impede_de_abrir(self):
        """Desligamento sujo deixa o arquivo para tras. Um aplicativo que se
        recusa a abrir por causa disso e pior que um aberto duas vezes."""
        os.environ["SDIP_DATA_DIR"] = os.path.join(support._TMP, "launcher-orfa")
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            morta = s.getsockname()[1]
        launcher.marcar_instancia(morta)
        try:
            self.assertIsNone(launcher.instancia_viva(),
                              "trava orfa foi tratada como instancia viva")
        finally:
            launcher.limpar_instancia()

    def test_instancia_viva_e_detectada(self):
        os.environ["SDIP_DATA_DIR"] = os.path.join(support._TMP, "launcher-viva")
        with socket.socket() as viva:
            viva.bind(("127.0.0.1", 0))
            viva.listen(1)
            porta = viva.getsockname()[1]
            launcher.marcar_instancia(porta)
            try:
                self.assertEqual(launcher.instancia_viva(), porta)
            finally:
                launcher.limpar_instancia()

    def test_sem_trava_nao_ha_instancia(self):
        os.environ["SDIP_DATA_DIR"] = os.path.join(support._TMP, "launcher-vazio")
        launcher.limpar_instancia()
        self.assertIsNone(launcher.instancia_viva())

    @staticmethod
    def _literais_do_launcher():
        """Strings que o codigo realmente usa.

        Por AST e nao por `in`: a primeira versao deste teste falhou contra a
        propria docstring que explica por que 0.0.0.0 nao entra. Comentario que
        cita o valor proibido nao e o valor proibido.
        """
        import ast
        with open(launcher.__file__, encoding="utf-8") as f:
            arvore = ast.parse(f.read())
        docs = set()
        for no in ast.walk(arvore):
            if isinstance(no, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                               ast.ClassDef)):
                d = ast.get_docstring(no, clean=False)
                if d:
                    docs.add(d)
        return [n.value for n in ast.walk(arvore)
                if isinstance(n, ast.Constant) and isinstance(n.value, str)
                and n.value not in docs]

    def test_so_escuta_em_loopback(self):
        """A ausencia de autenticacao e um fato do produto (L4). Escutar em
        qualquer interface publicaria dado de seguranca para a rede local."""
        self.assertEqual(launcher.HOST, "127.0.0.1")
        for literal in self._literais_do_launcher():
            self.assertNotIn("0.0.0.0", literal,
                             "endereco de escuta aberto no codigo do launcher")

    def test_nao_usa_reload_nem_workers(self):
        """Os dois criam subprocesso, e subprocesso dentro de executavel
        congelado reexecuta o proprio .exe -- instancias em cascata."""
        import ast
        with open(launcher.__file__, encoding="utf-8") as f:
            arvore = ast.parse(f.read())
        proibidos = {"reload", "workers"}
        for no in ast.walk(arvore):
            if isinstance(no, ast.Call):
                for kw in no.keywords:
                    self.assertNotIn(kw.arg, proibidos,
                                     f"launcher chama algo com {kw.arg}=")


class TestEmpacotamento(unittest.TestCase):
    """O spec e o instalador sao codigo, e erram calados."""

    def _ler(self, nome):
        caminho = os.path.join(support.REPO_ROOT, "packaging", nome)
        if not os.path.exists(caminho):
            self.skipTest(f"{nome} ausente")
        with open(caminho, encoding="utf-8") as f:
            return f.read()

    def test_spec_declara_os_imports_invisiveis(self):
        """uvicorn escolhe loop e protocolo por string; analise estatica nao ve."""
        spec = self._ler("pride-security.spec")
        for alvo in ("uvicorn", "app.domain.models", "app.db_migrations"):
            self.assertIn(alvo, spec, f"{alvo} nao esta em hiddenimports")

    def test_spec_embarca_templates_e_static(self):
        spec = self._ler("pride-security.spec")
        self.assertIn("templates", spec)
        self.assertIn("static", spec)

    def test_spec_nao_usa_onefile_nem_upx(self):
        """onefile extrai em %TEMP% a cada execucao e UPX dispara heuristica de
        antivirus -- os dois contra o publico exato deste produto."""
        spec = self._ler("pride-security.spec")
        self.assertIn("upx=False", spec)
        self.assertIn("COLLECT", spec, "onedir exige COLLECT")

    def test_instalador_e_por_usuario(self):
        """Sem UAC, e sem gravar em Program Files -- que seria somente leitura
        para o usuario comum."""
        iss = self._ler("pride-security.iss")
        self.assertIn("PrivilegesRequired=lowest", iss)
        self.assertIn("{userpf}", iss)

    def test_desinstalacao_nao_apaga_o_banco_por_padrao(self):
        """Historico de decisao e o ativo do produto. Perda silenciosa nele e
        pior que reinstalar."""
        iss = self._ler("pride-security.iss")
        self.assertIn("MB_DEFBUTTON2", iss,
                      "o padrao do dialogo precisa ser NAO apagar")
        self.assertNotIn("Type: filesandordirs; Name: \"{localappdata}\\PrideSecurity\"",
                         iss)


if __name__ == "__main__":
    unittest.main(verbosity=2)
