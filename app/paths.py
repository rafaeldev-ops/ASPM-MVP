"""
Onde ficam as coisas, com ou sem executavel congelado.

A LICAO QUE ESTE MODULO EXISTE PARA APLICAR
-------------------------------------------
O maior risco de congelar um aplicativo Python **nao sao imports, sao escritas**.
Import quebrado falha na hora, alto e claro. Escrita quebrada falha depois da
instalacao, na maquina de outra pessoa, com `PermissionError` num caminho que
so existe na maquina de quem empacotou.

Sob PyInstaller, `__file__` aponta para um diretorio de extracao **somente
leitura** (`sys._MEIPASS`). Todo caminho derivado dele serve para LER recurso e
nao serve para GRAVAR nada.

Entao ha duas raizes, e confundi-las e o bug:

    recurso(...)   ->  ao lado do codigo. Templates, CSS, dados embutidos.
                       Somente leitura quando congelado.
    dados(...)     ->  %LOCALAPPDATA%\\PrideSecurity. Banco, cache, exports.
                       Sempre gravavel, sobrevive a desinstalacao.

POR QUE %LOCALAPPDATA% E NAO "ao lado do .exe"
-----------------------------------------------
Instalacao **por usuario** ali dispensa UAC, e `Program Files` e somente leitura
para usuario comum -- gravar o banco ao lado do executavel funcionaria na
maquina do desenvolvedor e falharia na do usuario. E dado de seguranca da
organizacao nao deve ficar num diretorio que qualquer instalador limpa.

As variaveis `SDIP_DB_PATH` e `SDIP_CACHE_DIR` continuam vencendo tudo: e assim
que o container aponta para um volume, e que os testes apontam para um temporario.
"""

import os
import sys

APP_NAME = "PrideSecurity"


def congelado():
    """Rodando dentro de um executavel PyInstaller?"""
    return getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS")


def raiz_recursos():
    """Onde estao os arquivos que acompanham o codigo. **Somente leitura.**"""
    if congelado():
        return sys._MEIPASS
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def recurso(*partes):
    return os.path.join(raiz_recursos(), *partes)


def raiz_dados():
    """Onde a aplicacao pode gravar.

    Fora do Windows cai em `~/.local/share/PrideSecurity`, para o modulo nao
    virar um `if platform` espalhado pelo resto do codigo.
    """
    override = os.environ.get("SDIP_DATA_DIR")
    if override:
        return override
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.join(
            os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, APP_NAME)


def dados(*partes, criar=True):
    caminho = os.path.join(raiz_dados(), *partes)
    if criar:
        alvo = caminho if not os.path.splitext(caminho)[1] else os.path.dirname(caminho)
        try:
            os.makedirs(alvo, exist_ok=True)
        except OSError:
            pass
    return caminho


def caminho_do_banco():
    """`SDIP_DB_PATH` vence; senao, ao lado do codigo em desenvolvimento e em
    `%LOCALAPPDATA%` quando congelado.

    A distincao importa: em desenvolvimento, banco ao lado do repositorio e o
    que se espera (e esta no `.gitignore`). Instalado, ali seria somente leitura.
    """
    env = os.environ.get("SDIP_DB_PATH")
    if env:
        return env
    if congelado():
        return dados("sdip.db")
    return os.path.join(raiz_recursos(), "sdip.db")


def diretorio_de_cache():
    """Cache da KEV e afins. `SDIP_CACHE_DIR` vence."""
    env = os.environ.get("SDIP_CACHE_DIR")
    if env:
        return env
    if congelado():
        return dados("cache")
    return os.path.join(raiz_recursos(), "phase0", ".cache")


def descrever():
    """Para a tela de configuracao e para o relatorio de problema.

    Usuario que nao acha o proprio banco abre chamado; uma linha na interface
    resolve isso mais barato que qualquer documentacao.
    """
    return {
        "congelado": congelado(),
        "recursos": raiz_recursos(),
        "dados": raiz_dados(),
        "banco": caminho_do_banco(),
        "cache": diretorio_de_cache(),
    }
