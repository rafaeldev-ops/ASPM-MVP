"""
Cofre de credenciais.

A chave de API de um provider externo nunca entra no banco, nem em arquivo de
configuracao, nem em log, nem em resposta de endpoint. No Windows ela vai para o
Credential Manager, que cifra o blob por perfil de usuario (DPAPI por baixo).

`ctypes` contra `advapi32.dll`, sem dependencia nova. `keyring` foi descartado
porque descobre backends por entry points, e um sistema de plugins e mais um
problema de hook quando isto for congelado num executavel.

O fallback e um **tipo**, nao um `if platform.system()` espalhado pelo codigo.
Fora do Windows o cofre e somente-leitura sobre variavel de ambiente, e a tela
diz isso. Gravar chave em texto plano em `~/.config` seria postura pior que a
variavel -- e a ADR-0011 e explicita: afrouxar depois e facil, apertar depois de
um vazamento e impossivel.
"""

import ctypes
import os
import sys

CRED_TYPE_GENERIC = 1
CRED_PERSIST_LOCAL_MACHINE = 2
# O Credential Manager rejeita blob acima disso. Falhar com mensagem clara e
# melhor que um erro do Windows sem contexto.
MAX_BLOB_BYTES = 2560

TARGET_PREFIX = "PrideSecurity/ai/"


class CredentialError(Exception):
    pass


class CredentialStoreReadOnly(CredentialError):
    pass


# --------------------------------------------------------------------------
# Interface
# --------------------------------------------------------------------------

class CredentialStore:
    name = "none"
    available = False
    writable = False

    def get(self, key):
        return None

    def set(self, key, secret):
        raise CredentialStoreReadOnly(self.describe())

    def delete(self, key):
        raise CredentialStoreReadOnly(self.describe())

    def has(self, key):
        return self.get(key) is not None

    def describe(self):
        return "Nenhum cofre de credenciais disponivel nesta plataforma."


class NullCredentialStore(CredentialStore):
    """Sem cofre. A aplicacao continua util: o provider externo fica indisponivel
    e os modos local e desligado seguem funcionando."""


class EnvCredentialStore(CredentialStore):
    """Somente leitura, sobre variavel de ambiente.

    E o caminho de desenvolvimento e o do container. Deliberadamente sem
    escrita: persistir chave num arquivo que ninguem lembra de apagar e pior que
    exigir a variavel.
    """

    name = "env"
    available = True
    writable = False

    ENV_BY_KEY = {"openai": "SDIP_OPENAI_API_KEY"}

    def get(self, key):
        var = self.ENV_BY_KEY.get(key)
        if not var:
            return None
        return (os.environ.get(var) or "").strip() or None

    def describe(self):
        vars_ = ", ".join(sorted(self.ENV_BY_KEY.values()))
        return (f"Nesta plataforma a chave vem de variavel de ambiente ({vars_}) "
                f"e nao e persistida pela aplicacao.")


# --------------------------------------------------------------------------
# Windows
# --------------------------------------------------------------------------

if sys.platform == "win32":
    from ctypes import wintypes

    class _FILETIME(ctypes.Structure):
        _fields_ = [("dwLowDateTime", wintypes.DWORD),
                    ("dwHighDateTime", wintypes.DWORD)]

    class _CREDENTIAL_ATTRIBUTEW(ctypes.Structure):
        _fields_ = [("Keyword", wintypes.LPWSTR),
                    ("Flags", wintypes.DWORD),
                    ("ValueSize", wintypes.DWORD),
                    ("Value", ctypes.POINTER(ctypes.c_byte))]

    class _CREDENTIALW(ctypes.Structure):
        _fields_ = [("Flags", wintypes.DWORD),
                    ("Type", wintypes.DWORD),
                    ("TargetName", wintypes.LPWSTR),
                    ("Comment", wintypes.LPWSTR),
                    ("LastWritten", _FILETIME),
                    ("CredentialBlobSize", wintypes.DWORD),
                    ("CredentialBlob", ctypes.POINTER(ctypes.c_byte)),
                    ("Persist", wintypes.DWORD),
                    ("AttributeCount", wintypes.DWORD),
                    ("Attributes", ctypes.POINTER(_CREDENTIAL_ATTRIBUTEW)),
                    ("TargetAlias", wintypes.LPWSTR),
                    ("UserName", wintypes.LPWSTR)]


class WindowsCredentialStore(CredentialStore):
    """Credential Manager do Windows, via advapi32."""

    name = "wincred"
    writable = True

    def __init__(self):
        self._api = None
        if sys.platform != "win32":
            return
        try:
            api = ctypes.WinDLL("advapi32", use_last_error=True)
            api.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                      wintypes.DWORD,
                                      ctypes.POINTER(ctypes.POINTER(_CREDENTIALW))]
            api.CredReadW.restype = wintypes.BOOL
            api.CredWriteW.argtypes = [ctypes.POINTER(_CREDENTIALW), wintypes.DWORD]
            api.CredWriteW.restype = wintypes.BOOL
            api.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                        wintypes.DWORD]
            api.CredDeleteW.restype = wintypes.BOOL
            api.CredFree.argtypes = [ctypes.c_void_p]
            api.CredFree.restype = None
            self._api = api
        except (OSError, AttributeError):
            self._api = None

    @property
    def available(self):
        return self._api is not None

    @staticmethod
    def _target(key):
        return TARGET_PREFIX + str(key)

    def get(self, key):
        if not self.available:
            return None
        ptr = ctypes.POINTER(_CREDENTIALW)()
        ok = self._api.CredReadW(self._target(key), CRED_TYPE_GENERIC, 0,
                                 ctypes.byref(ptr))
        if not ok:
            return None
        try:
            cred = ptr.contents
            size = int(cred.CredentialBlobSize)
            if size <= 0:
                return None
            buf = ctypes.create_string_buffer(size)
            ctypes.memmove(buf, cred.CredentialBlob, size)
            try:
                return buf.raw.decode("utf-16-le").strip() or None
            finally:
                # Zeramos o buffer que e nosso. A `str` resultante e imutavel e
                # nao da para limpar em Python -- dizer isso e mais honesto que
                # fingir que a limpeza e completa.
                ctypes.memset(buf, 0, size)
        finally:
            self._api.CredFree(ptr)

    def set(self, key, secret):
        if not self.available:
            raise CredentialStoreReadOnly(self.describe())
        secret = str(secret or "")
        if not secret.strip():
            raise CredentialError("Segredo vazio.")
        blob = secret.encode("utf-16-le")
        if len(blob) > MAX_BLOB_BYTES:
            raise CredentialError(
                f"Segredo acima do limite do Credential Manager "
                f"({len(blob)} bytes; maximo {MAX_BLOB_BYTES}).")

        buf = ctypes.create_string_buffer(blob, len(blob))
        cred = _CREDENTIALW()
        ctypes.memset(ctypes.byref(cred), 0, ctypes.sizeof(cred))
        cred.Type = CRED_TYPE_GENERIC
        cred.TargetName = self._target(key)
        cred.Comment = "Pride Security ASPM"
        cred.CredentialBlobSize = len(blob)
        cred.CredentialBlob = ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte))
        cred.Persist = CRED_PERSIST_LOCAL_MACHINE
        cred.UserName = "pride-security"

        ok = self._api.CredWriteW(ctypes.byref(cred), 0)
        ctypes.memset(buf, 0, len(blob))
        if not ok:
            raise CredentialError(
                f"CredWriteW falhou (codigo {ctypes.get_last_error()}).")

    def delete(self, key):
        if not self.available:
            raise CredentialStoreReadOnly(self.describe())
        self._api.CredDeleteW(self._target(key), CRED_TYPE_GENERIC, 0)

    def describe(self):
        if not self.available:
            return "Credential Manager indisponivel neste processo."
        return ("A chave fica no Credential Manager do Windows, cifrada pelo seu "
                "perfil de usuario. Ela nunca e gravada no banco nem em arquivo.")


# --------------------------------------------------------------------------
# Selecao
# --------------------------------------------------------------------------

_store = None


def get_store():
    """O cofre desta maquina. Memoizado: a plataforma nao muda em execucao."""
    global _store
    if _store is None:
        if sys.platform == "win32":
            win = WindowsCredentialStore()
            _store = win if win.available else EnvCredentialStore()
        else:
            _store = EnvCredentialStore()
    return _store


def reset():
    """Para os testes. Nao usar em producao."""
    global _store
    _store = None


def resolve(key):
    """Busca a chave, preferindo a variavel de ambiente quando existir.

    A variavel vence porque e uma acao explicita do operador naquela execucao.
    Devolve `(segredo, origem)` -- e a origem e gravada em todo registro de
    analise, porque ambiguidade sobre a procedencia de uma credencial e ao mesmo
    tempo pesadelo de suporte e lacuna de auditoria.
    """
    env = EnvCredentialStore()
    from_env = env.get(key)
    if from_env:
        return from_env, "env"
    store = get_store()
    if store.name == "env":
        return None, "none"
    value = store.get(key)
    return (value, store.name) if value else (None, "none")


def info():
    """Estado do cofre para a tela. Nunca inclui a chave, nem parte dela."""
    store = get_store()
    return {"backend": store.name, "available": bool(store.available),
            "writable": bool(store.writable), "detail": store.describe()}
