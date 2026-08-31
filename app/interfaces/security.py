"""
Defesa contra CSRF no servidor local.

O PROBLEMA, e por que ele so aparece agora
------------------------------------------
Enquanto isto era `python -m uvicorn` rodando quando o analista quer, a janela
era curta. Como aplicativo instalado, o servidor fica de pe o dia inteiro em
`127.0.0.1:8000` -- e **qualquer pagina aberta no navegador do usuario pode
enviar um POST para la**. A politica de mesma origem impede o atacante de LER a
resposta; ela nao impede o pedido de acontecer.

O que um pedido desses conseguiria hoje: importar dados, reprocessar, trocar o
provider de IA para um externo, e disparar analise -- ou seja, **causar egresso
de dado de seguranca para um terceiro escolhido pelo atacante**. E o unico
lugar do sistema onde uma pagina remota consegue efeito colateral real.

A DEFESA, em duas camadas
-------------------------
**1. Origem verificada (`SameOriginMiddleware`).** Todo metodo inseguro precisa
provar que veio da propria aplicacao. Navegador moderno envia `Origin` em POST
de formulario e em `fetch`, sempre, e **nao existe forma de a pagina suprimir
esse cabecalho** -- e por isso que a checagem funciona. `Referer` entra como
segunda leitura para clientes antigos.

**2. Token de duplo envio (`csrf_token`).** Cookie `SameSite=Strict` mais campo
oculto no formulario. Num POST de outro site o navegador nem manda o cookie,
entao a comparacao falha sozinha. Existe como profundidade: se algum navegador
deixar de mandar `Origin`, esta camada ainda segura.

A DECISAO QUE PRECISA ESTAR ESCRITA
-----------------------------------
**Pedido sem `Origin` e sem `Referer` passa.** Isso e deliberado, e nao e um
buraco: quem faz esse pedido nao e navegador -- e `curl`, um script, a suite de
testes. E um script rodando na maquina do usuario **nao precisa de CSRF para
nada**: ele abre `sdip.db` direto. Bloquear ali custaria a API programatica e
nao tiraria nenhuma capacidade do atacante.

O ataque que este modulo existe para impedir e especificamente *pagina remota
dirigindo o navegador local*, e navegador sempre se identifica.

O QUE ISTO NAO RESOLVE
----------------------
Nada disto e autenticacao. Um processo local mal-intencionado continua tendo
acesso total ao banco -- e a resposta certa para isso e sistema de arquivos, nao
cabecalho HTTP. `docs/PROJECT_STATE.md` §Security Considerations registra o
limite.
"""

import hmac
import os
import secrets
from urllib.parse import urlsplit

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, PlainTextResponse

COOKIE_NAME = "sdip_csrf"
FORM_FIELD = "_csrf"
HEADER_NAME = "x-csrf-token"

METODOS_INSEGUROS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Hosts que contam como "esta maquina". Porta e ignorada de proposito: o
# instalador pode subir em porta livre, e travar a porta transformaria o
# controle numa fonte de suporte sem ganhar seguranca -- outra origem local ja
# tem acesso ao banco de qualquer jeito.
HOSTS_LOCAIS = frozenset({"127.0.0.1", "localhost", "[::1]", "::1"})


def _host_de(url):
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def origem_local(valor):
    """`Origin`/`Referer` aponta para esta maquina?

    `Origin: null` (sandbox de iframe, `data:`) devolve False de proposito: nao
    da para provar procedencia, entao nao passa.
    """
    if not valor or valor == "null":
        return False
    host = _host_de(valor)
    return bool(host) and host in HOSTS_LOCAIS


def novo_token():
    return secrets.token_urlsafe(32)


def token_da_requisicao(request):
    """O token desta sessao de navegador, criando um se ainda nao existe.

    Guardado em `request.state` para o mesmo valor servir ao formulario e ao
    cookie dentro do mesmo ciclo.
    """
    if getattr(request.state, "csrf_token", None):
        return request.state.csrf_token
    token = request.cookies.get(COOKIE_NAME) or novo_token()
    request.state.csrf_token = token
    return token


class SameOriginMiddleware(BaseHTTPMiddleware):
    """Recusa metodo inseguro cuja origem nao seja esta maquina."""

    def __init__(self, app, exempt_prefixes=()):
        super().__init__(app)
        self.exempt = tuple(exempt_prefixes)

    async def dispatch(self, request, call_next):
        if request.method in METODOS_INSEGUROS and not self._isento(request.url.path):
            recusa = self._checar(request)
            if recusa is not None:
                return recusa

        response = await call_next(request)

        # Cookie emitido em toda resposta que ja tenha um token no ciclo. Sem
        # `httponly` nao ha ganho aqui: o servidor injeta o valor no formulario,
        # entao nenhum JS precisa le-lo.
        token = getattr(request.state, "csrf_token", None)
        if token and request.cookies.get(COOKIE_NAME) != token:
            response.set_cookie(
                COOKIE_NAME, token, httponly=True, samesite="strict",
                secure=False, path="/")
        return response

    def _isento(self, path):
        return any(path.startswith(p) for p in self.exempt)

    def _checar(self, request):
        origin = request.headers.get("origin")
        referer = request.headers.get("referer")

        if origin is not None:
            if not origem_local(origin):
                return self._negar(request, "origem cruzada")
            return None

        if referer is not None:
            if not origem_local(referer):
                return self._negar(request, "referer de outra origem")
            return None

        # Nem um nem outro: nao e navegador. Ver o cabecalho deste modulo.
        return None

    @staticmethod
    def _negar(request, motivo):
        texto = (f"Pedido recusado: {motivo}. Esta aplicacao so aceita acoes "
                 f"iniciadas pelas proprias telas, em 127.0.0.1.")
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": texto}, status_code=403)
        return PlainTextResponse(texto, status_code=403)


def validar_token(request, enviado):
    """Duplo envio: o valor do formulario tem que bater com o do cookie.

    Comparacao em tempo constante por higiene, nao porque o modelo de ameaca
    exija -- o custo e zero e a alternativa ensina o habito errado.
    """
    do_cookie = request.cookies.get(COOKIE_NAME)
    if not do_cookie or not enviado:
        return False
    return hmac.compare_digest(str(do_cookie), str(enviado))


def desligado():
    """Escotilha para desenvolvimento, com nome que denuncia o que faz.

    Existe porque um controle sem saida documentada e um controle que alguem vai
    comentar no arquivo e esquecer commitado.
    """
    return os.environ.get("SDIP_DISABLE_CSRF") == "1"
