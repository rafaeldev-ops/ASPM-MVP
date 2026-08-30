"""
Transporte HTTP para os adaptadores de modelo.

Somente `urllib.request` da biblioteca padrao. Zero dependencia nova, e a razao
nao e tamanho: `urllib` usa `ssl.create_default_context()`, que no Windows le o
**repositorio de confianca do sistema**. Num notebook corporativo com proxy que
inspeciona TLS, esse caminho funciona; um cliente que traz o proprio pacote de
certificados falha com erro opaco.

O trabalho deste modulo e o que a ADR-0015 §1 define para um adaptador:
transporte, retry, timeout e telemetria. Validar resposta e de outra camada.
"""

import json
import ssl
import time
import urllib.error
import urllib.request

# Retry so onde repetir pode dar outro resultado. Nunca em 400/401/403/404/422:
# chave errada, modelo inexistente ou schema recusado falham identicamente na
# segunda tentativa, e cada tentativa e outro egresso -- cobrado, e registrado
# como mais uma divulgacao.
RETRYABLE_STATUS = frozenset({408, 429, 500, 502, 503, 504})
BACKOFF_S = (0.5, 1.5)
MAX_BACKOFF_S = 10.0


class HttpResult:
    """O que voltou, incluindo o que aconteceu no caminho."""

    def __init__(self, status, body, headers=None, attempts=1,
                 elapsed_ms=0, error=None):
        self.status = status
        self.body = body
        self.headers = headers or {}
        self.attempts = attempts
        self.elapsed_ms = elapsed_ms
        self.error = error

    @property
    def ok(self):
        return self.error is None and 200 <= (self.status or 0) < 300

    def json(self):
        """Corpo como JSON, ou None. Nunca levanta -- corpo malformado e um
        resultado a classificar, nao uma excecao a propagar."""
        try:
            return json.loads(self.body)
        except (ValueError, TypeError):
            return None

    def __repr__(self):
        return (f"<HttpResult {self.status} attempts={self.attempts} "
                f"{self.elapsed_ms}ms error={self.error!r}>")


def _opener(no_proxy):
    """Opener dedicado.

    `no_proxy` existe por um motivo especifico e nao obvio: `urllib.request`
    instala um ProxyHandler a partir de HTTP_PROXY/HTTPS_PROXY. Numa maquina com
    essas variaveis, uma requisicao para 127.0.0.1 sairia pelo proxy corporativo
    -- para fora da maquina -- enquanto a interface exibe o selo `local`. Quem
    promete egresso local passa `no_proxy=True`, e ainda assim verifica loopback
    por conta propria. Os dois, nao um.
    """
    handlers = []
    if no_proxy:
        handlers.append(urllib.request.ProxyHandler({}))
    handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    return urllib.request.build_opener(*handlers)


def post_json(url, payload, *, headers=None, timeout=60.0, retries=2,
              no_proxy=False):
    """POST de JSON. Nunca levanta: devolve HttpResult com `error` preenchido."""
    data = json.dumps(payload).encode("utf-8")
    hdrs = {"Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "PrideSecurity-ASPM/0.1"}
    hdrs.update(headers or {})

    opener = _opener(no_proxy)
    started = time.monotonic()
    last = None

    for attempt in range(1, max(1, retries + 1) + 1):
        req = urllib.request.Request(url, data=data, headers=hdrs, method="POST")
        try:
            with opener.open(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                elapsed = int((time.monotonic() - started) * 1000)
                return HttpResult(resp.status, body, dict(resp.headers),
                                  attempt, elapsed)
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            last = HttpResult(exc.code, body, dict(exc.headers or {}), attempt,
                              int((time.monotonic() - started) * 1000))
            if exc.code not in RETRYABLE_STATUS or attempt > retries:
                return last
            _sleep_for(attempt, last.headers.get("Retry-After"))
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = HttpResult(None, "", {}, attempt,
                              int((time.monotonic() - started) * 1000),
                              error=_classify(exc))
            if attempt > retries:
                return last
            _sleep_for(attempt, None)

    return last


def get_json(url, *, headers=None, timeout=10.0, no_proxy=False):
    """GET simples, sem retry. Usado para sondagem de disponibilidade, onde uma
    resposta rapida importa mais que insistir."""
    hdrs = {"Accept": "application/json", "User-Agent": "PrideSecurity-ASPM/0.1"}
    hdrs.update(headers or {})
    opener = _opener(no_proxy)
    started = time.monotonic()
    req = urllib.request.Request(url, headers=hdrs, method="GET")
    try:
        with opener.open(req, timeout=timeout) as resp:
            return HttpResult(resp.status, resp.read().decode("utf-8", errors="replace"),
                              dict(resp.headers), 1,
                              int((time.monotonic() - started) * 1000))
    except urllib.error.HTTPError as exc:
        return HttpResult(exc.code, "", dict(exc.headers or {}), 1,
                          int((time.monotonic() - started) * 1000))
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return HttpResult(None, "", {}, 1,
                          int((time.monotonic() - started) * 1000),
                          error=_classify(exc))


def _classify(exc):
    """Motivo curto e legivel. Nunca inclui corpo de resposta nem credencial."""
    text = str(getattr(exc, "reason", exc) or exc)
    low = text.lower()
    if "timed out" in low or isinstance(exc, TimeoutError):
        return "timeout"
    if "refused" in low:
        return "connection_refused"
    if "certificate" in low or "ssl" in low:
        return "tls_error"
    if "name or service" in low or "getaddrinfo" in low:
        return "dns_error"
    return "connection_error"


def _sleep_for(attempt, retry_after):
    delay = BACKOFF_S[min(attempt - 1, len(BACKOFF_S) - 1)]
    if retry_after:
        try:
            delay = max(delay, float(retry_after))
        except (TypeError, ValueError):
            pass
    time.sleep(min(delay, MAX_BACKOFF_S))
