"""
Adaptador Ollama — modelo local.

**`localhost` e verificado, nao declarado.** O selo que a tela exibe e uma
propriedade checada: o adaptador resolve o host configurado e recusa enviar se
algum endereco resolvido nao for loopback. Duas consequencias: o Ollama Cloud
fica estruturalmente excluido (o que e correto de todo modo, porque ele nao
suporta structured output), e a promessa da interface deixa de ser um rotulo.

**A armadilha do proxy.** `urllib.request` instala um ProxyHandler a partir de
HTTP_PROXY/HTTPS_PROXY. Numa maquina com essas variaveis, uma requisicao para
127.0.0.1 sairia pelo proxy corporativo -- para fora da maquina -- enquanto a
tela exibe `local`. Por isso o transporte e sempre `no_proxy=True` **e** a
verificacao de loopback roda por conta propria. Os dois, nao um.
"""

import ipaddress
import socket
from urllib.parse import urlparse

from app.application.ai.prompt import OUTPUT_SCHEMA, build_messages
from app.application.ai.provider import (
    AIProvider, EgressClass, ProviderMalformed, ProviderResponse,
    ProviderStatus, ProviderTimeout, ProviderUnavailable,
)
from app.infrastructure import http

DEFAULT_BASE_URL = "http://127.0.0.1:11434"


class NotLoopbackError(ProviderUnavailable):
    """O host configurado nao resolve para loopback."""


class OllamaProvider(AIProvider):
    name = "ollama"
    egress = EgressClass.LOCALHOST
    requires_api_key = False
    supports_structured_output = True

    @property
    def base_url(self):
        return (self.settings.base_url or DEFAULT_BASE_URL).rstrip("/")

    def _assert_loopback(self):
        """Recusa qualquer host que nao seja loopback.

        Isto e o que torna `egress=LOCALHOST` uma afirmacao verificavel em vez de
        um rotulo, e e a razao de o Ollama Cloud nao poder ser configurado aqui.
        """
        host = urlparse(self.base_url).hostname or ""
        if not host:
            raise NotLoopbackError(f"URL invalida: {self.base_url}")
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror as exc:
            raise ProviderUnavailable(f"Nao consegui resolver {host}: {exc}")
        for info in infos:
            addr = info[4][0]
            try:
                if not ipaddress.ip_address(addr).is_loopback:
                    raise NotLoopbackError(
                        f"{host} resolve para {addr}, que nao e loopback. O "
                        f"provider local so aceita enderecos desta maquina.")
            except ValueError:
                raise NotLoopbackError(f"Endereco nao reconhecido: {addr}")
        return True

    def status(self, timeout=None):
        timeout = timeout or self.settings.probe_timeout_s
        try:
            self._assert_loopback()
        except ProviderUnavailable as exc:
            return ProviderStatus(False, str(exc))

        version = http.get_json(f"{self.base_url}/api/version",
                                timeout=timeout, no_proxy=True)
        if not version.ok:
            return ProviderStatus(
                False,
                "Nenhum runtime local respondeu. Instale e inicie o Ollama, ou "
                "escolha outro provider.")

        tags = http.get_json(f"{self.base_url}/api/tags",
                             timeout=timeout, no_proxy=True)
        models = []
        body = tags.json() if tags.ok else None
        if isinstance(body, dict):
            models = [m.get("name") for m in (body.get("models") or [])
                      if isinstance(m, dict) and m.get("name")]

        if not models:
            return ProviderStatus(
                False, "Ollama esta rodando, mas nenhum modelo foi baixado ainda.",
                models=())

        ver = (version.json() or {}).get("version", "?")
        return ProviderStatus(
            True, f"Ollama {ver} respondendo em {self.base_url}.", models=models)

    def _call(self, request):
        self._assert_loopback()
        model = (self.settings.model or "").strip()
        if not model:
            raise ProviderUnavailable("Nenhum modelo local selecionado.")

        payload = {
            "model": model,
            "messages": build_messages(request.context),
            "format": OUTPUT_SCHEMA,
            "stream": False,
            # Determinismo: o proprio guia do Ollama recomenda temperatura zero
            # com structured output.
            "options": {"temperature": 0, "num_predict": self.settings.max_output_tokens},
        }

        result = http.post_json(
            f"{self.base_url}/api/chat", payload,
            timeout=self.settings.timeout_s, retries=1, no_proxy=True)

        if result.error == "timeout":
            raise ProviderTimeout(
                f"O modelo {model} nao respondeu em {self.settings.timeout_s:.0f}s.")
        if result.error:
            raise ProviderUnavailable(
                f"Nao consegui falar com o Ollama: {result.error}.")
        if result.status == 404:
            raise ProviderUnavailable(
                f"O modelo '{model}' nao esta disponivel neste runtime.")
        if not result.ok:
            raise ProviderUnavailable(
                f"Ollama respondeu HTTP {result.status}.")

        body = result.json()
        if not isinstance(body, dict):
            raise ProviderMalformed("Resposta do Ollama nao era JSON.")

        content = ((body.get("message") or {}).get("content") or "").strip()
        if not content:
            raise ProviderMalformed("Resposta do Ollama sem conteudo.")

        import json
        try:
            parsed = json.loads(content)
        except ValueError:
            # O Ollama nao tem canal de recusa. Uma recusa chega como prosa que
            # falha o schema, e cai honestamente aqui -- nao tentamos adivinhar
            # por casamento de string.
            raise ProviderMalformed(
                "O modelo respondeu texto livre em vez do formato pedido.")

        return ProviderResponse(
            parsed=parsed,
            model=body.get("model") or model,
            tokens_in=body.get("prompt_eval_count"),
            tokens_out=body.get("eval_count"),
            latency_ms=result.elapsed_ms,
            attempts=result.attempts,
            stop_reason=body.get("done_reason"),
            http_status=result.status,
        )
