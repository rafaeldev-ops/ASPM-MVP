"""
Adaptador OpenAI — o unico caminho de egresso a terceiros.

Adaptador HTTP fino, sem SDK. O `openai` traria `httpx`, `pydantic`, `anyio`,
`distro`, `jiter` e mais, para um POST -- e um segundo `pydantic` disputando pino
com o do FastAPI. A ADR-0015 §1 define o trabalho do adaptador como transporte,
retry, timeout e telemetria, e e isso que ha aqui.

Dois cuidados que a ADR-0015 §6 nomeia por escrito e que uma implementacao
distraida erra:

  - **Checar `finish_reason` e o tamanho do array antes de indexar `choices[0]`.**
    Qualquer caminho que faca `choices[0]` sem olhar quebra, e quebra justamente
    numa recusa -- que num corpus de descricao de vulnerabilidade e evento
    recorrente, nao caso de borda.
  - **Recusa e HTTP 200.** Nao e erro de transporte; e um resultado a classificar.
"""

import json

from app.application.ai.prompt import OUTPUT_SCHEMA, SCHEMA_NAME, build_messages
from app.application.ai.provider import (
    AIProvider, EgressClass, ProviderMalformed, ProviderRefusal,
    ProviderResponse, ProviderStatus, ProviderTimeout, ProviderUnavailable,
)
from app.infrastructure import credentials, http

DEFAULT_BASE_URL = "https://api.openai.com/v1"
KEY_NAME = "openai"


class OpenAIProvider(AIProvider):
    name = "openai"
    egress = EgressClass.THIRD_PARTY
    requires_api_key = True
    supports_structured_output = True

    @property
    def base_url(self):
        return (self.settings.base_url or DEFAULT_BASE_URL).rstrip("/")

    def _key(self):
        secret, source = credentials.resolve(KEY_NAME)
        if not secret:
            raise ProviderUnavailable(
                "Nenhuma chave de API configurada para a OpenAI.")
        return secret, source

    @property
    def key_source(self):
        _, source = credentials.resolve(KEY_NAME)
        return source

    def status(self, timeout=None):
        """Sondagem sem enviar dado de achado.

        Verifica apenas se ha chave e se o modelo esta nomeado. Nao lista modelos
        pela rede: seria uma chamada externa so para desenhar um dropdown, e a
        promessa deste produto e que nada sai sem intencao explicita.
        """
        secret, source = credentials.resolve(KEY_NAME)
        if not secret:
            store = credentials.get_store()
            return ProviderStatus(
                False,
                "Nenhuma chave configurada. " + store.describe())
        if not (self.settings.model or "").strip():
            return ProviderStatus(False, "Nenhum modelo selecionado.")
        return ProviderStatus(
            True,
            f"Chave presente (origem: {source}). O contexto do achado sai desta "
            f"maquina quando voce executar a analise.",
            models=())

    def _call(self, request):
        secret, _ = self._key()
        model = (self.settings.model or "").strip()
        if not model:
            raise ProviderUnavailable("Nenhum modelo selecionado.")

        payload = {
            "model": model,
            "messages": build_messages(request.context),
            "temperature": 0,
            "max_tokens": self.settings.max_output_tokens,
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": SCHEMA_NAME, "strict": True,
                                "schema": OUTPUT_SCHEMA},
            },
        }

        result = http.post_json(
            f"{self.base_url}/chat/completions", payload,
            headers={"Authorization": f"Bearer {secret}"},
            timeout=self.settings.timeout_s, retries=2)

        if result.error == "timeout":
            raise ProviderTimeout(
                f"O provider nao respondeu em {self.settings.timeout_s:.0f}s.")
        if result.error:
            raise ProviderUnavailable(f"Falha de conexao: {result.error}.")
        if result.status in (401, 403):
            raise ProviderUnavailable("Chave de API recusada pelo provider.")
        if result.status == 404:
            raise ProviderUnavailable(f"O modelo '{model}' nao existe ou nao esta "
                                      f"disponivel para esta chave.")
        if result.status == 429:
            raise ProviderUnavailable("Limite de uso atingido no provider.")
        if not result.ok:
            raise ProviderUnavailable(f"O provider respondeu HTTP {result.status}.")

        body = result.json()
        if not isinstance(body, dict):
            raise ProviderMalformed("Resposta do provider nao era JSON.")

        choices = body.get("choices")
        # Antes de indexar. E o bug que a ADR-0015 §6 nomeia.
        if not isinstance(choices, list) or not choices:
            raise ProviderMalformed("Resposta sem escolhas.")

        choice = choices[0] or {}
        message = choice.get("message") or {}
        finish = choice.get("finish_reason")

        if message.get("refusal"):
            raise ProviderRefusal("O modelo recusou analisar este conteudo.")
        if finish == "content_filter":
            raise ProviderRefusal("O filtro de conteudo do provider bloqueou a resposta.")
        if finish == "length":
            raise ProviderMalformed("A resposta foi cortada por limite de tamanho.")

        content = (message.get("content") or "").strip()
        if not content:
            raise ProviderMalformed("Resposta sem conteudo.")

        try:
            parsed = json.loads(content)
        except ValueError:
            raise ProviderMalformed("Conteudo da resposta nao era JSON valido.")

        usage = body.get("usage") or {}
        return ProviderResponse(
            parsed=parsed,
            model=body.get("model") or model,
            tokens_in=usage.get("prompt_tokens"),
            tokens_out=usage.get("completion_tokens"),
            latency_ms=result.elapsed_ms,
            attempts=result.attempts,
            stop_reason=finish,
            http_status=result.status,
        )
