"""
Camada de IA.

Era um modulo; virou pacote. O `__init__` reexporta tudo que o modulo antigo
exportava, entao `from app.application import ai` e `ai.provider_info()` seguem
funcionando sem que nenhum chamador precise mudar.

Tres coisas mudaram de forma deliberada:

**O global `_active` morreu.** Ele lia `SDIP_AI_PROVIDER` uma vez e memoizava
para sempre, o que tornava impossivel trocar de provider sem reiniciar. Agora a
reconstrucao acontece quando a impressao digital da configuracao muda -- uma
construcao por configuracao, nao por requisicao.

**`provider_info()` nunca sonda.** Ele esta no caminho quente (`/aspm` e
`/api/v1/overview`); se sondasse um Ollama morto com timeout, toda renderizacao
do painel pagaria a espera. Status vem de cache com validade curta, com bandeira
de `stale`, e sondagem fresca so pelo botao de testar conexao.

**Nome desconhecido cai para o null, mas isso fica registrado.** Antes era
silencioso; `requested` diz o que foi pedido.
"""

import time

from app.application.ai.contract import (  # noqa: F401  (compatibilidade)
    AI_OUTPUT_FIELDS, deterministic_summary, validate_ai_output,
)
from app.application.ai.provider import (  # noqa: F401
    AIProvider, AnalysisRequest, EgressClass, ProviderBusy, ProviderError,
    ProviderMalformed, ProviderRefusal, ProviderStatus, ProviderTimeout,
    ProviderUnavailable,
)
from app.application.ai.providers import REGISTRY, NullProvider  # noqa: F401

STATUS_TTL_S = 30.0

_cached = None            # (fingerprint, provider)
_status_cache = {}        # fingerprint -> (timestamp, ProviderStatus)
_last_requested = None


def registry():
    """Os providers disponiveis. **Exatamente tres** (ADR-0018 §1), e um teste
    afirma isso -- e o mecanismo que sustenta a entrada WON'T do backlog."""
    return dict(REGISTRY)


def get_provider(session=None, org_id=None, force=False):
    """Provider ativo, reconstruido quando a configuracao muda."""
    global _cached, _last_requested
    from app.application.ai.settings import load

    settings = load(session, org_id)
    requested = (settings.provider or "null").strip().lower()
    cls = REGISTRY.get(requested)
    _last_requested = requested
    if cls is None:
        cls = NullProvider

    fingerprint = settings.fingerprint()
    if not force and _cached is not None and _cached[0] == fingerprint:
        return _cached[1]

    provider = cls(settings)
    _cached = (fingerprint, provider)
    return provider


def provider_status(session=None, org_id=None, probe=False):
    """Status com cache. `probe=True` forca sondagem fresca."""
    from app.application.ai.settings import load

    provider = get_provider(session, org_id)
    fingerprint = load(session, org_id).fingerprint()
    now = time.monotonic()

    cached = _status_cache.get(fingerprint)
    if not probe and cached and (now - cached[0]) < STATUS_TTL_S:
        return cached[1], True

    try:
        status = provider.status()
    except Exception as exc:                      # sondagem nunca derruba a tela
        status = ProviderStatus(False, f"Falha ao sondar: {exc}")
    _status_cache[fingerprint] = (now, status)
    return status, False


def provider_info(session=None, org_id=None, probe=False):
    """Resumo para tela e API. Sem segredo, sem URL com credencial."""
    from app.application.ai.settings import load

    provider = get_provider(session, org_id)
    settings = load(session, org_id)
    status, from_cache = provider_status(session, org_id, probe=probe)

    key_present = False
    if provider.requires_api_key:
        from app.infrastructure import credentials
        secret, _ = credentials.resolve("openai")
        key_present = bool(secret)

    return {
        "provider": provider.name,
        "requested": _last_requested or provider.name,
        "model": settings.model or None,
        "egress": provider.egress.value,
        "egress_label": provider.egress.label,
        # Derivado de `egress`. Mantido para o contrato existente e para
        # `tests/test_api.py:143` continuarem valendo.
        "external": provider.is_external,
        "available": status.available,
        "detail": status.detail,
        "stale": bool(from_cache),
        "key_present": key_present,
    }


def reset():
    """Limpa os caches. Para testes; nao usar em producao."""
    global _cached, _last_requested
    _cached = None
    _last_requested = None
    _status_cache.clear()
