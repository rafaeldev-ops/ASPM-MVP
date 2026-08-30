"""
Os adaptadores.

Sao **tres**, e o teto e imposto por teste, nao por intencao (ADR-0018 §1). Um
quarto exige editar a ADR e o teste no mesmo commit -- que e exatamente o atrito
que a ADR-0015 protegia quando rejeitou a abstracao de seis providers.

A superficie comum e fina de proposito: transporte, retry, timeout, telemetria.
**Nenhuma camada finge que os providers sao equivalentes.** Cada adaptador
conhece as proprias esquisitices, e onde o comportamento difere ele difere de
forma visivel em vez de ser alisado num denominador comum falso.
"""

from app.application.ai.providers.null import NullProvider
from app.application.ai.providers.ollama import OllamaProvider
from app.application.ai.providers.openai import OpenAIProvider

REGISTRY = {
    NullProvider.name: NullProvider,
    OllamaProvider.name: OllamaProvider,
    OpenAIProvider.name: OpenAIProvider,
}

__all__ = ["REGISTRY", "NullProvider", "OllamaProvider", "OpenAIProvider"]
