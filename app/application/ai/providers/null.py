"""
Sem modelo. Sintese deterministica.

Nao e placeholder: e o padrao, e e o que preserva a promessa de que nada sai da
maquina. Tambem e o caminho que a pagina de achado usa em toda renderizacao, e o
fallback de qualquer analise que falhe -- por isso **nao faz I/O nenhum**, e um
teste monkeypatcha `urlopen` para levantar e confirma que a pagina ainda abre.
"""

from app.application.ai.provider import (
    AIProvider, EgressClass, ProviderResponse, ProviderStatus,
)


class NullProvider(AIProvider):
    name = "null"
    egress = EgressClass.NONE
    requires_api_key = False
    supports_structured_output = False

    def status(self, timeout=None):
        return ProviderStatus(
            True, "Sintese deterministica. Nenhuma chamada, nenhum modelo.")

    def _call(self, request):
        """Devolve a sintese deterministica na forma do contrato novo.

        Nao ha modelo, entao nao ha o que citar alem do que ja foi calculado --
        `evidence_ids` vem do que o contexto entregou, o que mantem a validacao
        de fundamentacao valida tambem por aqui.
        """
        payload = request.context.payload
        a = payload.get("assessment") or {}
        reasons = a.get("reasons") or []
        asset = (payload.get("asset") or {}).get("name") or "ativo nao identificado"
        rem = payload.get("remediation") or {}

        parsed = {
            "summary": f"{payload.get('title')} em {asset}. "
                       f"Classificacao: {a.get('band_label', 'sem banda')}.",
            "risk_explanation": ("Motivos: " + "; ".join(reasons) + ".") if reasons
                                else "Sem motivos registrados pelo motor deterministico.",
            "recommended_action": rem.get("action")
                                  or "Sem orientacao de correcao disponivel.",
            "recommended_reason": "",
            "evidence_ids": sorted(request.context.evidence_ids),
            "contradicting_evidence_ids": [],
            "uncertainty_reasons": list(payload.get("evidence_gaps") or []),
        }
        return ProviderResponse(parsed=parsed, model="deterministico",
                                latency_ms=0, attempts=1)
