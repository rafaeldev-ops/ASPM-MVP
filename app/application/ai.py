"""
Abstracao de provider de IA.

Duas regras do briefing (secoes 19, 20 e 21) que este modulo torna estruturais:

1. **A IA nunca decide.** Ela nao calcula banda, nao diz se um CVE esta na KEV,
   nao resolve estado e nao faz logica temporal. Tudo isso e deterministico e
   ja existe. A IA sintetiza explicacao a partir de evidencia que ja foi
   coletada e ja foi decidida.

2. **O MVP funciona sem IA.** O provider padrao e o `NullProvider`, que nao faz
   chamada nenhuma e devolve uma sintese deterministica montada a partir dos
   mesmos campos. Nada na aplicacao quebra sem chave de API, e nenhum dado de
   achado sai da maquina a menos que alguem configure um provider externo e
   ligue explicitamente.

Saida sempre validada contra o contrato. Resposta livre nunca vira autoridade.
"""

import os

# O contrato de saida. Campos extras sao descartados, campos faltantes viram
# vazio -- o consumidor nunca recebe uma forma diferente desta.
AI_OUTPUT_FIELDS = ("summary", "risk_explanation", "recommended_action",
                    "evidence_ids", "uncertainty_reasons")


def validate_ai_output(raw):
    """Normaliza e valida. Nunca levanta: IA degradada nao derruba a tela."""
    if not isinstance(raw, dict):
        return {"summary": "", "risk_explanation": "", "recommended_action": "",
                "evidence_ids": [], "uncertainty_reasons": ["saida do modelo invalida"]}
    out = {}
    for f in AI_OUTPUT_FIELDS:
        v = raw.get(f)
        if f in ("evidence_ids", "uncertainty_reasons"):
            out[f] = [str(x) for x in v] if isinstance(v, (list, tuple)) else []
        else:
            out[f] = str(v) if v is not None else ""
    return out


class AIProvider:
    name = "base"
    is_external = False

    def summarize_risk(self, context):
        raise NotImplementedError

    @property
    def available(self):
        return True


class NullProvider(AIProvider):
    """Sem modelo. Sintese deterministica a partir dos campos ja calculados.

    Nao e um placeholder: e a configuracao padrao e a que preserva a promessa de
    que nada sai da maquina. O texto e montado das mesmas razoes que o motor
    deterministico produziu, entao a tela e util sem nenhuma API externa.
    """

    name = "null"
    is_external = False

    def summarize_risk(self, context):
        a = context.get("assessment") or {}
        reasons = a.get("reasons") or []
        asset = context.get("asset_name") or "ativo nao identificado"
        title = context.get("title") or "achado"
        band_label = a.get("band_label", "sem banda")

        summary = f"{title} em {asset}. Classificacao: {band_label}."
        explanation = ("Motivos: " + "; ".join(reasons) + ".") if reasons else (
            "Nao ha motivos registrados: o motor nao encontrou sinal suficiente.")

        rem = context.get("remediation") or {}
        action = rem.get("action") or "Sem orientacao de correcao disponivel."
        if rem.get("confidence"):
            action += f" (confianca: {rem['confidence']})"

        unc = list(a.get("ineligibility_reasons") or [])
        if a.get("decision_points", {}).get("applicability") == "unknown":
            unc.append("aplicabilidade nao determinada")
        if a.get("decision_points", {}).get("exposure") == "unknown":
            unc.append("exposicao do ativo nao mapeada")

        return validate_ai_output({
            "summary": summary,
            "risk_explanation": explanation,
            "recommended_action": action,
            "evidence_ids": [str(e) for e in (context.get("evidence_ids") or [])],
            "uncertainty_reasons": unc,
        })


_PROVIDERS = {"null": NullProvider}
_active = None


def get_provider():
    """Provider ativo. `SDIP_AI_PROVIDER` escolhe; o padrao e nenhum.

    Um nome desconhecido cai para o NullProvider em vez de quebrar -- degradar
    para deterministico e sempre preferivel a derrubar a aplicacao.
    """
    global _active
    if _active is None:
        name = (os.environ.get("SDIP_AI_PROVIDER") or "null").strip().lower()
        _active = _PROVIDERS.get(name, NullProvider)()
    return _active


def provider_info():
    p = get_provider()
    return {"provider": p.name, "external": p.is_external, "available": p.available}
