"""
O portao de saida.

A ADR-0011 poe a fronteira de redacao num **tipo**, verificado por MyPy strict.
Este repositorio nao tem MyPy, nem lint, nem CI -- entao o portao de build nao
existe, e alegar o contrario seria reivindicar um controle que nao temos. O
substituto e estrutural e em tempo de execucao:

1. `FindingContext` e nao-serializavel por construcao (`__reduce__` levanta).
2. `analyze()` e template method final na base; adaptadores implementam `_call`.
3. Teste de reflexao: nenhum provider define `analyze` no proprio `__dict__`.
4. Teste: `json.dumps(FindingContext(...))` levanta.

`redact()` aplica um **segundo allowlist independente**. Se o construtor de
contexto um dia vazar um campo, este aqui derruba. Cinto e suspensorio de
proposito: e o unico ponto por onde tudo passa.
"""

from dataclasses import dataclass

from app.application.ai import detectors
from app.application.ai.provider import EgressClass

# Unico tier do MVP (ADR-0011 §3).
TIER_NO_CODE = "no_code"
MAX_TIER_BY_EGRESS = {
    EgressClass.NONE: TIER_NO_CODE,
    EgressClass.LOCALHOST: TIER_NO_CODE,
    EgressClass.THIRD_PARTY: TIER_NO_CODE,
}

# Segundo allowlist. Nada fora desta lista sai, qualquer que seja o construtor.
ALLOWED_TOP_LEVEL = frozenset({
    "schema_version", "finding_class", "title", "description", "severity",
    "cve", "cwes", "package_name", "package_version", "fixed_version",
    "file_path_shape", "file_basename", "source_system", "source_rule_id",
    "assessment", "asset", "remediation", "decision_history", "open_debt",
    "evidence", "evidence_gaps", "knowledge_versions", "contains_synthetic",
})

DESCRIPTION_CAP_EXTERNAL = 600


class RedactionBlocked(Exception):
    """Segredo detectado num caminho de egresso externo.

    **Falha fechado, sempre.** Nunca enviar carga parcialmente higienizada a um
    fornecedor: a estrategia de reversao da ADR-0011 e o argumento inteiro --
    afrouxar depois e facil, e segredo enviado nao se recolhe.
    """


@dataclass(frozen=True)
class RedactedContext:
    """O unico tipo que um provider aceita."""

    payload: dict
    tier: str
    egress: EgressClass
    context_hash: str
    redactions: tuple
    evidence_ids: frozenset

    def __repr__(self):
        return (f"<RedactedContext egress={self.egress.value} tier={self.tier} "
                f"redactions={len(self.redactions)}>")


def effective_tier(configured, egress):
    """O tier efetivo e o **minimo** entre o configurado e o maximo do egresso."""
    ceiling = MAX_TIER_BY_EGRESS[egress]
    return ceiling if configured != ceiling else configured


def _walk_strings(node, path, on_string):
    """Percorre toda folha textual, aplicando `on_string(caminho, valor)`."""
    if isinstance(node, str):
        return on_string(path, node)
    if isinstance(node, dict):
        return {k: _walk_strings(v, f"{path}.{k}" if path else k, on_string)
                for k, v in node.items()}
    if isinstance(node, (list, tuple)):
        return [_walk_strings(v, f"{path}[{i}]", on_string)
                for i, v in enumerate(node)]
    return node


def redact(ctx, *, egress, tier=TIER_NO_CODE):
    """`FindingContext` -> `RedactedContext`. Levanta `RedactionBlocked` quando
    ha segredo e o egresso e externo."""
    from app.application.ai.context import FindingContext

    if not isinstance(ctx, FindingContext):
        raise TypeError("redact() recebe um FindingContext.")

    egress = EgressClass(egress)
    tier = effective_tier(tier, egress)

    payload = {k: v for k, v in ctx._payload().items() if k in ALLOWED_TOP_LEVEL}

    # Campos que so o egresso local pode carregar.
    if egress is EgressClass.THIRD_PARTY:
        payload["file_basename"] = None
        if payload.get("description"):
            desc = payload["description"]
            if len(desc) > DESCRIPTION_CAP_EXTERNAL:
                payload["description"] = desc[:DESCRIPTION_CAP_EXTERNAL] + " […truncado]"

    found = []

    def _on_string(path, value):
        cleaned, hits = detectors.redact_text(value)
        for name in hits:
            found.append({"field_path": path, "detector": name, "count": 1})
        return cleaned

    payload = _walk_strings(payload, "", _on_string)

    if found and egress is EgressClass.THIRD_PARTY:
        kinds = sorted({f["detector"] for f in found})
        raise RedactionBlocked(
            "Segredo detectado no contexto e o egresso e externo. A analise foi "
            f"bloqueada antes de qualquer envio. Detectores: {', '.join(kinds)}.")

    return RedactedContext(
        payload=payload,
        tier=tier,
        egress=egress,
        context_hash=ctx.hash(),
        redactions=tuple(found),
        evidence_ids=frozenset(ctx.evidence_ids),
    )


def preview(redacted):
    """Carga exata para a tela de pre-voo.

    Mostrar a carga de verdade, e nao uma descricao dela, e o unico jeito de um
    usuario atento verificar a promessa -- e torna um defeito de redacao visivel
    a um humano antes de virar incidente.
    """
    import json
    return json.dumps(redacted.payload, indent=2, ensure_ascii=False,
                      sort_keys=True, default=str)
