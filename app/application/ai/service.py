"""
Orquestracao da analise. Unica porta que as rotas podem chamar.

    Finding -> build_context -> redact -> provider.analyze -> validate -> registro

Toda saida, inclusive falha, vira uma linha em `ai_analyses`. **Analise que
falhou tambem e gravada**: um provider que recusa 40% de um corpus de seguranca
precisa ser visivel, e a ADR-0015 §2 diz que taxa de recusa pode ser o criterio
que decide o fornecedor. Registrar so sucesso destroi exatamente essa metrica.

A banda deterministica, o score e a versao do modelo de risco **nunca sao
alterados** por nenhum outcome -- nem pelo sucesso. Um teste afirma isso para
cada um dos nove resultados possiveis.
"""

import json
from datetime import datetime, timezone

from sqlalchemy import desc, select

from app.application.ai import contract, prompt, redaction
from app.application.ai.context import CONTEXT_SCHEMA_VERSION, build_context
from app.application.ai.provider import (
    AnalysisRequest, EgressClass, ProviderError,
)


def utcnow():
    return datetime.now(timezone.utc)


class EgressNotConfirmed(Exception):
    """A confirmacao de egresso nao bate com a configuracao atual.

    Existe para uma tela de pre-voo aberta antes de o usuario trocar de provider
    nao virar um envio para o provider errado.
    """


def analyze_finding(session, finding, *, confirmed_egress=None, actor=None):
    """Roda a analise e grava o registro. Devolve o `AIAnalysis` persistido."""
    from app.application.ai import get_provider
    from app.application.ai.settings import load as load_settings
    from app.domain.models import AIAnalysis

    settings = load_settings(session, finding.org_id)
    provider = get_provider(session, org_id=finding.org_id)

    if confirmed_egress is not None and str(confirmed_egress) != provider.egress.value:
        raise EgressNotConfirmed(
            f"A confirmacao foi para egresso '{confirmed_egress}', mas a "
            f"configuracao atual e '{provider.egress.value}'. Revise antes de "
            f"executar.")

    ctx = build_context(session, finding)
    started = utcnow()

    record = AIAnalysis(
        org_id=finding.org_id,
        finding_id=finding.id,
        created_at=started,
        outcome=contract.MALFORMED,
        provider=provider.name,
        model=(settings.model or None),
        egress=provider.egress.value,
        redaction_tier=redaction.effective_tier(settings.tier, provider.egress),
        key_source=getattr(provider, "key_source", None),
        prompt_version=prompt.PROMPT_VERSION,
        prompt_hash=prompt.prompt_hash(),
        context_schema_version=CONTEXT_SCHEMA_VERSION,
        context_hash=ctx.hash(),
        analysis_version=(f"{prompt.PROMPT_VERSION}+{CONTEXT_SCHEMA_VERSION}"
                          f"+{(finding.risk_model_version or 'sem-modelo')}"),
        # Gravados para provar que nao mudaram.
        deterministic_band=finding.band,
        risk_model_version=finding.risk_model_version,
        contains_synthetic=ctx.contains_synthetic,
        evidence_gaps_json=json.dumps(list(ctx.evidence_gaps), ensure_ascii=False),
        evidence_dropped_json=json.dumps(list(ctx.evidence_dropped), ensure_ascii=False),
        attempts=1,
    )

    analysis = None
    redacted = None

    try:
        redacted = redaction.redact(ctx, egress=provider.egress, tier=settings.tier)
        record.redaction_tier = redacted.tier
        record.redactions_json = json.dumps(list(redacted.redactions),
                                            ensure_ascii=False)

        response = provider.analyze(AnalysisRequest(
            redacted, prompt.OUTPUT_SCHEMA, settings))

        record.model = response.model or record.model
        record.tokens_in = response.tokens_in
        record.tokens_out = response.tokens_out
        record.latency_ms = response.latency_ms
        record.attempts = response.attempts
        record.estimated_cost_usd = _cost(settings, response)

        analysis = contract.validate(response.parsed, redacted)
        record.outcome = analysis.outcome
        record.summary = analysis.summary
        record.risk_explanation = analysis.risk_explanation
        record.recommended_action = analysis.recommended_action
        record.suggested_reason = analysis.recommended_reason or None
        record.evidence_ids_json = json.dumps(analysis.evidence_ids)
        record.contradicting_evidence_ids_json = json.dumps(
            analysis.contradicting_evidence_ids)
        record.uncertainty_reasons_json = json.dumps(
            analysis.uncertainty_reasons, ensure_ascii=False)
        record.error_detail = analysis.error_detail or None

    except redaction.RedactionBlocked as exc:
        record.outcome = contract.BLOCKED_REDACTION
        record.error_detail = str(exc)[:300]
        record.redactions_json = json.dumps(
            [{"field_path": "?", "detector": "bloqueado", "count": 1}])
    except ProviderError as exc:
        record.outcome = exc.outcome
        record.error_detail = str(exc)[:300]
    except Exception as exc:                       # nunca derruba a tela
        record.outcome = contract.MALFORMED
        record.error_detail = f"{type(exc).__name__}: {exc}"[:300]

    # Confianca e deterministica: calculada aqui, nunca emitida pelo modelo.
    score, inputs = contract.confidence_for(ctx, analysis)
    record.confidence = score
    record.confidence_model_version = contract.CONFIDENCE_MODEL_VERSION
    if not record.latency_ms:
        record.latency_ms = int((utcnow() - started).total_seconds() * 1000)

    session.add(record)
    session.flush()
    record._confidence_inputs = inputs
    return record


def _cost(settings, response):
    """Custo estimado. Preco vem da configuracao, nunca do codigo."""
    if not (settings.cost_per_1k_in or settings.cost_per_1k_out):
        return None
    tin = (response.tokens_in or 0) / 1000.0
    tout = (response.tokens_out or 0) / 1000.0
    return round(tin * settings.cost_per_1k_in + tout * settings.cost_per_1k_out, 6)


def latest_for(session, finding_id):
    from app.domain.models import AIAnalysis
    return session.scalars(
        select(AIAnalysis).where(AIAnalysis.finding_id == finding_id)
        .order_by(desc(AIAnalysis.created_at), desc(AIAnalysis.id)).limit(1)).first()


def history_for(session, finding_id, limit=10):
    from app.domain.models import AIAnalysis
    return session.scalars(
        select(AIAnalysis).where(AIAnalysis.finding_id == finding_id)
        .order_by(desc(AIAnalysis.created_at), desc(AIAnalysis.id))
        .limit(limit)).all()


def rollup(session, org_id=None, days=30):
    """Outcomes e latencia por provider.

    E a exigencia da ADR-0015 §2 -- "taxa de recusa no nosso corpus pode ser o
    criterio que decide o fornecedor" -- na escala de uma pessoa. SQL simples,
    sem tabela nova.
    """
    from datetime import timedelta

    from sqlalchemy import func

    from app.domain.models import DEFAULT_ORG, AIAnalysis
    org_id = org_id or DEFAULT_ORG
    since = utcnow() - timedelta(days=days)

    rows = session.execute(
        select(AIAnalysis.provider, AIAnalysis.outcome,
               func.count(AIAnalysis.id), func.avg(AIAnalysis.latency_ms))
        .where(AIAnalysis.org_id == org_id, AIAnalysis.created_at >= since)
        .group_by(AIAnalysis.provider, AIAnalysis.outcome)).all()

    out = {}
    for provider, outcome, count, avg_ms in rows:
        bucket = out.setdefault(provider, {"total": 0, "outcomes": {}, "avg_ms": 0})
        bucket["outcomes"][outcome] = count
        bucket["total"] += count
        if avg_ms:
            bucket["avg_ms"] = int(avg_ms)
    return out
