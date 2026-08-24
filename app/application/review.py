"""
Analyst Review — o loop humano.

Decisoes sao APPEND-ONLY (ADR-0001, CLAUDE.md 15). Revisar nao edita a decisao
antiga: cria uma nova que aponta para ela via `supersedes_id`. A anterior fica,
com a fotografia do que se sabia quando foi tomada.

Isso nao e purismo de modelagem. A tese do produto e que decisoes envelhecem;
um modelo que sobrescreve a decisao antiga apaga exatamente o dado que prova a
tese, e o apaga de forma irrecuperavel para tudo que ja foi coletado.

Toda revisao registra `classification`. Uma decisao de analista real e
`REAL_EXTERNAL_DATA`; uma decisao gerada pelo dataset de demonstracao e
`SYNTHETIC_DATA`. As duas nunca se confundem no relatorio.
"""

import json
from datetime import datetime, timezone

from sqlalchemy import desc, select

from app.application import knowledge
from app.domain.enums import ClosureReason
from app.domain.models import DEFAULT_ORG, Decision, DecisionDebt, Finding


def utcnow():
    return datetime.now(timezone.utc)


class ReviewError(ValueError):
    pass


def submit_review(session, finding_id, reason, rationale, analyst,
                  org_id=DEFAULT_ORG, classification="REAL_EXTERNAL_DATA",
                  resolves_debt_id=None):
    """Registra a decisao do analista.

    Exige justificativa: uma decisao sem razao registrada nao alimenta memoria
    organizacional nenhuma, e memoria organizacional e a coisa que o produto
    diz estar construindo.
    """
    finding = session.get(Finding, finding_id)
    if finding is None or finding.org_id != org_id:
        raise ReviewError("Achado nao encontrado.")

    try:
        reason_enum = ClosureReason(str(reason).strip().lower())
    except ValueError:
        raise ReviewError(
            f"Razao invalida: {reason!r}. Valores aceitos: "
            + ", ".join(r.value for r in ClosureReason))

    if not str(rationale or "").strip():
        raise ReviewError("A justificativa e obrigatoria.")

    previous = finding.current_decision

    # A fotografia e tirada AGORA, com a data de agora. E contra ela que uma
    # divida futura sera medida.
    snap = knowledge.kev().knowledge_as_of(finding.cve, utcnow()) if finding.cve else {}

    decision = Decision(
        org_id=org_id, reason=reason_enum.value,
        rationale=str(rationale).strip(), decided_at=utcnow(),
        decided_by=str(analyst or "analista").strip()[:120],
        classification=classification, source_system="analyst-review",
        knowledge_snapshot_json=json.dumps(snap, default=str),
        supersedes_id=previous.id if previous else None,
        is_review=previous is not None)
    # Anexar pela RELACAO. Com `session.add()` e a chave estrangeira solta, a
    # colecao `finding.decisions` fica desatualizada e a proxima revisao na
    # mesma sessao nao acha a decisao anterior -- perdendo a cadeia
    # `supersedes`, que e justamente a trilha de auditoria que o modelo
    # append-only existe para manter.
    finding.decisions.append(decision)
    session.flush()

    # O achado segue o veredito.
    if reason_enum == ClosureReason.FIXED:
        finding.status = "closed"
        finding.closed_at = decision.decided_at
    elif reason_enum.is_decision_to_not_act:
        finding.status = "closed"
        finding.closed_at = decision.decided_at
    else:
        finding.status = "open"

    # Fechar a divida que motivou a revisao, quando houver.
    if resolves_debt_id:
        debt = session.get(DecisionDebt, int(resolves_debt_id))
        if debt is not None and debt.org_id == org_id:
            debt.resolved = True
            debt.resolved_at = utcnow()
            debt.resolution_decision_id = decision.id
    else:
        for debt in session.scalars(select(DecisionDebt).where(
                DecisionDebt.finding_id == finding.id,
                DecisionDebt.resolved.is_(False))).all():
            debt.resolved = True
            debt.resolved_at = utcnow()
            debt.resolution_decision_id = decision.id

    session.flush()
    return decision


def decision_history(session, finding_id):
    """Historico completo, do mais recente ao mais antigo. Nada e apagado."""
    return session.scalars(
        select(Decision).where(Decision.finding_id == finding_id)
        .order_by(desc(Decision.decided_at), desc(Decision.id))).all()


def review_queue(session, org_id=DEFAULT_ORG, limit=100):
    """O que precisa de olho humano, na ordem em que importa.

    Divida de decisao primeiro: sao decisoes que a organizacao ja tomou e que o
    mundo pode ter invalidado -- valem mais que um achado novo que ninguem
    ainda olhou, porque alguem ja concluiu que estava tudo bem.
    """
    debts = session.scalars(
        select(DecisionDebt).where(DecisionDebt.org_id == org_id,
                                   DecisionDebt.resolved.is_(False))
        .order_by(desc(DecisionDebt.event_date)).limit(limit)).all()

    items = [{"kind": "decision_debt", "debt": d, "finding": d.finding,
              "priority": 0} for d in debts]

    seen = {d.finding_id for d in debts}
    undecided = session.scalars(
        select(Finding).where(Finding.org_id == org_id,
                              Finding.band.in_(("act_now", "act_soon")))
        .order_by(desc(Finding.ordering_score)).limit(limit)).all()
    for f in undecided:
        if f.id in seen or f.current_decision is not None:
            continue
        items.append({"kind": "undecided", "debt": None, "finding": f, "priority": 1})

    items.sort(key=lambda i: (i["priority"],
                              -(i["finding"].ordering_score or 0) if i["finding"] else 0))
    return items[:limit]


def stats(session, org_id=DEFAULT_ORG):
    decisions = session.scalars(
        select(Decision).where(Decision.org_id == org_id)).all()
    by_reason, by_class = {}, {}
    for d in decisions:
        by_reason[d.reason] = by_reason.get(d.reason, 0) + 1
        by_class[d.classification] = by_class.get(d.classification, 0) + 1
    reviews = sum(1 for d in decisions if d.is_review)
    return {"decisions": len(decisions), "reviews": reviews,
            "by_reason": by_reason, "by_classification": by_class}
