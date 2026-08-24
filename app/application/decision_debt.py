"""
Decision Debt — o diferencial do produto, dentro do MVP.

Porta a logica ja validada de `evaluation/ring0/decision_debt.py` para o
caminho da aplicacao. Nao importa daquele modulo: `evaluation/` e codigo de
avaliacao, com seu proprio ciclo de vida, e a mesma regra que separa
`phase0/` de `app/` vale aqui.

A regra temporal e a mesma, e continua estrutural:

    O estado externo so e consultado com uma data, e a data de entrada no KEV
    nao e revelada se for posterior a data da decisao.

As duas pilhas nunca se somam:

    decision_debt   o CVE entrou no KEV DEPOIS do fechamento -> o mundo mudou
    closed_despite  o CVE JA estava no KEV no dia -> outra historia, e pior

Fundir as duas inflaria o numero principal com achados que contam uma historia
diferente, e quem recebe o relatorio notaria.
"""

import json
from datetime import date, datetime, timezone

from sqlalchemy import select

from app.application import knowledge
from app.domain.enums import ClosureReason
from app.domain.models import DEFAULT_ORG, Decision, DecisionDebt, Finding

POTENTIALLY_OBSOLETE = "POTENTIALLY_OBSOLETE"
INVALID_AT_DECISION_TIME = "INVALID_AT_DECISION_TIME"
STILL_VALID = "STILL_VALID"
UNKNOWN_OUTSIDE_WINDOW = "UNKNOWN_OUTSIDE_WINDOW"
NOT_APPLICABLE = "NOT_APPLICABLE"

TRIGGER_KEV = "KEV_LISTED"


def as_date(d):
    if isinstance(d, datetime):
        return d.date()
    if isinstance(d, date):
        return d
    return None


def evaluate_decision(decision, finding, kev, as_of_now=None):
    """Uma decisao -> uma linha da matriz temporal.

    Explica o que mudou, quando, com que evidencia, e por que a decisao antiga
    precisa de revisao (briefing 11).
    """
    now = as_date(as_of_now) or datetime.now(timezone.utc).date()
    reason = ClosureReason(decision.reason)
    d_at = as_date(decision.decided_at)

    row = {
        "decision_id": decision.id, "finding_id": finding.id,
        "cve": finding.cve, "decision_date": d_at.isoformat() if d_at else None,
        "decision_reason": reason.value, "decision_reason_label": reason.label,
        "decision_classification": decision.classification,
        "knowledge_as_of_decision": None, "trigger": None,
        "event_date": None, "current_state": None,
        "validity": None, "re_litigation_candidate": False,
        "explanation": None, "days_after_decision": None, "evidence": [],
    }

    # `fixed` nao tem divida: nao ha decisao de nao agir a re-litigar.
    # `unknown` tambem nao: nao sabemos o que foi decidido, e tratar ignorancia
    # como decisao inflaria o numero.
    if not reason.is_decision_to_not_act:
        row["validity"] = NOT_APPLICABLE
        row["explanation"] = (
            f"Fechado como '{reason.label}': nao e uma decisao de nao agir, "
            "entao nao ha divida de decisao a computar.")
        return row

    if not finding.cve:
        row["validity"] = UNKNOWN_OUTSIDE_WINDOW
        row["explanation"] = ("O achado nao tem CVE. O gatilho de KEV e indexado por "
                              "CVE, entao nao ha como avaliar esta decisao por ele.")
        return row

    # A unica porta para o estado externo, e ela e cega ao futuro.
    k = kev.knowledge_as_of(finding.cve, d_at)
    row["knowledge_as_of_decision"] = k
    row["current_state"] = kev.state_as_of(finding.cve, now)
    added = kev.date_added(finding.cve)

    if k["kev_state"] == "IN_KEV":
        row["validity"] = INVALID_AT_DECISION_TIME
        row["trigger"] = TRIGGER_KEV
        row["event_date"] = k["kev_date_added_if_known"]
        row["explanation"] = (
            f"O CVE ja constava no CISA KEV em {k['kev_date_added_if_known']}, "
            f"antes do fechamento em {d_at}. Isto NAO e divida de decisao: e um "
            f"achado fechado enquanto ja era sabidamente explorado.")
        row["evidence"] = [_kev_evidence(kev, finding.cve)]
        return row

    if added and d_at and added > d_at:
        row["validity"] = POTENTIALLY_OBSOLETE
        row["trigger"] = TRIGGER_KEV
        row["event_date"] = added.isoformat()
        row["days_after_decision"] = (added - d_at).days
        row["re_litigation_candidate"] = True
        entry = kev.entry(finding.cve)
        row["explanation"] = (
            f"Quando esta decisao foi tomada em {d_at}, o CVE nao constava no "
            f"CISA KEV. Ele entrou em {added} — {(added - d_at).days} dias depois. "
            f"A razao do fechamento ('{reason.label}') foi avaliada sem essa "
            f"informacao."
            + (" Ha uso confirmado em campanha de ransomware."
               if entry and entry["known_ransomware"] else ""))
        row["evidence"] = [_kev_evidence(kev, finding.cve)]
        return row

    if row["current_state"] == "UNKNOWN_OUTSIDE_WINDOW":
        row["validity"] = UNKNOWN_OUTSIDE_WINDOW
        row["explanation"] = ("O CVE nao aparece na janela deste catalogo. Nao da para "
                              "afirmar que nunca entrou no KEV.")
        return row

    row["validity"] = STILL_VALID
    row["explanation"] = "Nenhuma mudanca material desde o fechamento."
    return row


def _kev_evidence(kev, cve):
    e = kev.entry(cve) or {}
    return {
        "evidence_type": "kev_listing", "source": "CISA KEV",
        "source_authority": "authoritative", "source_id": cve,
        "date_added": str(e.get("date_added")),
        "known_ransomware": e.get("known_ransomware"),
        "vendor": e.get("vendor"), "product": e.get("product"),
        "classification": "REAL_EXTERNAL_DATA",
        "catalog_version": kev.version,
    }


def scan(session, org_id=DEFAULT_ORG, as_of_now=None):
    """Varre as decisoes vigentes e materializa a divida encontrada."""
    kev = knowledge.kev()
    findings = session.scalars(select(Finding).where(Finding.org_id == org_id)).all()

    stats = {"evaluated": 0, "decision_debt": 0, "closed_despite": 0,
             "still_valid": 0, "unknown": 0, "not_applicable": 0, "created": 0}
    rows = []

    for f in findings:
        decision = f.current_decision
        if decision is None:
            continue
        stats["evaluated"] += 1
        row = evaluate_decision(decision, f, kev, as_of_now)
        rows.append(row)

        if row["validity"] == POTENTIALLY_OBSOLETE:
            stats["decision_debt"] += 1
        elif row["validity"] == INVALID_AT_DECISION_TIME:
            stats["closed_despite"] += 1
        elif row["validity"] == STILL_VALID:
            stats["still_valid"] += 1
        elif row["validity"] == NOT_APPLICABLE:
            stats["not_applicable"] += 1
        else:
            stats["unknown"] += 1

        if not row["re_litigation_candidate"]:
            continue

        existing = session.scalars(select(DecisionDebt).where(
            DecisionDebt.finding_id == f.id,
            DecisionDebt.decision_id == decision.id,
            DecisionDebt.trigger == row["trigger"])).first()
        if existing is None:
            existing = DecisionDebt(org_id=org_id, finding_id=f.id,
                                    decision_id=decision.id, trigger=row["trigger"],
                                    validity=row["validity"])
            session.add(existing)
            stats["created"] += 1
        existing.validity = row["validity"]
        existing.explanation = row["explanation"]
        existing.days_after_decision = row["days_after_decision"]
        existing.event_date = (datetime.fromisoformat(row["event_date"])
                               if row["event_date"] else None)
        existing.evidence_ids_json = json.dumps([e.id for e in f.evidence])

    session.flush()
    stats["rows"] = rows
    return stats


def open_debt(session, org_id=DEFAULT_ORG, limit=200):
    return session.scalars(
        select(DecisionDebt).where(DecisionDebt.org_id == org_id,
                                   DecisionDebt.resolved.is_(False))
        .order_by(DecisionDebt.event_date.desc()).limit(limit)).all()


def for_finding(session, finding):
    return session.scalars(select(DecisionDebt).where(
        DecisionDebt.finding_id == finding.id)).all()
