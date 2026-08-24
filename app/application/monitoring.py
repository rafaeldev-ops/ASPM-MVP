"""
Continuous Monitoring.

Para o MVP, "continuo" e re-importar e comparar snapshots -- nao streaming. O
que importa nao e a latencia, e detectar as mudancas que tornam uma decisao
antiga discutivel.

Detecta: achado novo, fechado, reaberto, severidade alterada, entrada no KEV,
mudanca de contexto do ativo.

**EPSS nao esta na lista, e a ausencia e o ponto.** EXP-001 mediu 71.885 CVEs
cruzando um limiar numa troca de versao de modelo contra 306 em dez dias de
mundo real. EXP-004 mediu, neste dataset, ~22.900 CVEs cruzando com um
deslocamento de 25% contra ~23 entradas de KEV por mes. Um evento de EPSS pode
ser registrado como sinal contextual; ele nunca e material e nunca acorda uma
decisao.
"""

from datetime import datetime, timezone

from sqlalchemy import desc, select

from app.application import knowledge
from app.domain.enums import ChangeKind
from app.domain.models import DEFAULT_ORG, Asset, ChangeEvent, Finding, ScanSnapshot


def utcnow():
    return datetime.now(timezone.utc)


def _record(session, kind, org_id, finding=None, asset=None, snapshot=None,
            summary="", old=None, new=None, source=None, occurred_at=None):
    ev = ChangeEvent(
        org_id=org_id, kind=kind.value,
        finding_id=finding.id if finding else None,
        asset_id=asset.id if asset else None,
        snapshot_id=snapshot.id if snapshot else None,
        occurred_at=occurred_at or utcnow(), detected_at=utcnow(),
        is_material=kind.is_material, summary=summary,
        old_value=str(old)[:200] if old is not None else None,
        new_value=str(new)[:200] if new is not None else None,
        source=source)
    session.add(ev)
    return ev


def detect_changes(session, snapshot, seen_ids, previous_state=None,
                   org_id=DEFAULT_ORG):
    """Compara o import atual com o estado anterior.

    `previous_state` e o dicionario capturado por `capture_state()` ANTES da
    importacao. Sem ele nao ha comparacao possivel -- e por isso a rotina de
    import chama a captura primeiro.
    """
    previous_state = previous_state or {}
    seen = set(seen_ids)
    counts = {k.value: 0 for k in ChangeKind}

    for fid, prev in previous_state.items():
        f = session.get(Finding, fid)
        if f is None:
            continue
        if fid not in seen and prev["status"] == "open":
            f.status = "closed"
            f.closed_at = f.closed_at or utcnow()
            _record(session, ChangeKind.FINDING_CLOSED, org_id, finding=f,
                    snapshot=snapshot,
                    summary="Achado ausente nesta importacao; marcado como fechado.")
            counts[ChangeKind.FINDING_CLOSED.value] += 1
        elif fid in seen:
            if prev["status"] == "closed":
                f.status = "reopened"
                _record(session, ChangeKind.FINDING_REOPENED, org_id, finding=f,
                        snapshot=snapshot, old="closed", new="reopened",
                        summary="Achado reapareceu depois de ter sido fechado.")
                counts[ChangeKind.FINDING_REOPENED.value] += 1
            if prev["severity"] != f.severity:
                _record(session, ChangeKind.SEVERITY_CHANGED, org_id, finding=f,
                        snapshot=snapshot, old=prev["severity"], new=f.severity,
                        summary=f"Severidade mudou de {prev['severity']} para {f.severity}.")
                counts[ChangeKind.SEVERITY_CHANGED.value] += 1

    for fid in seen:
        if fid not in previous_state:
            f = session.get(Finding, fid)
            if f:
                _record(session, ChangeKind.FINDING_NEW, org_id, finding=f,
                        snapshot=snapshot, summary="Achado visto pela primeira vez.")
                counts[ChangeKind.FINDING_NEW.value] += 1

    snapshot.findings_closed = counts[ChangeKind.FINDING_CLOSED.value]
    snapshot.findings_reopened = counts[ChangeKind.FINDING_REOPENED.value]
    session.flush()
    return counts


def capture_state(session, org_id=DEFAULT_ORG):
    """Fotografia do estado ANTES de importar. Chamar antes, sempre."""
    return {f.id: {"status": f.status, "severity": f.severity, "band": f.band}
            for f in session.scalars(
                select(Finding).where(Finding.org_id == org_id)).all()}


def detect_kev_changes(session, org_id=DEFAULT_ORG):
    """Registra entradas no KEV como eventos datados pela CISA.

    `occurred_at` e a data em que a CISA listou, nao a data em que percebemos.
    Isso e o que permite a divida de decisao comparar contra a data da decisao
    sem usar informacao do futuro.
    """
    kev = knowledge.kev()
    existing = {(e.finding_id, e.kind) for e in session.scalars(
        select(ChangeEvent).where(ChangeEvent.org_id == org_id,
                                  ChangeEvent.kind == ChangeKind.KEV_LISTED.value)).all()}
    n = 0
    for f in session.scalars(select(Finding).where(
            Finding.org_id == org_id, Finding.cve.isnot(None))).all():
        entry = kev.entry(f.cve)
        if not entry or (f.id, ChangeKind.KEV_LISTED.value) in existing:
            continue
        added = entry["date_added"]
        _record(session, ChangeKind.KEV_LISTED, org_id, finding=f,
                summary=(f"{f.cve} entrou no catalogo CISA KEV em {added}."
                         + (" Uso confirmado em ransomware."
                            if entry["known_ransomware"] else "")),
                new=str(added), source="CISA KEV",
                occurred_at=datetime.combine(added, datetime.min.time()) if added else None)
        n += 1
    session.flush()
    return {"kev_events": n}


def record_asset_change(session, asset, field, old, new, org_id=DEFAULT_ORG):
    """Mudanca de contexto do ativo. Materialmente relevante: um servico que
    passou de staging para producao muda a exposicao de tudo que roda nele."""
    _record(session, ChangeKind.ASSET_CONTEXT_CHANGED, org_id, asset=asset,
            old=old, new=new,
            summary=f"{field} do ativo mudou de {old} para {new}.")
    session.flush()


def timeline(session, org_id=DEFAULT_ORG, finding_id=None, asset_id=None, limit=100):
    q = select(ChangeEvent).where(ChangeEvent.org_id == org_id)
    if finding_id:
        q = q.where(ChangeEvent.finding_id == finding_id)
    if asset_id:
        q = q.where(ChangeEvent.asset_id == asset_id)
    return session.scalars(
        q.order_by(desc(ChangeEvent.occurred_at), desc(ChangeEvent.id)).limit(limit)).all()


def snapshots(session, org_id=DEFAULT_ORG, limit=20):
    return session.scalars(
        select(ScanSnapshot).where(ScanSnapshot.org_id == org_id)
        .order_by(desc(ScanSnapshot.taken_at)).limit(limit)).all()


def recent_material_changes(session, org_id=DEFAULT_ORG, limit=15):
    return session.scalars(
        select(ChangeEvent).where(ChangeEvent.org_id == org_id,
                                  ChangeEvent.is_material.is_(True))
        .order_by(desc(ChangeEvent.occurred_at)).limit(limit)).all()
