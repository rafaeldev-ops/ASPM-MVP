"""
Interface do MVP ASPM: telas HTML e API JSON versionada.

As telas ficam sob `/aspm`, a API sob `/api/v1`. O instrumento de backtest
legado continua em `/` -- nao foi tocado.

A API existe para o MVP ser verificavel sem clicar: todo numero que aparece
numa tela pode ser conferido num endpoint.
"""

import json
import os

from fastapi import APIRouter, Form, HTTPException, Request, UploadFile
from fastapi import File as FileParam
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, func, select

from app.application import (
    ai, decision_debt, demo, ingestion, knowledge, monitoring, pipeline,
    prioritization, remediation, review,
)
from app.db import SessionLocal
from app.domain.enums import Band, ClosureReason
from app.domain.models import (
    DEFAULT_ORG, Asset, ChangeEvent, Decision, DecisionDebt, Finding, Remediation,
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

web = APIRouter(prefix="/aspm", tags=["aspm-web"])
api = APIRouter(prefix="/api/v1", tags=["aspm-api"])

MAX_UPLOAD_MB = 25
BAND_ORDER = [b.value for b in Band]


# --------------------------------------------------------------------------
# Consultas compartilhadas
# --------------------------------------------------------------------------

def overview_data(session, org_id=DEFAULT_ORG):
    total_assets = session.scalar(
        select(func.count(Asset.id)).where(Asset.org_id == org_id)) or 0
    total_findings = session.scalar(
        select(func.count(Finding.id)).where(Finding.org_id == org_id)) or 0

    bands = dict(session.execute(
        select(Finding.band, func.count(Finding.id))
        .where(Finding.org_id == org_id).group_by(Finding.band)).all())
    severities = dict(session.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.org_id == org_id).group_by(Finding.severity)).all())
    statuses = dict(session.execute(
        select(Finding.status, func.count(Finding.id))
        .where(Finding.org_id == org_id).group_by(Finding.status)).all())

    open_debt = session.scalar(
        select(func.count(DecisionDebt.id)).where(
            DecisionDebt.org_id == org_id, DecisionDebt.resolved.is_(False))) or 0
    resolved_debt = session.scalar(
        select(func.count(DecisionDebt.id)).where(
            DecisionDebt.org_id == org_id, DecisionDebt.resolved.is_(True))) or 0

    kev_findings = session.scalar(
        select(func.count(Finding.id)).where(
            Finding.org_id == org_id,
            Finding.assessment_json.like('%"kev_listed"%'))) or 0

    crit_assets = session.scalar(
        select(func.count(Asset.id)).where(
            Asset.org_id == org_id, Asset.criticality == "critical")) or 0
    unresolved_owner = session.scalar(
        select(func.count(Asset.id)).where(
            Asset.org_id == org_id, Asset.criticality.is_(None))) or 0

    return {
        "assets": total_assets, "findings": total_findings,
        "bands": {b: bands.get(b, 0) for b in BAND_ORDER},
        "severities": severities, "statuses": statuses,
        "open_debt": open_debt, "resolved_debt": resolved_debt,
        "kev_findings": kev_findings,
        "critical_assets": crit_assets,
        "assets_without_criticality": unresolved_owner,
        "recent_changes": monitoring.recent_material_changes(session, org_id, 12),
        "snapshots": monitoring.snapshots(session, org_id, 5),
        "review_stats": review.stats(session, org_id),
        "knowledge": knowledge.versions(),
        "ai": ai.provider_info(),
    }


def _finding_view(session, f):
    """Tudo que a tela de detalhe precisa, num objeto so."""
    rem = remediation.for_finding(session, f)
    debts = decision_debt.for_finding(session, f)
    from app.application import correlation
    return {
        "finding": f,
        "asset": f.asset,
        "explain": prioritization.explain(f),
        "evidence": sorted(f.evidence, key=lambda e: e.evidence_type),
        "remediation": rem,
        "decisions": review.decision_history(session, f.id),
        "current_decision": f.current_decision,
        "debts": debts,
        "related": correlation.related_findings(session, f),
        "timeline": monitoring.timeline(session, f.org_id, finding_id=f.id, limit=40),
    }


# --------------------------------------------------------------------------
# Telas
# --------------------------------------------------------------------------

@web.get("", response_class=HTMLResponse)
@web.get("/", response_class=HTMLResponse)
def overview(request: Request):
    with SessionLocal() as s:
        data = overview_data(s)
    return templates.TemplateResponse(request, "aspm/overview.html", {"d": data})


@web.get("/assets", response_class=HTMLResponse)
def assets_list(request: Request, criticality: str = "", environment: str = ""):
    with SessionLocal() as s:
        q = select(Asset).where(Asset.org_id == DEFAULT_ORG)
        if criticality:
            q = q.where(Asset.criticality == criticality)
        if environment:
            q = q.where(Asset.environment == environment)
        assets = s.scalars(q.order_by(Asset.name)).all()

        rows = []
        for a in assets:
            bands = {}
            for f in a.findings:
                bands[f.band] = bands.get(f.band, 0) + 1
            worst = next((b for b in BAND_ORDER if bands.get(b)), None)
            rows.append({"asset": a, "findings": len(a.findings),
                         "bands": bands, "worst": worst})
        rows.sort(key=lambda r: (BAND_ORDER.index(r["worst"]) if r["worst"]
                                 else 99, -r["findings"]))
        crits = sorted({a.criticality for a in assets if a.criticality})
        envs = sorted({a.environment for a in assets if a.environment})
    return templates.TemplateResponse(request, "aspm/assets.html", {
        "rows": rows, "criticality": criticality, "environment": environment,
        "crits": crits, "envs": envs})


@web.get("/assets/{asset_id}", response_class=HTMLResponse)
def asset_detail(request: Request, asset_id: int):
    with SessionLocal() as s:
        a = s.get(Asset, asset_id)
        if a is None:
            raise HTTPException(404, "Ativo nao encontrado.")
        findings = sorted(a.findings,
                          key=lambda f: (BAND_ORDER.index(f.band) if f.band in BAND_ORDER
                                         else 99, -(f.ordering_score or 0)))
        tl = monitoring.timeline(s, a.org_id, asset_id=a.id, limit=30)
        return templates.TemplateResponse(request, "aspm/asset_detail.html", {
            "a": a, "findings": findings, "timeline": tl})


@web.get("/findings", response_class=HTMLResponse)
def findings_list(request: Request, band: str = "", severity: str = "",
                  status: str = "", asset: str = "", kev: str = "", q: str = ""):
    with SessionLocal() as s:
        query = select(Finding).where(Finding.org_id == DEFAULT_ORG)
        if band:
            query = query.where(Finding.band == band)
        if severity:
            query = query.where(Finding.severity == severity)
        if status:
            query = query.where(Finding.status == status)
        if kev == "1":
            query = query.where(Finding.assessment_json.like('%"kev_listed"%'))
        if q:
            like = f"%{q}%"
            query = query.where(Finding.title.like(like) | Finding.cve.like(like))
        findings = s.scalars(query.limit(600)).all()
        if asset:
            findings = [f for f in findings if f.asset and f.asset.identifier == asset]
        findings.sort(key=lambda f: (BAND_ORDER.index(f.band) if f.band in BAND_ORDER
                                     else 99, -(f.ordering_score or 0)))
        assets = s.scalars(select(Asset).where(Asset.org_id == DEFAULT_ORG)
                           .order_by(Asset.name)).all()
    return templates.TemplateResponse(request, "aspm/findings.html", {
        "findings": findings, "assets": assets,
        "f": {"band": band, "severity": severity, "status": status,
              "asset": asset, "kev": kev, "q": q},
        "bands": BAND_ORDER})


@web.get("/findings/{finding_id}", response_class=HTMLResponse)
def finding_detail(request: Request, finding_id: int):
    with SessionLocal() as s:
        f = s.get(Finding, finding_id)
        if f is None:
            raise HTTPException(404, "Achado nao encontrado.")
        v = _finding_view(s, f)
        v["ai"] = ai.get_provider().summarize_risk({
            "title": f.title, "asset_name": f.asset.name if f.asset else None,
            "assessment": f.assessment,
            "remediation": {"action": v["remediation"].action,
                            "confidence": v["remediation"].confidence}
            if v["remediation"] else {},
            "evidence_ids": [e.id for e in f.evidence]})
        v["ai_provider"] = ai.provider_info()
        v["reasons"] = list(ClosureReason)
        return templates.TemplateResponse(request, "aspm/finding_detail.html", v)


@web.get("/debt", response_class=HTMLResponse)
def debt_list(request: Request):
    with SessionLocal() as s:
        items = decision_debt.open_debt(s)
        resolved = s.scalars(select(DecisionDebt).where(
            DecisionDebt.org_id == DEFAULT_ORG, DecisionDebt.resolved.is_(True))
            .order_by(desc(DecisionDebt.resolved_at)).limit(30)).all()
        return templates.TemplateResponse(request, "aspm/debt.html", {
            "items": items, "resolved": resolved})


@web.get("/review", response_class=HTMLResponse)
def review_queue(request: Request):
    with SessionLocal() as s:
        items = review.review_queue(s)
        return templates.TemplateResponse(request, "aspm/review.html", {
            "items": items, "reasons": list(ClosureReason),
            "stats": review.stats(s)})


@web.get("/timeline", response_class=HTMLResponse)
def timeline_view(request: Request, material: str = ""):
    with SessionLocal() as s:
        q = select(ChangeEvent).where(ChangeEvent.org_id == DEFAULT_ORG)
        if material == "1":
            q = q.where(ChangeEvent.is_material.is_(True))
        events = s.scalars(q.order_by(desc(ChangeEvent.occurred_at),
                                      desc(ChangeEvent.id)).limit(200)).all()
        return templates.TemplateResponse(request, "aspm/timeline.html", {
            "events": events, "material": material,
            "snapshots": monitoring.snapshots(s, DEFAULT_ORG, 10)})


# --------------------------------------------------------------------------
# Acoes
# --------------------------------------------------------------------------

@web.post("/actions/demo")
def action_demo():
    with SessionLocal() as s:
        demo.build(s)
    return RedirectResponse("/aspm", status_code=303)


@web.post("/actions/simulate-change")
def action_simulate():
    with SessionLocal() as s:
        demo.simulate_context_change(s)
    return RedirectResponse("/aspm/timeline", status_code=303)


@web.post("/actions/reprocess")
def action_reprocess():
    with SessionLocal() as s:
        pipeline.reprocess(s)
    return RedirectResponse("/aspm", status_code=303)


@web.post("/actions/import")
async def action_import(file: UploadFile = FileParam(None),
                        kind: str = Form("findings")):
    if not file or not file.filename:
        raise HTTPException(400, "Nenhum arquivo enviado.")
    blob = await file.read()
    if len(blob) > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(400, f"Arquivo acima de {MAX_UPLOAD_MB}MB.")
    raw = blob.decode("utf-8-sig", errors="replace")
    name = file.filename.lower()

    try:
        if name.endswith(".sarif"):
            rows = ingestion.parse_sarif(raw)
        else:
            rows = ingestion.parse_tabular(
                raw, name.endswith(".json") or raw.lstrip().startswith(("[", "{")))
    except (ValueError, KeyError) as exc:
        raise HTTPException(400, f"Nao consegui ler o arquivo: {exc}")

    if not rows:
        raise HTTPException(400, "Nenhuma linha lida do arquivo.")

    with SessionLocal() as s:
        if kind == "assets":
            ingestion.import_assets(s, rows, source_system=file.filename)
            s.commit()
        else:
            pipeline.run_import(s, rows, source_system=file.filename,
                                label=f"Importacao: {file.filename}")
    return RedirectResponse("/aspm", status_code=303)


@web.post("/actions/review")
def action_review(finding_id: int = Form(...), reason: str = Form(...),
                  rationale: str = Form(...), analyst: str = Form("analista"),
                  debt_id: str = Form("")):
    with SessionLocal() as s:
        try:
            review.submit_review(s, finding_id, reason, rationale, analyst,
                                 resolves_debt_id=int(debt_id) if debt_id else None)
        except review.ReviewError as exc:
            raise HTTPException(400, str(exc))
        s.commit()
    return RedirectResponse(f"/aspm/findings/{finding_id}", status_code=303)


# --------------------------------------------------------------------------
# API JSON
# --------------------------------------------------------------------------

def _asset_json(a):
    return {"id": a.id, "identifier": a.identifier, "name": a.name, "type": a.type,
            "owner": a.owner, "criticality": a.criticality,
            "environment": a.environment, "internet_facing": a.internet_facing,
            "status": a.status, "source_system": a.source_system,
            "first_seen": a.first_seen, "last_seen": a.last_seen,
            "findings": len(a.findings)}


def _finding_json(f, deep=False):
    out = {"id": f.id, "fingerprint": f.fingerprint, "title": f.title,
           "cve": f.cve, "cwe": f.cwes, "severity": f.severity, "band": f.band,
           "ordering_score": f.ordering_score, "status": f.status,
           "asset": f.asset.identifier if f.asset else None,
           "package": f.package_name, "version": f.package_version,
           "fixed_version": f.fixed_version, "source_system": f.source_system,
           "risk_model_version": f.risk_model_version,
           "group_id": f.group_id, "first_seen": f.first_seen, "last_seen": f.last_seen}
    if deep:
        out["assessment"] = f.assessment
        out["evidence"] = [
            {"id": e.id, "type": e.evidence_type, "source": e.source,
             "source_id": e.source_id, "authority": e.source_authority,
             "classification": e.classification, "observed_at": e.observed_at,
             "retrieved_at": e.retrieved_at, "freshness": e.freshness_note,
             "content": json.loads(e.content) if e.content else None}
            for e in f.evidence]
        d = f.current_decision
        out["current_decision"] = ({
            "id": d.id, "reason": d.reason, "rationale": d.rationale,
            "decided_at": d.decided_at, "decided_by": d.decided_by,
            "classification": d.classification,
            "knowledge_snapshot": d.knowledge_snapshot} if d else None)
    return out


@api.get("/overview")
def api_overview():
    with SessionLocal() as s:
        d = overview_data(s)
        d.pop("recent_changes", None)
        d["snapshots"] = [{"id": x.id, "label": x.label, "taken_at": x.taken_at,
                           "findings_seen": x.findings_seen,
                           "findings_new": x.findings_new,
                           "findings_closed": x.findings_closed}
                          for x in d["snapshots"]]
    return JSONResponse(json.loads(json.dumps(d, default=str)))


@api.get("/assets")
def api_assets():
    with SessionLocal() as s:
        assets = s.scalars(select(Asset).where(Asset.org_id == DEFAULT_ORG)).all()
        return JSONResponse(json.loads(json.dumps(
            {"count": len(assets), "assets": [_asset_json(a) for a in assets]},
            default=str)))


@api.get("/findings")
def api_findings(band: str = "", limit: int = 200):
    with SessionLocal() as s:
        q = select(Finding).where(Finding.org_id == DEFAULT_ORG)
        if band:
            q = q.where(Finding.band == band)
        findings = s.scalars(q.limit(min(limit, 1000))).all()
        return JSONResponse(json.loads(json.dumps(
            {"count": len(findings),
             "findings": [_finding_json(f) for f in findings]}, default=str)))


@api.get("/findings/{finding_id}")
def api_finding(finding_id: int):
    with SessionLocal() as s:
        f = s.get(Finding, finding_id)
        if f is None:
            raise HTTPException(404, "Achado nao encontrado.")
        out = _finding_json(f, deep=True)
        rem = remediation.for_finding(s, f)
        out["remediation"] = ({"confidence": rem.confidence, "action": rem.action,
                               "detail": rem.detail, "source": rem.source,
                               "generated_by": rem.generated_by} if rem else None)
        out["decision_debt"] = [
            {"id": d.id, "trigger": d.trigger, "validity": d.validity,
             "explanation": d.explanation, "event_date": d.event_date,
             "days_after_decision": d.days_after_decision, "resolved": d.resolved}
            for d in decision_debt.for_finding(s, f)]
        return JSONResponse(json.loads(json.dumps(out, default=str)))


@api.get("/decision-debt")
def api_debt():
    with SessionLocal() as s:
        items = decision_debt.open_debt(s)
        return JSONResponse(json.loads(json.dumps({
            "count": len(items),
            "warning": ("As decisoes do dataset de demonstracao sao SINTETICAS. "
                        "Verifique `decision.classification` antes de citar "
                        "qualquer numero."),
            "items": [{"id": d.id, "finding_id": d.finding_id,
                       "cve": d.finding.cve if d.finding else None,
                       "trigger": d.trigger, "validity": d.validity,
                       "explanation": d.explanation, "event_date": d.event_date,
                       "days_after_decision": d.days_after_decision,
                       "decision_classification": (d.decision.classification
                                                   if d.decision else None)}
                      for d in items]}, default=str)))


@api.get("/timeline")
def api_timeline(limit: int = 100):
    with SessionLocal() as s:
        events = monitoring.timeline(s, DEFAULT_ORG, limit=limit)
        return JSONResponse(json.loads(json.dumps({
            "count": len(events),
            "events": [{"id": e.id, "kind": e.kind, "material": e.is_material,
                        "summary": e.summary, "occurred_at": e.occurred_at,
                        "detected_at": e.detected_at, "finding_id": e.finding_id,
                        "asset_id": e.asset_id, "source": e.source}
                       for e in events]}, default=str)))


@api.post("/review")
def api_review(payload: dict):
    with SessionLocal() as s:
        try:
            d = review.submit_review(
                s, int(payload["finding_id"]), payload["reason"],
                payload.get("rationale", ""), payload.get("analyst", "api"),
                resolves_debt_id=payload.get("debt_id"))
        except (KeyError, ValueError) as exc:
            raise HTTPException(400, f"Payload invalido: {exc}")
        except review.ReviewError as exc:
            raise HTTPException(400, str(exc))
        s.commit()
        return JSONResponse({"decision_id": d.id, "reason": d.reason,
                             "supersedes": d.supersedes_id,
                             "classification": d.classification})
