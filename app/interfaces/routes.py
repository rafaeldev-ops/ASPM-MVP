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
from app.application.ai import redaction as ai_redaction
from app.application.ai import service as ai_service
from app.application.ai import settings as ai_settings
from app.application.ai.context import build_context
from app.infrastructure import credentials
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
        "ai": ai.provider_info(session),
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
        # A sintese desta tela e DETERMINISTICA e nao passa por provider nenhum.
        #
        # A versao anterior chamava `ai.get_provider().summarize_risk(...)` aqui
        # dentro. Enquanto so existia o provider nulo isso era inofensivo -- mas
        # no instante em que um provider externo virasse selecionavel, cada
        # visualizacao de pagina enviaria dados de achado para fora num GET
        # idempotente, sem consentimento e sem registro, e um refresh
        # multiplicaria. Analise com modelo acontece **somente** por POST
        # explicito, atras da tela de pre-voo (ADR-0018 §2).
        v["ai"] = ai.deterministic_summary({
            "title": f.title, "asset_name": f.asset.name if f.asset else None,
            "assessment": f.assessment,
            "remediation": {"action": v["remediation"].action,
                            "confidence": v["remediation"].confidence}
            if v["remediation"] else {},
            "evidence_ids": [e.id for e in f.evidence]})
        v["ai_provider"] = ai.provider_info(s)
        v["analysis"] = ai_service.latest_for(s, f.id)
        v["analysis_history"] = ai_service.history_for(s, f.id)
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
# Configuracao de IA
# --------------------------------------------------------------------------

@web.get("/settings", response_class=HTMLResponse)
def settings_screen(request: Request):
    with SessionLocal() as s:
        cfg = ai_settings.load(s)
        info = ai.provider_info(s)
        status, stale = ai.provider_status(s)
        return templates.TemplateResponse(request, "aspm/settings.html", {
            "cfg": cfg,
            "info": info,
            "status": status,
            "stale": stale,
            "providers": [
                {"name": n, "egress": cls.egress.value,
                 "egress_label": cls.egress.label,
                 "explanation": cls.egress.explanation,
                 "requires_key": cls.requires_api_key}
                for n, cls in sorted(ai.registry().items(),
                                     key=lambda kv: kv[1].egress.rank)],
            "credential": credentials.info(),
            "env_locked": ai_settings.env_overrides(),
            "rollup": ai_service.rollup(s),
        })


@web.post("/actions/settings/ai")
def action_save_ai(provider: str = Form("null"), model: str = Form(""),
                   base_url: str = Form(""), timeout_s: str = Form("60"),
                   analyst: str = Form("analista")):
    with SessionLocal() as s:
        ai_settings.save(s, {"provider": provider, "model": model,
                             "base_url": base_url, "timeout_s": timeout_s},
                         updated_by=analyst)
        s.commit()
    ai.reset()
    return RedirectResponse("/aspm/settings", status_code=303)


@web.post("/actions/settings/ai/key")
def action_save_key(api_key: str = Form(""), remove: str = Form("")):
    """Escreve ou apaga a chave no cofre do sistema.

    A chave nunca passa pelo banco, nunca vai para log e nenhum endpoint a
    devolve -- e a regra da ADR-0011 §5 aplicada aqui.
    """
    store = credentials.get_store()
    if not store.writable:
        raise HTTPException(400, store.describe())
    try:
        if remove:
            store.delete("openai")
        elif api_key.strip():
            store.set("openai", api_key.strip())
    except credentials.CredentialError as exc:
        raise HTTPException(400, str(exc))
    ai.reset()
    return RedirectResponse("/aspm/settings", status_code=303)


@web.post("/actions/settings/ai/test")
def action_test_provider():
    """Sondagem fresca. **Nao envia dado de achado nenhum.**"""
    with SessionLocal() as s:
        ai.provider_status(s, probe=True)
    return RedirectResponse("/aspm/settings", status_code=303)


# --------------------------------------------------------------------------
# Analise por achado
# --------------------------------------------------------------------------

@web.get("/findings/{finding_id}/analyze", response_class=HTMLResponse)
def analyze_confirm(request: Request, finding_id: int):
    """Tela de pre-voo.

    Declara o egresso ANTES da chamada e mostra **a carga redigida de verdade**,
    nao uma descricao dela. E o unico jeito de alguem atento verificar a
    promessa, e torna um defeito de redacao visivel a um humano antes de virar
    incidente.
    """
    with SessionLocal() as s:
        f = s.get(Finding, finding_id)
        if f is None:
            raise HTTPException(404, "Achado nao encontrado.")
        provider = ai.get_provider(s)
        cfg = ai_settings.load(s)
        ctx = build_context(s, f)

        payload, blocked, redacted = None, None, None
        try:
            redacted = ai_redaction.redact(ctx, egress=provider.egress, tier=cfg.tier)
            payload = ai_redaction.preview(redacted)
        except ai_redaction.RedactionBlocked as exc:
            blocked = str(exc)

        status, _ = ai.provider_status(s)
        return templates.TemplateResponse(request, "aspm/analyze_confirm.html", {
            "finding": f, "provider": provider, "cfg": cfg, "status": status,
            "payload": payload, "blocked": blocked, "redacted": redacted,
            "context": ctx, "info": ai.provider_info(s),
        })


@web.post("/findings/{finding_id}/analyze")
def analyze_run(finding_id: int, confirm_egress: str = Form(...)):
    with SessionLocal() as s:
        f = s.get(Finding, finding_id)
        if f is None:
            raise HTTPException(404, "Achado nao encontrado.")
        try:
            ai_service.analyze_finding(s, f, confirmed_egress=confirm_egress)
        except ai_service.EgressNotConfirmed as exc:
            raise HTTPException(409, str(exc))
        s.commit()
    return RedirectResponse(f"/aspm/findings/{finding_id}#analise", status_code=303)


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


def _int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@web.post("/actions/review")
def action_review(finding_id: int = Form(...), reason: str = Form(...),
                  rationale: str = Form(...), analyst: str = Form("analista"),
                  debt_id: str = Form(""), ai_analysis_id: str = Form(""),
                  ai_suggested_reason: str = Form("")):
    # Os dois ultimos vem do formulario pre-preenchido pela analise. Sao
    # registrados como o que a IA sugeriu, e a razao gravada continua sendo a que
    # o analista enviou -- inclusive quando ele trocou. E dessa diferenca que sai
    # a taxa de concordancia.
    with SessionLocal() as s:
        try:
            review.submit_review(s, finding_id, reason, rationale, analyst,
                                 resolves_debt_id=int(debt_id) if debt_id else None,
                                 ai_analysis_id=_int_or_none(ai_analysis_id),
                                 ai_suggested_reason=ai_suggested_reason or None)
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


@api.get("/settings/ai")
def api_ai_settings():
    """Configuracao efetiva. Segredo elidido por construcao -- ele nunca esteve
    neste objeto."""
    with SessionLocal() as s:
        cfg = ai_settings.load(s).as_public()
        cfg["info"] = ai.provider_info(s)
        cfg["credential"] = credentials.info()
        cfg["env_overrides"] = ai_settings.env_overrides()
    return JSONResponse(json.loads(json.dumps(cfg, default=str)))


@api.get("/findings/{finding_id}/analysis")
def api_finding_analysis(finding_id: int):
    with SessionLocal() as s:
        rows = ai_service.history_for(s, finding_id)
        return JSONResponse(json.loads(json.dumps({
            "count": len(rows),
            "analyses": [_analysis_json(a) for a in rows]}, default=str)))


@api.post("/findings/{finding_id}/analyze")
def api_finding_analyze(finding_id: int, payload: dict):
    """Exige confirmacao explicita do egresso.

    Sem isso um cliente distraido -- ou uma pagina aberta noutra aba -- dispara
    envio para terceiros sem ninguem ter visto para onde.
    """
    with SessionLocal() as s:
        f = s.get(Finding, finding_id)
        if f is None:
            raise HTTPException(404, "Achado nao encontrado.")
        confirm = (payload or {}).get("confirm_egress")
        if not confirm:
            raise HTTPException(
                409, "Informe `confirm_egress` com a classe de egresso atual.")
        try:
            record = ai_service.analyze_finding(s, f, confirmed_egress=confirm)
        except ai_service.EgressNotConfirmed as exc:
            raise HTTPException(409, str(exc))
        s.commit()
        return JSONResponse(json.loads(json.dumps(_analysis_json(record),
                                                  default=str)))


def _analysis_json(a):
    return {
        "id": a.id, "created_at": a.created_at, "outcome": a.outcome,
        "provider": a.provider, "model": a.model, "egress": a.egress,
        "redaction_tier": a.redaction_tier, "key_source": a.key_source,
        "analysis_version": a.analysis_version,
        "prompt_hash": a.prompt_hash, "context_hash": a.context_hash,
        "deterministic_band": a.deterministic_band,
        "risk_model_version": a.risk_model_version,
        "confidence": a.confidence,
        "confidence_band": a.confidence_band,
        "confidence_model_version": a.confidence_model_version,
        "summary": a.summary, "risk_explanation": a.risk_explanation,
        "recommended_action": a.recommended_action,
        "suggested_reason": a.suggested_reason,
        "evidence_ids": a.evidence_ids,
        "contradicting_evidence_ids": a.contradicting_evidence_ids,
        "uncertainty_reasons": a.uncertainty_reasons,
        "evidence_gaps": a.evidence_gaps,
        "redactions": a.redactions,
        "contains_synthetic": a.contains_synthetic,
        "latency_ms": a.latency_ms, "attempts": a.attempts,
        "tokens_in": a.tokens_in, "tokens_out": a.tokens_out,
        "error_detail": a.error_detail,
    }


@api.post("/review")
def api_review(payload: dict):
    with SessionLocal() as s:
        try:
            d = review.submit_review(
                s, int(payload["finding_id"]), payload["reason"],
                payload.get("rationale", ""), payload.get("analyst", "api"),
                resolves_debt_id=payload.get("debt_id"),
                ai_analysis_id=payload.get("ai_analysis_id"),
                ai_suggested_reason=payload.get("ai_suggested_reason"))
        except (KeyError, ValueError) as exc:
            raise HTTPException(400, f"Payload invalido: {exc}")
        except review.ReviewError as exc:
            raise HTTPException(400, str(exc))
        s.commit()
        return JSONResponse({"decision_id": d.id, "reason": d.reason,
                             "supersedes": d.supersedes_id,
                             "classification": d.classification,
                             "ai_analysis_id": d.ai_analysis_id,
                             "ai_suggested_reason": d.ai_suggested_reason,
                             "agreed_with_ai": d.agreed_with_ai})
