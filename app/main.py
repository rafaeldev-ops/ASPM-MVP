import os

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, func, select

from app.analysis import demo_export_rows, load_export_from_text, run_analysis
from app.db import Analysis, DebtItem, SessionLocal, init_db, save_analysis
from app.interfaces.security import (
    SameOriginMiddleware, desligado as csrf_desligado, token_da_requisicao,
)

from app.paths import recurso

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Um export grande e legitimo; um upload de 200MB numa demo nao e. O limite
# existe para o erro ser uma mensagem clara em vez de a maquina travar.
MAX_UPLOAD_MB = 25

app = FastAPI(title="SDIP — Security Decision Intelligence Platform", docs_url=None, redoc_url=None)

# CSRF. Instalado aqui e nao por rota porque a garantia que interessa e
# "nenhuma rota insegura escapa" -- e uma lista por rota esquece a proxima.
# `/health` fica de fora por ser GET e nao ter efeito.
if not csrf_desligado():
    app.add_middleware(SameOriginMiddleware)

app.mount("/static", StaticFiles(directory=recurso("app", "static")), name="static")
templates = Jinja2Templates(directory=recurso("app", "templates"))

# Toda template renderizada ganha `csrf_token` sem a rota precisar lembrar. A
# alternativa -- passar no contexto de cada `TemplateResponse` -- e exatamente o
# tipo de coisa que funciona ate alguem acrescentar uma tela.
_render_original = templates.TemplateResponse


def _render_com_token(request, name=None, context=None, *args, **kwargs):
    ctx = dict(context or {})
    try:
        ctx.setdefault("csrf_token", token_da_requisicao(request))
    except Exception:
        pass
    return _render_original(request, name, ctx, *args, **kwargs)


templates.TemplateResponse = _render_com_token

# O MVP ASPM vive sob /aspm e /api/v1. O instrumento de backtest legado continua
# em / -- as duas superficies compartilham o mesmo banco e nenhuma tabela do
# backtest foi alterada.
#
# A forma `from ... import` e obrigatoria aqui: `import app.domain.models`
# religaria o nome `app` ao PACOTE e sobrescreveria a instancia FastAPI acima.
from app.domain import models as _aspm_models  # noqa: E402,F401
from app.interfaces.routes import api as aspm_api  # noqa: E402
from app.interfaces.routes import web as aspm_web  # noqa: E402

app.include_router(aspm_web)
app.include_router(aspm_api)

init_db()


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    with SessionLocal() as s:
        analyses = s.scalars(
            select(Analysis).order_by(desc(Analysis.created_at)).limit(25)
        ).all()
        totals = s.execute(
            select(
                func.count(Analysis.id),
                func.coalesce(func.sum(Analysis.debt_count), 0),
                func.coalesce(func.sum(Analysis.despite_count), 0),
                func.coalesce(func.sum(Analysis.analyzed), 0),
            )
        ).one()
    return templates.TemplateResponse(request, "index.html", {
        "analyses": analyses,
        "totals": {"runs": totals[0], "debt": totals[1],
                   "despite": totals[2], "analyzed": totals[3]},
    })


@app.post("/analyses")
async def create_analysis(request: Request, file: UploadFile = File(None),
                          use_demo: str = Form(None)):
    from app.interfaces.routes import exigir_csrf
    await exigir_csrf(request)
    if use_demo:
        rows, source_name, is_demo = demo_export_rows(), "Export sintético (demo)", True
    else:
        if not file or not file.filename:
            raise HTTPException(400, "Nenhum arquivo enviado.")
        blob = await file.read()
        if len(blob) > MAX_UPLOAD_MB * 1024 * 1024:
            raise HTTPException(400, f"Arquivo acima de {MAX_UPLOAD_MB}MB.")
        raw = blob.decode("utf-8-sig", errors="replace")
        is_json = file.filename.lower().endswith(".json") or raw.lstrip().startswith(("[", "{"))
        rows, source_name, is_demo = load_export_from_text(raw, is_json), file.filename, False

    try:
        summary, debt, despite, sample, excl = run_analysis(rows)
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    analysis_id = save_analysis(source_name, is_demo, summary, debt, despite, sample, excl)
    return RedirectResponse(f"/analyses/{analysis_id}", status_code=303)


@app.get("/analyses/{analysis_id}", response_class=HTMLResponse)
def analysis_detail(request: Request, analysis_id: int, kind: str = "debt",
                    reason: str = "", ransomware: str = ""):
    if kind not in ("debt", "despite"):
        kind = "debt"
    with SessionLocal() as s:
        analysis = s.get(Analysis, analysis_id)
        if not analysis:
            raise HTTPException(404, "Análise não encontrada.")

        q = select(DebtItem).where(DebtItem.analysis_id == analysis_id,
                                   DebtItem.kind == kind)
        if reason:
            q = q.where(DebtItem.reason == reason)
        if ransomware == "1":
            q = q.where(DebtItem.ransomware.is_(True))
        q = q.order_by(desc(DebtItem.ransomware), desc(DebtItem.kev_added))
        items = s.scalars(q.limit(500)).all()

        reasons = s.scalars(
            select(DebtItem.reason).where(DebtItem.analysis_id == analysis_id)
            .distinct().order_by(DebtItem.reason)
        ).all()

        timeline = s.execute(
            select(func.strftime("%Y-%m", DebtItem.kev_added), func.count(DebtItem.id))
            .where(DebtItem.analysis_id == analysis_id, DebtItem.kind == "debt")
            .group_by(func.strftime("%Y-%m", DebtItem.kev_added))
            .order_by(func.strftime("%Y-%m", DebtItem.kev_added))
        ).all()

    return templates.TemplateResponse(request, "analysis.html", {
        "a": analysis, "items": items, "kind": kind,
        "reason": reason, "ransomware": ransomware,
        "reasons": [r for r in reasons if r],
        "timeline": [{"month": m, "count": c} for m, c in timeline if m],
    })


@app.get("/analyses/{analysis_id}/session", response_class=HTMLResponse)
def review_session(request: Request, analysis_id: int):
    """A amostra estratificada de 20 para a sessao de revisao (protocolo V1 §1.5)."""
    with SessionLocal() as s:
        analysis = s.get(Analysis, analysis_id)
        if not analysis:
            raise HTTPException(404, "Análise não encontrada.")
        items = s.scalars(
            select(DebtItem)
            .where(DebtItem.analysis_id == analysis_id,
                   DebtItem.in_session_sample.is_(True))
            .order_by(desc(DebtItem.ransomware), desc(DebtItem.kev_added))
        ).all()
    return templates.TemplateResponse(request, "session.html", {"a": analysis, "items": items})


@app.get("/health")
def health():
    return {"status": "ok"}
