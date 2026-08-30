"""
Contrato de saida, validacao e confianca.

Tres coisas que este modulo garante e que o schema do provider nao consegue:

**Fundamentacao dura.** Todo id de evidencia citado tem que estar no conjunto que
foi *entregue ao modelo* -- nao meramente existir no banco. Um id que existe mas
foi cortado pelo orcamento continua sendo alucinacao em relacao ao que o modelo
viu. Id desconhecido rejeita a resposta inteira.

**Confianca deterministica.** O briefing pede `confidence` na saida do modelo. A
ADR-0007 §2 diz "Deterministic + calibrator. Remove from the model's schema" e a
ADR-0010 §1 se chama "The model never emits confidence or score". As ADRs ganham:
o campo existe porque a tela precisa, e e calculado por completude de evidencia.

**Falha fecha.** Recusa, timeout, JSON invalido ou schema violado nao produzem
recomendacao, e **nunca** produzem sugestao de despriorizar. A banda
deterministica nao e tocada por nenhum outcome -- nem pelo sucesso.

`validate` nunca levanta. IA degradada nao derruba a tela.
"""

from dataclasses import dataclass, field

CONFIDENCE_MODEL_VERSION = "evidence-completeness-1"

# Conjunto fechado. Dirige tela e telemetria ao mesmo tempo.
OK = "ok"
OK_DEGRADED = "ok_degraded"
REFUSED = "refused"
TIMEOUT = "timeout"
UNAVAILABLE = "unavailable"
MALFORMED = "malformed"
REJECTED_UNGROUNDED = "rejected_ungrounded"
BLOCKED_REDACTION = "blocked_redaction"
BUSY = "busy"

OUTCOMES = (OK, OK_DEGRADED, REFUSED, TIMEOUT, UNAVAILABLE, MALFORMED,
            REJECTED_UNGROUNDED, BLOCKED_REDACTION, BUSY)

OUTCOME_LABEL = {
    OK: "Analise concluida",
    OK_DEGRADED: "Analise concluida com ressalvas",
    REFUSED: "O modelo recusou a analise",
    TIMEOUT: "O modelo nao respondeu no tempo limite",
    UNAVAILABLE: "Provider indisponivel",
    MALFORMED: "Resposta do modelo fora do formato esperado",
    REJECTED_UNGROUNDED: "Resposta rejeitada: citou evidencia inexistente",
    BLOCKED_REDACTION: "Bloqueado antes do envio: segredo detectado no contexto",
    BUSY: "Ha analises em andamento",
}

# Cortes aplicados depois do fato -- o schema nao consegue expressa-los.
CAP_SUMMARY = 600
CAP_EXPLANATION = 2000
CAP_ACTION = 800
CAP_REASONS = 8
CAP_REASON_LEN = 200

# Compatibilidade: os cinco campos historicos continuam existindo.
AI_OUTPUT_FIELDS = ("summary", "risk_explanation", "recommended_action",
                    "evidence_ids", "uncertainty_reasons")


@dataclass
class ValidatedAnalysis:
    outcome: str = MALFORMED
    summary: str = ""
    risk_explanation: str = ""
    recommended_action: str = ""
    recommended_reason: str = ""
    evidence_ids: list = field(default_factory=list)
    contradicting_evidence_ids: list = field(default_factory=list)
    uncertainty_reasons: list = field(default_factory=list)
    error_detail: str = ""

    @property
    def ok(self):
        return self.outcome in (OK, OK_DEGRADED)

    @property
    def label(self):
        return OUTCOME_LABEL.get(self.outcome, self.outcome)


def _clean_text(value, cap):
    """Texto do modelo, higienizado.

    Remove controle e ANSI. O texto nunca e marcado como seguro no template,
    nunca vai para `href`/`src`, e nao e renderizado como markdown -- carregamento
    remoto de imagem e o canal de exfiltracao sem clique que a ADR-0007 nomeia.
    """
    if value is None:
        return ""
    text = str(value)
    text = "".join(ch for ch in text if ch == "\n" or ch == "\t" or ord(ch) >= 32)
    text = text.replace("\x1b", "")
    if len(text) > cap:
        text = text[:cap].rstrip() + " […truncado]"
    return text.strip()


def _ints(value):
    out = []
    if isinstance(value, (list, tuple)):
        for v in value:
            try:
                out.append(int(v))
            except (TypeError, ValueError):
                continue
    return out


def validate(raw, redacted):
    """Resposta crua -> `ValidatedAnalysis`. Nunca levanta."""
    from app.domain.enums import ClosureReason

    if not isinstance(raw, dict):
        return ValidatedAnalysis(
            outcome=MALFORMED,
            uncertainty_reasons=["a resposta do modelo nao era um objeto JSON"],
            error_detail="resposta nao e objeto")

    supplied = set(redacted.evidence_ids) if redacted is not None else set()
    cited = _ints(raw.get("evidence_ids"))
    contra = _ints(raw.get("contradicting_evidence_ids"))

    # Fundamentacao dura, contra o que FOI ENTREGUE ao modelo.
    unknown = [i for i in cited + contra if i not in supplied]
    if unknown:
        return ValidatedAnalysis(
            outcome=REJECTED_UNGROUNDED,
            uncertainty_reasons=[
                f"a resposta citou evidencia que nao lhe foi fornecida: "
                f"{sorted(set(unknown))[:5]}"],
            error_detail=f"{len(unknown)} id(s) sem fundamentacao")

    reasons = []
    for r in (raw.get("uncertainty_reasons") or [])[:CAP_REASONS]:
        cleaned = _clean_text(r, CAP_REASON_LEN)
        if cleaned:
            reasons.append(cleaned)

    suggested = str(raw.get("recommended_reason") or "").strip().lower()
    if suggested:
        try:
            suggested = ClosureReason(suggested).value
        except ValueError:
            reasons.append("a razao sugerida pelo modelo era invalida e foi descartada")
            suggested = ""

    result = ValidatedAnalysis(
        outcome=OK,
        summary=_clean_text(raw.get("summary"), CAP_SUMMARY),
        risk_explanation=_clean_text(raw.get("risk_explanation"), CAP_EXPLANATION),
        recommended_action=_clean_text(raw.get("recommended_action"), CAP_ACTION),
        recommended_reason=suggested,
        evidence_ids=sorted(set(cited)),
        contradicting_evidence_ids=sorted(set(contra)),
        uncertainty_reasons=reasons,
    )

    if not result.summary and not result.risk_explanation:
        result.outcome = MALFORMED
        result.error_detail = "resposta sem sintese e sem explicacao"
        return result

    # Citar nada tendo recebido evidencia nao rejeita, mas e sinal.
    if supplied and not result.evidence_ids:
        result.outcome = OK_DEGRADED
        result.uncertainty_reasons.append(
            "a resposta nao citou nenhuma evidencia das fornecidas")

    return result


def confidence_for(ctx, analysis):
    """Confianca por completude de evidencia. Sem modelo, sem rotulo.

    Calibrador do estagio 0 da ADR-0010: mede o quanto sabemos, nao o quanto o
    modelo acha que sabe. Devolve `(valor, insumos)` -- e os insumos vao para a
    tela, porque a ADR-0010 §2 proibe renderizar confianca como numero solto.
    """
    required = len(ctx.evidence_gaps) + len(ctx.evidence)
    filled = len(ctx.evidence)
    completeness = (filled / required) if required else 0.0

    authoritative = sum(1 for e in ctx.evidence if e.authority == "authoritative")
    authority = min(1.0, authoritative / 2.0)

    real = sum(1 for e in ctx.evidence if e.classification == "REAL_EXTERNAL_DATA")
    freshness = min(1.0, real / 2.0)

    score = 0.45 * completeness + 0.30 * authority + 0.25 * freshness

    penalties = {}
    if ctx.asset is None or not (ctx.asset or {}).get("criticality"):
        penalties["criticidade do ativo nao resolvida"] = 0.20
    if ctx.contains_synthetic:
        penalties["historico de decisao sintetico"] = 0.25
    if ctx.evidence_gaps:
        penalties[f"{len(ctx.evidence_gaps)} lacuna(s) de evidencia"] = min(
            0.20, 0.05 * len(ctx.evidence_gaps))
    if analysis is not None and analysis.uncertainty_reasons:
        penalties["o modelo declarou incerteza"] = 0.10

    score -= sum(penalties.values())
    score = max(0.0, min(1.0, score))

    return round(score, 3), {
        "completude de evidencia": round(completeness, 2),
        "autoridade da fonte": round(authority, 2),
        "procedencia real": round(freshness, 2),
        "penalidades": penalties,
        "versao": CONFIDENCE_MODEL_VERSION,
    }


# --------------------------------------------------------------------------
# Sintese deterministica -- o caminho que a tela sempre usa
# --------------------------------------------------------------------------

def deterministic_summary(context):
    """Os cinco campos historicos, sem I/O e sem modelo.

    E o que a pagina de achado renderiza em toda visualizacao, e continua sendo o
    fallback quando qualquer analise falha. Nao faz chamada nenhuma: e por isso
    que uma pagina nunca fica em branco por causa de provider fora do ar.
    """
    a = (context or {}).get("assessment") or {}
    reasons = a.get("reasons") or []
    asset = (context or {}).get("asset_name") or "ativo nao identificado"
    title = (context or {}).get("title") or "achado"
    band = a.get("band_label", "sem banda")

    summary = f"{title} em {asset}. Classificacao: {band}."
    explanation = ("Motivos: " + "; ".join(reasons) + ".") if reasons else (
        "Nao ha motivos registrados: o motor nao encontrou sinal suficiente.")

    rem = (context or {}).get("remediation") or {}
    action = rem.get("action") or "Sem orientacao de correcao disponivel."
    if rem.get("confidence"):
        action += f" (confianca: {rem['confidence']})"

    unc = list(a.get("ineligibility_reasons") or [])
    dp = a.get("decision_points") or {}
    if dp.get("applicability") == "unknown":
        unc.append("aplicabilidade nao determinada")
    if dp.get("exposure") == "unknown":
        unc.append("exposicao do ativo nao mapeada")

    return validate_ai_output({
        "summary": summary,
        "risk_explanation": explanation,
        "recommended_action": action,
        "evidence_ids": [str(e) for e in ((context or {}).get("evidence_ids") or [])],
        "uncertainty_reasons": unc,
    })


def validate_ai_output(raw):
    """Coercao de forma dos cinco campos historicos.

    Preservada com o mesmo nome e o mesmo comportamento de antes: nunca levanta,
    forma fixa, chave extra descartada. `tests/test_e2e.py` depende disso.
    """
    if not isinstance(raw, dict):
        return {"summary": "", "risk_explanation": "", "recommended_action": "",
                "evidence_ids": [],
                "uncertainty_reasons": ["saida do modelo invalida"]}
    out = {}
    for f in AI_OUTPUT_FIELDS:
        v = raw.get(f)
        if f in ("evidence_ids", "uncertainty_reasons"):
            out[f] = [str(x) for x in v] if isinstance(v, (list, tuple)) else []
        else:
            out[f] = str(v) if v is not None else ""
    return out
