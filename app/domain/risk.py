"""
Modelo de risco deterministico. Puro: sem I/O, sem SQL, sem LLM.

Esta e a arvore de `docs/decisions/risk-model.md` 4.2, na versao reparada por
`exp-002` -- 20 linhas, espaco de 720 combinacoes, provada total e sem linhas
mortas por `phase0/v2_riskmodel.py --assert`.

**Nao e uma formula nova.** O briefing da Sprint 3 (secao 8) diz para nao
inventar uma se ja houver decisao documentada, e ha: esta. Portada, nao
reescrita -- e `tests/test_risk_tree.py` reexecuta as mesmas assercoes que o
instrumento do phase0 executa, para as duas nao divergirem em silencio.

O LLM nao entra aqui. A prioridade e deterministica e explicavel; a IA, quando
existir, sintetiza a explicacao, nunca produz a banda.
"""

from app.domain.enums import Band

ANY = None

EXPLOITATION = ("none", "poc", "public", "active")
EXPOSURE = ("not_deployed", "unknown", "internal", "controlled", "open")
APPLICABILITY = ("not_applicable", "unknown", "applicable")
CRITICALITY = ("low", "medium", "high", "critical")
CONTROL = ("none", "present", "enforcing")

# risk-model.md 4.2, revisado 2026-08-17 por exp-002. A primeira linha que casa
# vence. Alterar qualquer linha exige rodar a matriz de transicao de bandas
# (risk-model.md 7.2) antes de mergear.
TREE = [
    (1,  {"active"}, ANY, {"unknown", "applicable"}, ANY, ANY, "act_now"),
    (2,  {"active"}, ANY, {"not_applicable"}, ANY, ANY, "act_soon"),
    (3,  {"public"}, {"open"}, {"applicable"}, ANY, {"none", "present"}, "act_now"),
    (4,  {"public"}, {"open"}, {"applicable"}, ANY, {"enforcing"}, "act_soon"),
    (5,  {"public"}, {"open"}, {"unknown"}, {"critical", "high"}, ANY, "act_soon"),
    (6,  {"public"}, {"internal", "controlled"}, {"applicable"},
         {"critical", "high"}, {"none", "present"}, "act_soon"),
    (7,  {"public"}, {"unknown"}, {"unknown", "applicable"}, ANY, ANY, "act_soon"),
    (8,  {"poc"}, {"open"}, {"applicable"}, ANY, {"none", "present"}, "act_soon"),
    (9,  {"poc"}, ANY, {"applicable"}, {"critical"}, ANY, "act_soon"),
    (10, {"none"}, {"open"}, {"applicable"}, {"critical"}, ANY, "act_soon"),
    (11, {"poc", "none"}, {"open"}, {"applicable"}, {"high", "medium"}, ANY, "scheduled"),
    (12, {"none"}, {"internal", "controlled"}, {"applicable"}, {"critical"},
         {"none", "present"}, "scheduled"),
    (13, {"public"}, {"internal", "controlled"}, {"applicable"}, ANY, ANY, "scheduled"),
    (14, {"poc"}, {"internal", "controlled", "unknown"}, {"applicable"}, ANY, ANY,
         "scheduled"),
    (15, ANY, ANY, {"unknown"}, ANY, ANY, "track"),
    (16, {"none"}, {"internal", "controlled"}, {"applicable"}, {"low"},
         {"enforcing"}, "deprioritize_candidate"),
    (17, {"public"}, ANY, {"not_applicable"}, ANY, ANY, "track"),
    (18, {"none", "poc"}, ANY, {"not_applicable"}, ANY, ANY, "deprioritize_candidate"),
    (19, {"none", "poc"}, {"not_deployed"}, ANY, ANY, ANY, "deprioritize_candidate"),
    # Catch-all conservador: "nao pensamos nisso" custa hora de analista, nunca
    # silencio. Nunca deprioriza.
    (20, ANY, ANY, ANY, ANY, ANY, "track"),
]

UNMATCHED = "UNMATCHED"

ORD_EXPLOIT = {"none": 0.0, "poc": 0.4, "public": 0.7, "active": 1.0}
ORD_EXPOSURE = {"not_deployed": 0.0, "unknown": 0.3, "internal": 0.5,
                "controlled": 0.4, "open": 1.0}
ORD_CRIT = {"low": 0.1, "medium": 0.4, "high": 0.7, "critical": 1.0}
ORD_APPL = {"not_applicable": 0.0, "unknown": 0.4, "applicable": 1.0}
BAND_ORDER = {b.value: b.rank for b in Band}


def band_of(dp1, dp2, dp3, dp4, dp5):
    for row in TREE:
        if all(spec is ANY or val in spec
               for spec, val in zip(row[1:6], (dp1, dp2, dp3, dp4, dp5))):
            return row[6], row[0]
    return UNMATCHED, None


def decision_points(f):
    """Features -> os cinco pontos de decisao. risk-model.md 3."""
    # DP1 exploitation
    if f.get("kev_listed") or f.get("active_exploitation"):
        dp1 = "active"
    elif f.get("exploit_public"):
        dp1 = "public"
    elif f.get("exploit_maturity") == "poc":
        dp1 = "poc"
    else:
        dp1 = "none"

    # DP2 exposure. `not_deployed` primeiro: um servico que nao esta em producao
    # nao pode estar exposto em producao, diga o registro o que disser.
    if f.get("environment") in ("staging", "dev") or f.get("artifact_shipped") is False:
        dp2 = "not_deployed"
    elif f.get("internet_facing") is True and f.get("environment") == "prod":
        dp2 = "open"
    elif f.get("entry_point_confirmed") is True and f.get("internet_facing") is False:
        dp2 = "controlled"
    elif f.get("internet_facing") is False and f.get("environment") == "prod":
        dp2 = "internal"
    else:
        dp2 = "unknown"

    # DP3 applicability. `not_applicable` exige sinal POSITIVO de tier A;
    # ausencia de evidencia devolve `unknown`, nunca `not_applicable`.
    if (f.get("range_covers_deployed") is False
            or (f.get("reachability") == "not_reachable" and f.get("reach_tier_a"))
            or (f.get("dependency_scope") == "dev_only"
                and f.get("artifact_shipped") is False)):
        dp3 = "not_applicable"
    elif f.get("range_covers_deployed") is True and f.get("reachability") != "not_reachable":
        dp3 = "applicable"
    else:
        dp3 = "unknown"

    # Criticidade nula falha FECHADO: assume critico. Nao saber a criticidade de
    # um ativo nao pode baratear o achado.
    dp4 = f.get("criticality") or "critical"
    dp5 = f.get("compensating_control") or "none"
    return dp1, dp2, dp3, dp4, dp5


def ordering_score(f, dps):
    """Score de ordenacao DENTRO da banda. Nao substitui a banda.

    EPSS entra aqui, com peso 0.20 -- como sinal contextual de ordenacao, que e
    exatamente o papel que EXP-001 e EXP-004 deixaram para ele. Ele nunca move
    a banda e nunca dispara re-litigio.
    """
    dp1, dp2, dp3, dp4, _ = dps
    c = {
        "cvss": 0.20 * ((f.get("cvss_base") or 0) / 10.0),
        "epss": 0.20 * (f.get("epss_percentile") or 0.0),
        "exploitation": 0.15 * ORD_EXPLOIT[dp1],
        "exposure": 0.15 * ORD_EXPOSURE[dp2],
        "criticality": 0.15 * ORD_CRIT[dp4],
        "applicability": 0.10 * ORD_APPL[dp3],
        "pressure": 0.05 * min(1.0, (f.get("age_days") or 0) / 365.0),
    }
    return max(0.0, min(1.0, sum(c.values()))), c


def non_suppressible(f):
    """Motivos pelos quais um achado nunca pode ser silenciado (ADR-0007)."""
    if f.get("kev_listed"):
        return "kev_listed"
    if f.get("active_exploitation"):
        return "active_exploitation"
    return None


# Texto humano por ponto de decisao. A explicabilidade e requisito (briefing 8),
# entao a frase nasce junto da regra em vez de ser montada na template.
_REASON_TEXT = {
    "exploitation": {
        "active": "exploracao ativa conhecida (CISA KEV)",
        "public": "existe exploit publico",
        "poc": "existe prova de conceito",
        "none": "sem exploit conhecido",
    },
    "exposure": {
        "open": "exposto a internet em producao",
        "internal": "interno em producao",
        "controlled": "alcancavel apenas por caminho controlado",
        "not_deployed": "nao esta em producao",
        "unknown": "exposicao desconhecida (ativo nao mapeado)",
    },
    "applicability": {
        "applicable": "a faixa afetada cobre a versao em uso",
        "not_applicable": "a faixa afetada nao cobre a versao em uso",
        "unknown": "aplicabilidade nao determinada",
    },
    "criticality": {
        "critical": "ativo de criticidade critica",
        "high": "ativo de criticidade alta",
        "medium": "ativo de criticidade media",
        "low": "ativo de criticidade baixa",
    },
    "control": {
        "enforcing": "controle compensatorio ativo e aplicado",
        "present": "controle compensatorio presente mas nao aplicado",
        "none": "sem controle compensatorio",
    },
}


def assess(f):
    """Avaliacao completa e explicavel de um achado.

    Devolve banda, linha da arvore, score de ordenacao, motivos em texto e
    elegibilidade para despriorizacao automatica.
    """
    dps = decision_points(f)
    names = ("exploitation", "exposure", "applicability", "criticality", "control")
    band, row = band_of(*dps)
    score, contrib = ordering_score(f, dps)
    ns = non_suppressible(f)

    # Piso de sobreposicao: nada com exploracao ativa cai abaixo de act_soon,
    # qualquer que seja a linha que casou.
    if ns and BAND_ORDER.get(band, 9) > BAND_ORDER["act_soon"]:
        band = "act_soon"

    blockers = []
    if ns:
        blockers.append(f"non_suppressible:{ns}")
    if f.get("criticality") is None:
        blockers.append("criticality_unresolved")
    if (f.get("cvss_spread") or 0) > 2.0:
        blockers.append("cvss_disagreement")

    reasons = [_REASON_TEXT[n][v] for n, v in zip(names, dps) if v in _REASON_TEXT[n]]
    if ns == "kev_listed":
        reasons.insert(0, "CVE consta no catalogo CISA KEV — nunca suprimivel")

    return {
        "decision_points": dict(zip(names, dps)),
        "band": band,
        "band_label": Band(band).label if band != UNMATCHED else "Sem banda",
        "tree_row": row,
        "ordering_score": round(score, 3),
        "score_contributions": {k: round(v, 3) for k, v in contrib.items()},
        "non_suppressible": ns,
        "auto_deprioritize_eligible": band == "deprioritize_candidate" and not blockers,
        "ineligibility_reasons": blockers,
        "reasons": reasons,
        "model_version": "risk-model.md-4.2+exp-002",
    }


def all_combinations():
    for a in EXPLOITATION:
        for b in EXPOSURE:
            for c in APPLICABILITY:
                for d in CRITICALITY:
                    for e in CONTROL:
                        yield a, b, c, d, e
