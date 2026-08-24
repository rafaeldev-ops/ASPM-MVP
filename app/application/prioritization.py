"""
Prioritization Engine.

Monta o vetor de features a partir do achado + ativo + evidencia, e chama a
arvore deterministica de `app/domain/risk.py` -- que e `risk-model.md` 4.2
reparada por exp-002, nao uma formula nova (briefing 8).

O LLM nao participa. A banda sai da arvore; a explicacao sai das razoes que a
propria arvore produziu. A IA, quando ligada, reescreve essa explicacao em
prosa -- nunca a origina.
"""

import json

from sqlalchemy import select

from app.application import knowledge
from app.domain.models import DEFAULT_ORG, Finding
from app.domain.risk import assess


def features_for(finding, asset=None, kev=None):
    """Achado + ativo -> vetor de features do modelo de risco.

    Campo desconhecido fica None e o modelo trata como desconhecido. Nada aqui
    inventa um valor plausivel para preencher lacuna -- e a lacuna que faz o
    achado cair em `track` em vez de ser despriorizado por engano.
    """
    kev = kev or knowledge.kev()
    entry = kev.entry(finding.cve) if finding.cve else None

    env = (asset.environment if asset else None) or None
    internet = asset.internet_facing if asset else None
    criticality = (asset.criticality if asset else None) or None

    # Aplicabilidade: so afirmamos "cobre" quando ha versao instalada E versao
    # corrigida para comparar. Sem isso, `unknown`.
    range_covers = None
    if finding.package_version and finding.fixed_version:
        range_covers = _version_lt(finding.package_version, finding.fixed_version)

    return {
        "kev_listed": entry is not None,
        "active_exploitation": bool(entry and entry.get("known_ransomware")),
        "exploit_public": entry is not None,
        "exploit_maturity": None,
        "environment": env,
        "internet_facing": internet,
        "entry_point_confirmed": None,
        "artifact_shipped": None,
        "range_covers_deployed": range_covers,
        "reachability": None,
        "reach_tier_a": False,
        "dependency_scope": None,
        "criticality": criticality,
        "compensating_control": None,
        "cvss_base": finding.cvss_base,
        "epss_percentile": finding.epss_percentile,
        "cvss_spread": 0.0,
        "age_days": _age_days(finding),
    }


def _version_lt(a, b):
    """Comparacao de versao suficiente para semver simples. None se nao der.

    Devolver None em vez de um palpite importa: um falso `True` aqui vira
    `applicable`, que sobe a banda de um achado que talvez nao se aplique.
    """
    def parts(v):
        out = []
        for chunk in str(v).replace("-", ".").split("."):
            if chunk.isdigit():
                out.append(int(chunk))
            else:
                return None
        return out
    pa, pb = parts(a), parts(b)
    if pa is None or pb is None:
        return None
    n = max(len(pa), len(pb))
    pa += [0] * (n - len(pa))
    pb += [0] * (n - len(pb))
    return pa < pb


def _age_days(finding):
    if not finding.first_seen:
        return 0
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    seen = finding.first_seen
    if seen.tzinfo is None:
        seen = seen.replace(tzinfo=timezone.utc)
    return max(0, (now - seen).days)


def prioritize_finding(finding, asset=None, kev=None):
    result = assess(features_for(finding, asset, kev))
    finding.band = result["band"]
    finding.ordering_score = result["ordering_score"]
    finding.risk_model_version = result["model_version"]
    finding.assessment_json = json.dumps(result, ensure_ascii=False)
    return result


def prioritize_all(session, org_id=DEFAULT_ORG):
    kev = knowledge.kev()
    findings = session.scalars(select(Finding).where(Finding.org_id == org_id)).all()
    bands = {}
    for f in findings:
        r = prioritize_finding(f, f.asset, kev)
        bands[r["band"]] = bands.get(r["band"], 0) + 1
    session.flush()
    return {"scored": len(findings), "bands": bands}


def explain(finding):
    """Explicacao pronta para a tela. Sempre disponivel, sempre deterministica."""
    a = finding.assessment or {}
    return {
        "band": a.get("band"),
        "band_label": a.get("band_label"),
        "score": a.get("ordering_score"),
        "reasons": a.get("reasons", []),
        "decision_points": a.get("decision_points", {}),
        "non_suppressible": a.get("non_suppressible"),
        "blockers": a.get("ineligibility_reasons", []),
        "model_version": a.get("model_version"),
    }
