"""
Remediation Guidance.

A regra do briefing (secao 9) e curta e e a coisa toda:

    **Nao inventar instrucao de correcao.**

Entao a orientacao aqui e derivada de fatos que ja estao no achado ou na
evidencia -- versao corrigida declarada pelo scanner, advisory do KEV, historico
da propria organizacao -- e cada uma sai com um nivel de confianca e uma fonte.
Quando nao ha fonte, o sistema diz `uncertain` e explica o que falta, em vez de
produzir um texto plausivel.

Os quatro niveis, e o que cada um exige:

    VERIFIED     ha versao corrigida concreta vinda da fonte
    RECOMMENDED  ha advisory autoritativo (KEV) mas nao a versao exata
    HISTORICAL   esta organizacao ja resolveu um achado do mesmo grupo antes
    UNCERTAIN    nao ha fonte -- e isso e o que se diz
"""

import json

from sqlalchemy import select

from app.domain.enums import ClosureReason, RemediationConfidence
from app.domain.models import DEFAULT_ORG, Decision, Finding, Remediation


def _historical_precedent(session, finding, org_id):
    """A organizacao ja decidiu algo sobre o mesmo grupo?

    E o comeco da memoria organizacional: nao "o que a internet diz", mas "o que
    voces fizeram da ultima vez".
    """
    if not finding.group_id:
        return None
    peers = session.scalars(select(Finding).where(
        Finding.org_id == org_id, Finding.group_id == finding.group_id,
        Finding.id != finding.id)).all()
    if not peers:
        return None
    peer_ids = [p.id for p in peers]
    decisions = session.scalars(select(Decision).where(
        Decision.finding_id.in_(peer_ids)).order_by(Decision.decided_at.desc())).all()
    fixed = [d for d in decisions if d.reason == ClosureReason.FIXED.value]
    if fixed:
        return {"kind": "fixed", "decision": fixed[0], "peers": len(peers)}
    if decisions:
        return {"kind": decisions[0].reason, "decision": decisions[0], "peers": len(peers)}
    return None


def build_guidance(session, finding, org_id=DEFAULT_ORG):
    """Produz a orientacao para um achado. Nunca inventa."""
    evidence_ids = [e.id for e in finding.evidence]
    kev_ev = next((e for e in finding.evidence if e.evidence_type == "kev_listing"), None)

    # 1. VERIFIED — ha versao corrigida concreta.
    if finding.package_name and finding.fixed_version:
        cur = finding.package_version or "versao atual"
        return {
            "confidence": RemediationConfidence.VERIFIED,
            "action": (f"Atualizar {finding.package_name} de {cur} "
                       f"para {finding.fixed_version}."),
            "detail": ("A versao corrigida foi declarada pela propria fonte do achado, "
                       "nao inferida."),
            "source": finding.source_system,
            "source_url": None,
            "evidence_ids": evidence_ids,
        }

    # 2. RECOMMENDED — advisory autoritativo, sem versao exata.
    if kev_ev:
        content = json.loads(kev_ev.content or "{}")
        ransom = content.get("known_ransomware")
        action = (f"Aplicar a correcao do fornecedor para {finding.cve} em "
                  f"{content.get('vendor', '')} {content.get('product', '')}".strip() + ".")
        detail = ("O CVE consta no catalogo CISA KEV, com exploracao conhecida desde "
                  f"{content.get('date_added')}. A CISA exige acao para orgaos federais; "
                  "a versao corrigida exata nao esta no catalogo e deve vir do advisory "
                  "do fornecedor.")
        if ransom:
            detail += " Ha uso confirmado em campanha de ransomware."
        return {
            "confidence": RemediationConfidence.RECOMMENDED,
            "action": action, "detail": detail,
            "source": "CISA KEV", "source_url": kev_ev.source_url,
            "evidence_ids": evidence_ids,
        }

    # 3. HISTORICAL — precedente da propria organizacao.
    prec = _historical_precedent(session, finding, org_id)
    if prec:
        d = prec["decision"]
        reason = ClosureReason(d.reason)
        if prec["kind"] == "fixed":
            action = ("Aplicar a mesma correcao usada em achado equivalente deste "
                      "grupo.")
        else:
            action = (f"Achado equivalente deste grupo foi fechado como "
                      f"'{reason.label}'. Revisar se a mesma decisao se aplica.")
        return {
            "confidence": RemediationConfidence.HISTORICAL,
            "action": action,
            "detail": (f"{prec['peers']} achado(s) correlacionado(s); decisao mais "
                       f"recente em {d.decided_at:%Y-%m-%d}"
                       + (f" por {d.decided_by}" if d.decided_by else "")
                       + f". Origem da decisao: {d.classification}."),
            "source": f"historico da organizacao (decisao #{d.id})",
            "source_url": None,
            "evidence_ids": evidence_ids,
        }

    # 4. UNCERTAIN — diga o que falta.
    missing = []
    if not finding.cve:
        missing.append("o achado nao tem CVE (regra de SAST: nao ha advisory a consultar)")
    if not finding.package_name:
        missing.append("nao ha pacote identificado")
    if not finding.fixed_version:
        missing.append("nao ha versao corrigida declarada pela fonte")
    return {
        "confidence": RemediationConfidence.UNCERTAIN,
        "action": ("Sem orientacao de correcao derivavel das fontes disponiveis. "
                   "Revisao manual necessaria."),
        "detail": ("Faltam: " + "; ".join(missing) + "." if missing else
                   "Nenhuma fonte autoritativa foi encontrada para este achado."),
        "source": None, "source_url": None,
        "evidence_ids": evidence_ids,
    }


def generate_all(session, org_id=DEFAULT_ORG):
    findings = session.scalars(select(Finding).where(Finding.org_id == org_id)).all()
    counts = {}
    for f in findings:
        g = build_guidance(session, f, org_id)
        existing = session.scalars(select(Remediation).where(
            Remediation.finding_id == f.id)).first()
        if existing is None:
            existing = Remediation(org_id=org_id, finding_id=f.id,
                                   action=g["action"], confidence=g["confidence"].value)
            session.add(existing)
        existing.confidence = g["confidence"].value
        existing.action = g["action"]
        existing.detail = g["detail"]
        existing.source = g["source"]
        existing.source_url = g["source_url"]
        existing.evidence_ids_json = json.dumps(g["evidence_ids"])
        existing.generated_by = "deterministic"
        counts[g["confidence"].value] = counts.get(g["confidence"].value, 0) + 1
    session.flush()
    return {"generated": len(findings), "by_confidence": counts}


def for_finding(session, finding):
    return session.scalars(select(Remediation).where(
        Remediation.finding_id == finding.id)).first()
