"""
Risk Correlation.

Liga Asset -> Finding -> Vulnerability -> Evidence, e agrupa achados que sao o
mesmo problema visto de angulos diferentes.

Regras que este modulo respeita (CLAUDE.md 25):

  - **Nao fundir irreversivelmente.** Agrupar cria um `FindingGroup` e aponta os
    membros para ele. Cada Finding continua existindo inteiro, com sua
    proveniencia. Re-correlacionar e recomputar o agrupamento, nao restaurar
    dado perdido.
  - **Registrar POR QUE.** `correlation_basis` diz qual sinal uniu o grupo, e os
    sinais tem forcas diferentes -- CVE+pacote e identidade, regra+arquivo e
    recorrencia. Misturar os dois sem registrar qual foi usado tornaria
    impossivel avaliar a qualidade do agrupamento depois.
  - **Semelhanca nao e identidade.** Nao ha agrupamento por similaridade
    textual. O run do Ring 0 mostrou o custo disso: `vmware/splinterdb` e
    `VMware vCenter` compartilham um token e nao tem relacao nenhuma.

Sem graph database. Duas tabelas e um indice resolvem o conjunto de consultas
que o MVP tem (ADR-0014).
"""

import json
from collections import defaultdict

from sqlalchemy import select

from app.application import knowledge
from app.domain.enums import EvidenceClass
from app.domain.models import DEFAULT_ORG, Evidence, Finding, FindingGroup

# Base de correlacao, da mais forte para a mais fraca. A primeira que se aplica
# vence, e fica registrada no grupo.
BASIS_CVE_PACKAGE = "cve+package"
BASIS_CVE = "cve"
BASIS_RULE_LOCATION = "rule+location"
BASIS_RULE_ASSET = "rule+asset"


def _group_key(f):
    """A chave de agrupamento e a base que a produziu."""
    if f.cve and f.package_name:
        return f"{f.cve}|{f.package_name}".lower(), BASIS_CVE_PACKAGE
    if f.cve:
        return f.cve.lower(), BASIS_CVE
    if f.source_rule_id and f.file_path:
        return f"{f.source_rule_id}|{f.file_path}".lower(), BASIS_RULE_LOCATION
    if f.source_rule_id and f.asset_id:
        return f"{f.source_rule_id}|asset:{f.asset_id}".lower(), BASIS_RULE_ASSET
    return None, None


def correlate(session, org_id=DEFAULT_ORG):
    """Recomputa os grupos. Idempotente: rodar de novo da o mesmo resultado."""
    findings = session.scalars(select(Finding).where(Finding.org_id == org_id)).all()

    buckets = defaultdict(list)
    for f in findings:
        key, basis = _group_key(f)
        if key:
            buckets[(key, basis)].append(f)
        else:
            f.group_id = None

    existing = {g.group_key: g for g in session.scalars(
        select(FindingGroup).where(FindingGroup.org_id == org_id)).all()}

    groups_created, grouped_findings, multi = 0, 0, 0
    for (key, basis), members in buckets.items():
        g = existing.get(key)
        if g is None:
            g = FindingGroup(org_id=org_id, group_key=key, correlation_basis=basis,
                             title=members[0].title)
            session.add(g)
            session.flush()
            groups_created += 1
        g.correlation_basis = basis
        g.member_count = len(members)
        for f in members:
            f.group_id = g.id
        grouped_findings += len(members)
        if len(members) > 1:
            multi += 1

    session.flush()
    return {
        "findings": len(findings),
        "groups": len(buckets),
        "groups_created": groups_created,
        "grouped_findings": grouped_findings,
        "multi_member_groups": multi,
        # "Duplicatas" aqui sao membros alem do primeiro de cada grupo. Nao e
        # uma taxa de falso positivo -- e quantos achados sao a mesma coisa.
        "duplicates_absorbed": grouped_findings - len(buckets),
        "ungrouped": sum(1 for f in findings if f.group_id is None),
    }


def _add_evidence(session, finding, **kw):
    """Grava evidencia sem duplicar: mesma fonte + mesmo id -> atualiza.

    Anexa pela RELACAO, nao por `session.add()` com a chave estrangeira solta.
    A diferenca nao e estilo: um `add()` nao atualiza a colecao `finding.evidence`
    ja carregada, e quem ler a evidencia na mesma sessao logo depois -- que e
    exatamente o que a geracao de remediacao faz -- enxerga uma lista vazia e
    conclui `uncertain` para um achado que tem advisory.
    """
    existing = next((e for e in finding.evidence
                     if e.source == kw["source"]
                     and e.source_id == kw.get("source_id")), None)
    if existing is None:
        existing = session.scalars(select(Evidence).where(
            Evidence.finding_id == finding.id,
            Evidence.source == kw["source"],
            Evidence.source_id == kw.get("source_id"))).first()
    if existing is not None:
        for k, v in kw.items():
            setattr(existing, k, v)
        return existing
    ev = Evidence(org_id=finding.org_id, **kw)
    finding.evidence.append(ev)
    return ev


def enrich(session, org_id=DEFAULT_ORG):
    """Anexa conhecimento externo como evidencia com proveniencia.

    KEV e EPSS entram aqui com estatutos diferentes, e a diferenca esta gravada
    no registro: o KEV e evidencia de exploracao (autoritativa, datada); o EPSS
    e sinal contextual de ordenacao, marcado como tal para ninguem o ler como
    gatilho depois.
    """
    kev = knowledge.kev()
    epss = knowledge.epss()
    findings = session.scalars(select(Finding).where(
        Finding.org_id == org_id, Finding.cve.isnot(None))).all()

    kev_hits, epss_hits = 0, 0
    for f in findings:
        entry = kev.entry(f.cve)
        if entry:
            _add_evidence(
                session, f,
                evidence_type="kev_listing", source="CISA KEV",
                source_id=f.cve, source_url=knowledge.KEV_URL,
                source_authority="authoritative",
                classification=EvidenceClass.REAL_EXTERNAL.value,
                content=json.dumps({
                    "date_added": str(entry["date_added"]),
                    "vendor": entry["vendor"], "product": entry["product"],
                    "known_ransomware": entry["known_ransomware"],
                    "short_description": entry["short_description"],
                }, ensure_ascii=False),
                observed_at=_to_dt(entry["date_added"]),
                freshness_note=f"catalogo KEV {kev.version}")
            kev_hits += 1

        score, pct = epss.get(f.cve)
        if score is not None:
            f.epss_score, f.epss_percentile = score, pct
            _add_evidence(
                session, f,
                evidence_type="epss_score", source="FIRST EPSS",
                source_id=f.cve,
                source_url="https://www.first.org/epss/",
                source_authority="authoritative",
                classification=EvidenceClass.REAL_EXTERNAL.value,
                content=json.dumps({
                    "epss": score, "percentile": pct,
                    "model_version": epss.model_version,
                    "usage": ("sinal contextual de ordenacao — NAO e gatilho de "
                              "re-litigio (EXP-001, EXP-004)"),
                }, ensure_ascii=False),
                freshness_note=f"modelo EPSS {epss.model_version} @ {epss.score_date}")
            epss_hits += 1

    session.flush()
    return {"findings_with_cve": len(findings), "kev_evidence": kev_hits,
            "epss_evidence": epss_hits}


def _to_dt(d):
    from datetime import datetime, time
    if d is None:
        return None
    if isinstance(d, datetime):
        return d
    return datetime.combine(d, time.min)


def related_findings(session, finding, limit=20):
    """Outras ocorrencias do mesmo problema. Alimenta a tela de detalhe."""
    if not finding.group_id:
        return []
    return session.scalars(
        select(Finding).where(Finding.group_id == finding.group_id,
                              Finding.id != finding.id).limit(limit)).all()
