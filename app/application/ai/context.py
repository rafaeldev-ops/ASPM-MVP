"""
Context builder. Evidence-first, por junção tipada.

O briefing desenha `Finding → Context Builder → Evidence Selection → Contexto`, o
que se le como ranqueamento. A ADR-0009 mediu que nove de onze necessidades de
evidencia sao **junção**, e que o modo de falha e ranquear o que deveria ser
obrigatorio. As caixas do briefing ficam; o recheio e slot-filling tipado, com
registro de lacuna. **Ninguem implementa reranker aqui.**

O que fica de fora, e por que, esta na tabela do modulo. O caso mais importante:

    `Finding.raw_json` guarda a linha inteira do scanner original, ate 200 KB.
    E o maior portador de segredo do banco e o caso "segredo adjacente" da
    ADR-0011 §2. **Nenhum caminho de IA le esse campo, em nenhum tier, para
    nenhum provider, incluindo o local.** Um teste de canario garante isso.

`FindingContext` e **nao-serializavel por construcao**: sem `__repr__` util, sem
helper de dicionario exportado, e `__reduce__` levanta. Pickle e um
`json.dumps(default=...)` distraido nao conseguem contrabandeá-lo para fora. E o
mesmo truque que a ADR-0011 usa em `RawScannerPayload`, uma camada abaixo.
"""

import hashlib
import json
import os
from dataclasses import dataclass, field

CONTEXT_SCHEMA_VERSION = "ai-context-1"

# Ordem deterministica de evidencia. Nao e ranqueamento por similaridade: e
# autoridade, depois procedencia, depois quao recente e o FATO, depois id.
_AUTHORITY_RANK = {"authoritative": 0, "vendor": 1, "community": 2, "derived": 3}
_CLASS_RANK = {"REAL_EXTERNAL_DATA": 0, "DERIVED_DATA": 1, "SYNTHETIC_DATA": 2}

# Conteudo de evidencia entra por tipo, com campos nomeados um a um. E a regra
# "extrativo, nunca abstrativo" da ADR-0009 no nivel do campo.
_EVIDENCE_FACTS = {
    "kev_listing": ("date_added", "vendor", "product", "known_ransomware",
                    "short_description"),
    "epss_score": ("epss", "percentile", "model_version"),
}


class ContextError(Exception):
    pass


@dataclass(frozen=True)
class ContextEvidence:
    id: int
    type: str
    source: str
    source_id: str | None
    authority: str
    classification: str
    observed_at: str | None
    retrieved_at: str | None
    facts: dict = field(default_factory=dict)


@dataclass(frozen=True)
class FindingContext:
    """O que o modelo pode ver. Nada fora desta lista chega a um provider."""

    schema_version: str
    finding_id: int
    finding_class: str

    title: str
    description: str | None
    severity: str | None
    cve: str | None
    cwes: tuple
    package_name: str | None
    package_version: str | None
    fixed_version: str | None
    file_path_shape: str | None
    file_basename: str | None
    source_system: str
    source_rule_id: str | None

    assessment: dict
    asset: dict | None
    remediation: dict | None
    decision_history: tuple
    open_debt: tuple

    evidence: tuple
    evidence_gaps: tuple
    evidence_dropped: tuple
    knowledge_versions: dict
    contains_synthetic: bool

    # ---- nao-serializavel por construcao ----
    def __repr__(self):
        return f"<FindingContext finding_id={self.finding_id}>"

    def __reduce__(self):
        raise TypeError(
            "FindingContext nao e serializavel. Passe por redaction.redact() "
            "antes de qualquer coisa que saia deste processo.")

    def _payload(self):
        """Somente `redaction` chama isto. Nome privado de proposito."""
        return {
            "schema_version": self.schema_version,
            "finding_class": self.finding_class,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "cve": self.cve,
            "cwes": list(self.cwes),
            "package_name": self.package_name,
            "package_version": self.package_version,
            "fixed_version": self.fixed_version,
            "file_path_shape": self.file_path_shape,
            "file_basename": self.file_basename,
            "source_system": self.source_system,
            "source_rule_id": self.source_rule_id,
            "assessment": self.assessment,
            "asset": self.asset,
            "remediation": self.remediation,
            "decision_history": [dict(d) for d in self.decision_history],
            "open_debt": [dict(d) for d in self.open_debt],
            "evidence": [{"id": e.id, "type": e.type, "source": e.source,
                          "authority": e.authority,
                          "classification": e.classification,
                          "observed_at": e.observed_at, "facts": e.facts}
                         for e in self.evidence],
            "evidence_gaps": list(self.evidence_gaps),
            "knowledge_versions": self.knowledge_versions,
            "contains_synthetic": self.contains_synthetic,
        }

    @property
    def evidence_ids(self):
        """Exatamente o que foi entregue ao modelo.

        E contra este conjunto que a fundamentacao e verificada -- nao contra o
        que existe no banco. Um id que existe mas foi cortado pelo orcamento
        continua sendo alucinacao em relacao ao que o modelo viu.
        """
        return {e.id for e in self.evidence}

    def hash(self):
        blob = json.dumps(self._payload(), sort_keys=True, separators=(",", ":"),
                          default=str)
        return hashlib.sha256(blob.encode()).hexdigest()[:16]


def _classify_finding(f):
    if f.package_name:
        return "sca"
    if f.cve:
        return "vuln"
    if f.source_rule_id or f.file_path:
        return "sast"
    return "other"


def _path_shape(path):
    """Forma do caminho, nunca o caminho.

    Um caminho vaza a arquitetura do repositorio e as vezes o proprio segredo --
    `config/prod-db-password.env` conta uma historia inteira. A forma preserva o
    sinal util para triagem sem carregar isso.
    """
    if not path:
        return None
    parts = [p for p in str(path).replace("\\", "/").split("/") if p]
    ext = os.path.splitext(parts[-1])[1].lower() if parts else ""
    looks_test = any("test" in p.lower() or "spec" in p.lower() for p in parts)
    return f"depth={len(parts)} ext={ext or 'none'} test={'yes' if looks_test else 'no'}"


def _required_slots(finding_class):
    return {
        "sca": ("exploitation", "applicability", "asset_context"),
        "vuln": ("exploitation", "asset_context"),
        "sast": ("rule_identity", "asset_context"),
        "other": ("asset_context",),
    }[finding_class]


def build_context(session, finding, *, budget_chars=8000):
    """Constroi o contexto de um achado. Nao faz I/O de rede."""
    from app.application import knowledge

    fclass = _classify_finding(finding)
    assessment = finding.assessment or {}

    asset = None
    if finding.asset:
        a = finding.asset
        asset = {
            "name": a.name,
            "type": a.type,
            "criticality": a.criticality,
            "environment": a.environment,
            "internet_facing": a.internet_facing,
            # Dado pessoal vira booleano (ADR-0011 §1: pseudonimizar dono).
            "owner_present": bool(a.owner),
        }

    rem = None
    from app.application import remediation as remediation_mod
    r = remediation_mod.for_finding(session, finding)
    if r:
        rem = {"confidence": r.confidence, "action": r.action,
               "detail": r.detail, "source": r.source}

    history = tuple(
        {"reason": d.reason, "decided_at": str(d.decided_at)[:10],
         "classification": d.classification, "is_review": bool(d.is_review)}
        for d in sorted(finding.decisions, key=lambda x: x.decided_at, reverse=True)[:6]
    )

    from app.application import decision_debt as debt_mod
    open_debt = tuple(
        {"trigger": d.trigger, "validity": d.validity,
         "event_date": str(d.event_date)[:10] if d.event_date else None,
         "days_after_decision": d.days_after_decision,
         "explanation": d.explanation}
        for d in debt_mod.for_finding(session, finding) if not d.resolved
    )

    evidence, dropped = _select_evidence(finding, budget_chars)
    gaps = _gaps(fclass, finding, evidence, asset)

    synthetic = any(d["classification"] == "SYNTHETIC_DATA" for d in history)

    return FindingContext(
        schema_version=CONTEXT_SCHEMA_VERSION,
        finding_id=finding.id,
        finding_class=fclass,
        title=finding.title,
        description=finding.description,
        severity=finding.severity,
        cve=finding.cve,
        cwes=tuple(finding.cwes or ()),
        package_name=finding.package_name,
        package_version=finding.package_version,
        fixed_version=finding.fixed_version,
        file_path_shape=_path_shape(finding.file_path),
        file_basename=(os.path.basename(str(finding.file_path))
                       if finding.file_path else None),
        source_system=finding.source_system,
        source_rule_id=finding.source_rule_id,
        assessment={k: assessment.get(k) for k in (
            "band", "band_label", "decision_points", "reasons",
            "non_suppressible", "ineligibility_reasons", "ordering_score",
            "model_version")},
        asset=asset,
        remediation=rem,
        decision_history=history,
        open_debt=open_debt,
        evidence=evidence,
        evidence_gaps=gaps,
        evidence_dropped=dropped,
        knowledge_versions=knowledge.versions(),
        contains_synthetic=synthetic,
    )


def _select_evidence(finding, budget_chars):
    """Ordena, corta pelo orcamento, e **registra o que caiu**.

    Sem o registro de descarte, "a evidencia decisiva foi cortada antes de o
    modelo ver?" nao tem resposta -- que e exatamente o ponto da ADR-0009.
    """
    items = sorted(
        finding.evidence,
        key=lambda e: (_AUTHORITY_RANK.get(e.source_authority, 9),
                       _CLASS_RANK.get(e.classification, 9),
                       -(e.observed_at.toordinal() if e.observed_at else 0),
                       e.id))
    kept, dropped, used = [], [], 0
    for e in items:
        facts = _facts_for(e)
        size = len(json.dumps(facts, default=str)) + 120
        if used + size > budget_chars and kept:
            dropped.append({"id": e.id, "slot": e.evidence_type,
                            "reason": "orcamento de contexto"})
            continue
        used += size
        kept.append(ContextEvidence(
            id=e.id, type=e.evidence_type, source=e.source,
            source_id=e.source_id, authority=e.source_authority,
            classification=e.classification,
            observed_at=str(e.observed_at)[:10] if e.observed_at else None,
            retrieved_at=str(e.retrieved_at)[:10] if e.retrieved_at else None,
            facts=facts))
    return tuple(kept), tuple(dropped)


def _facts_for(evidence):
    """Conteudo por allowlist, por tipo de evidencia.

    Tipo desconhecido devolve vazio e vira lacuna -- e melhor o modelo saber que
    falta algo do que receber um blob que ninguem revisou.
    """
    allowed = _EVIDENCE_FACTS.get(evidence.evidence_type)
    if not allowed or not evidence.content:
        return {}
    try:
        raw = json.loads(evidence.content)
    except (ValueError, TypeError):
        return {}
    if not isinstance(raw, dict):
        return {}
    return {k: raw[k] for k in allowed if k in raw}


def _gaps(fclass, finding, evidence, asset):
    gaps = []
    types = {e.type for e in evidence}
    required = _required_slots(fclass)

    if "exploitation" in required and "kev_listing" not in types:
        gaps.append("sem evidencia de exploracao ativa (CVE fora do catalogo KEV)")
    if "applicability" in required and not finding.fixed_version:
        gaps.append("sem versao corrigida declarada pela fonte")
    if "rule_identity" in required and not finding.source_rule_id:
        gaps.append("achado sem identificador de regra")
    if "asset_context" in required:
        if asset is None:
            gaps.append("achado sem ativo associado")
        elif not asset.get("criticality"):
            gaps.append("criticidade do ativo nao resolvida")
    for e in evidence:
        if e.type not in _EVIDENCE_FACTS:
            gaps.append(f"evidencia de tipo nao mapeado: {e.type}")
    return tuple(gaps)
