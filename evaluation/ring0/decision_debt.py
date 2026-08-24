#!/usr/bin/env python3
"""
Motor de divida de decisao -- o nucleo do Ring 0.

Responde uma pergunta e recusa responder outra.

    RESPONDE : "esta decisao, tomada em D, adquiriu depois evidencia que
                invalida a razao pela qual foi fechada?"

    RECUSA   : qualquer pergunta cuja resposta dependa de saber hoje o que
                nao se sabia em D.

A segunda parte e o que separa este motor de um relatorio bonito e errado.
`knowledge_as_of()` e a unica porta para o estado externo, e ela nao tem como
devolver informacao posterior a data pedida -- nao por disciplina de quem
chama, mas porque a funcao nao ve o futuro (secao 15 e 16 do briefing).

EPSS NAO e gatilho. Decidido em EXP-001 com numero medido e reconfirmado em
EXP-004 deste run. O motor tem uma classe para eventos de EPSS e ela esta na
lista de NAO-materiais.

Somente biblioteca padrao.
"""

import os
import sys
from datetime import date, datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ingest_kev import KevCatalog  # noqa: E402


# --------------------------------------------------------------------------
# Eventos de mudanca externa
# --------------------------------------------------------------------------

# Materiais: mudam o que se sabe sobre exploracao ou sobre aplicabilidade.
KEV_LISTED = "KEV_LISTED"
ADVISORY_RANGE_NARROWED = "ADVISORY_RANGE_NARROWED"
EXPLOITABILITY_CHANGED = "EXPLOITABILITY_CHANGED"

# Nao-materiais: mudam bytes, nao risco.
EPSS_SCORE_CHANGED = "EPSS_SCORE_CHANGED"
DESCRIPTION_UPDATED = "DESCRIPTION_UPDATED"
METADATA_TIMESTAMP_CHANGED = "METADATA_TIMESTAMP_CHANGED"
LOW_AUTHORITY_SOURCE_CHANGED = "LOW_AUTHORITY_SOURCE_CHANGED"

# Caso a parte: nao gera candidato, muda a disponibilidade da evidencia.
EVIDENCE_REMOVED = "EVIDENCE_REMOVED"

MATERIAL_KINDS = frozenset({KEV_LISTED, ADVISORY_RANGE_NARROWED, EXPLOITABILITY_CHANGED})
NON_MATERIAL_KINDS = frozenset({
    EPSS_SCORE_CHANGED, DESCRIPTION_UPDATED,
    METADATA_TIMESTAMP_CHANGED, LOW_AUTHORITY_SOURCE_CHANGED,
})

# Por que cada nao-material esta fora. Escrito aqui e nao num comentario solto
# porque o relatorio le esta tabela -- a justificativa e parte da saida.
NON_MATERIAL_RATIONALE = {
    EPSS_SCORE_CHANGED: (
        "EPSS e um score de modelo. Uma troca de versao de modelo move dezenas de "
        "milhares de CVEs atraves de um limiar sem que nada tenha mudado no mundo "
        "(EXP-001; reconfirmado em EXP-004). Nao e gatilho."),
    DESCRIPTION_UPDATED: (
        "Texto reescrito nao e risco alterado. Disparar aqui e treinar o analista a "
        "ignorar o produto."),
    METADATA_TIMESTAMP_CHANGED: (
        "Um feed republicado muda timestamps em massa. Seria uma avalanche por "
        "manutencao de infraestrutura alheia."),
    LOW_AUTHORITY_SOURCE_CHANGED: (
        "Autoridade da fonte e parte da evidencia (ADR-0013). Fonte fraca nao promove "
        "uma decisao a re-litigio sozinha."),
}

# Razoes de fechamento que representam uma decisao de NAO agir. Um achado
# corrigido nao tem divida de decisao -- nao ha decisao a re-litigar.
DECISION_TO_NOT_ACT = frozenset({"false_positive", "risk_accepted", "wont_fix", "mitigated"})


def as_date(d):
    if isinstance(d, datetime):
        return d.date()
    if isinstance(d, date):
        return d
    return datetime.strptime(str(d)[:10], "%Y-%m-%d").date()


class ChangeEvent:
    def __init__(self, kind, cve_id, at, source, authority="authoritative", detail=""):
        self.kind = kind
        self.cve_id = str(cve_id).upper()
        self.at = as_date(at)
        self.source = source
        self.authority = authority
        self.detail = detail

    def to_dict(self):
        return {"kind": self.kind, "cve_id": self.cve_id, "at": self.at.isoformat(),
                "source": self.source, "authority": self.authority, "detail": self.detail}


class TemporalLeakageError(Exception):
    """Alguem tentou usar informacao posterior a data da decisao."""


class KnowledgeOracle:
    """A unica porta para o estado externo, e ela e cega para o futuro.

    Todo metodo exige `as_of`. Nao existe uma consulta sem data -- e a ausencia
    dela e o controle de vazamento, nao um teste que roda depois.
    """

    def __init__(self, kev_catalog):
        self.kev = kev_catalog
        self.queries = []  # trilha de auditoria: toda consulta fica registrada

    def knowledge_as_of(self, cve_id, as_of):
        as_of = as_date(as_of)
        state = self.kev.state_as_of(cve_id, as_of)
        added = self.kev.date_added(cve_id)

        # O controle: se o CVE entrou no KEV DEPOIS de as_of, a data de entrada
        # e informacao do futuro e nao sai desta funcao.
        disclosed_date = added.isoformat() if (added and added <= as_of) else None
        if added and added > as_of and disclosed_date is not None:
            raise TemporalLeakageError(
                f"{cve_id}: date_added {added} e posterior a as_of {as_of}")

        entry = self.kev.by_cve.get(str(cve_id).upper())
        record = {
            "cve_id": str(cve_id).upper(),
            "as_of": as_of.isoformat(),
            "kev_state": state,
            "kev_date_added_if_known": disclosed_date,
            # ransomware so e conhecido se a entrada ja era conhecida naquele dia
            "known_ransomware_if_known": (
                bool(entry["known_ransomware"]) if (entry and disclosed_date) else None),
            "source": "CISA KEV",
            "source_authority": "authoritative",
        }
        self.queries.append(record)
        return record


class Decision:
    """Uma decisao historica de fechar um achado.

    `classification` e obrigatorio e existe para tornar impossivel confundir
    uma decisao fabricada com uma decisao de analista real (briefing item 3).
    """

    def __init__(self, decision_id, cve_id, decided_at, reason, classification,
                 finding_ref=None, decided_by=None, notes=""):
        if classification not in ("REAL_EXTERNAL_DATA", "DERIVED_DATA", "SYNTHETIC_DATA"):
            raise ValueError(f"classification invalida: {classification!r}")
        self.decision_id = decision_id
        self.cve_id = str(cve_id).upper() if cve_id else None
        self.decided_at = as_date(decided_at)
        self.reason = reason
        self.classification = classification
        self.finding_ref = finding_ref
        self.decided_by = decided_by
        self.notes = notes

    def to_dict(self):
        return {"decision_id": self.decision_id, "cve_id": self.cve_id,
                "decided_at": self.decided_at.isoformat(), "reason": self.reason,
                "classification": self.classification, "finding_ref": self.finding_ref,
                "decided_by": self.decided_by, "notes": self.notes}


# --------------------------------------------------------------------------
# O motor
# --------------------------------------------------------------------------

# Vereditos
STILL_VALID = "STILL_VALID"
POTENTIALLY_OBSOLETE = "POTENTIALLY_OBSOLETE"
INVALID_AT_DECISION_TIME = "INVALID_AT_DECISION_TIME"
NOT_APPLICABLE = "NOT_APPLICABLE"
UNKNOWN_OUTSIDE_WINDOW = "UNKNOWN_OUTSIDE_WINDOW"


class ReLitigationEngine:
    def __init__(self, oracle):
        self.oracle = oracle

    def evaluate(self, decision, as_of_now, extra_events=()):
        """Uma decisao -> uma linha da matriz temporal (briefing item 10)."""
        now = as_date(as_of_now)
        d = decision.decided_at

        row = {
            "decision_id": decision.decision_id,
            "cve_id": decision.cve_id,
            "decision_date": d.isoformat(),
            "decision_reason": decision.reason,
            "decision_classification": decision.classification,
            "knowledge_as_of_decision": None,
            "external_event_kind": None,
            "external_event_date": None,
            "current_state": None,
            "decision_validity": None,
            "re_litigation_candidate": False,
            "reason": None,
            "evidence": [],
            "non_material_events_seen": [],
            "evidence_availability": "AVAILABLE",
        }

        if decision.reason not in DECISION_TO_NOT_ACT:
            row["decision_validity"] = NOT_APPLICABLE
            row["reason"] = ("fechado como corrigido: nao e uma decisao de nao agir, "
                             "nao ha divida de decisao a computar")
            return row

        # 1. O que se sabia NO DIA da decisao. Unica porta, e ela e cega ao futuro.
        knowledge = self.oracle.knowledge_as_of(decision.cve_id, d)
        row["knowledge_as_of_decision"] = knowledge

        # 2. O estado de hoje, explicitamente marcado como estado de hoje.
        current = self.oracle.kev.state_as_of(decision.cve_id, now)
        row["current_state"] = current
        added = self.oracle.kev.date_added(decision.cve_id)

        # 3. Eventos nao-materiais: contabilizados, nunca promovidos a gatilho.
        for ev in extra_events:
            if ev.kind in NON_MATERIAL_KINDS:
                row["non_material_events_seen"].append({
                    **ev.to_dict(), "suppressed_because": NON_MATERIAL_RATIONALE[ev.kind]})
            elif ev.kind == EVIDENCE_REMOVED:
                # Evidencia sumir nao cria candidato. Muda o que da para afirmar.
                row["evidence_availability"] = "EVIDENCE_MISSING"
                row["non_material_events_seen"].append({
                    **ev.to_dict(),
                    "suppressed_because": ("evidencia ausente muda evidence_availability; "
                                           "ausencia de evidencia nao e evidencia de mudanca")})

        # 4. O gatilho material.
        if knowledge["kev_state"] == "IN_KEV":
            # Ja estava no KEV quando foi fechado. Nao e divida de decisao --
            # e uma historia diferente e pior, e as duas nunca se somam.
            row["decision_validity"] = INVALID_AT_DECISION_TIME
            row["external_event_kind"] = KEV_LISTED
            row["external_event_date"] = knowledge["kev_date_added_if_known"]
            row["re_litigation_candidate"] = False
            row["reason"] = ("closed_despite: o CVE ja constava no KEV no dia do "
                             "fechamento. Nao e divida de decisao")
            row["evidence"] = [self._kev_evidence(decision.cve_id, added)]
            return row

        if added is not None and added > d:
            row["decision_validity"] = POTENTIALLY_OBSOLETE
            row["external_event_kind"] = KEV_LISTED
            row["external_event_date"] = added.isoformat()
            row["re_litigation_candidate"] = True
            row["reason"] = (f"o CVE entrou no CISA KEV em {added.isoformat()}, "
                             f"{(added - d).days} dias depois do fechamento")
            row["evidence"] = [self._kev_evidence(decision.cve_id, added)]
            return row

        if knowledge["kev_state"] == "UNKNOWN_OUTSIDE_WINDOW":
            row["decision_validity"] = UNKNOWN_OUTSIDE_WINDOW
            row["reason"] = ("o CVE nao aparece na janela de 12 meses deste catalogo. "
                             "Nao da para afirmar que nunca entrou no KEV")
            return row

        row["decision_validity"] = STILL_VALID
        row["reason"] = "nenhuma mudanca material desde o fechamento"
        return row

    def _kev_evidence(self, cve_id, added):
        e = self.oracle.kev.by_cve.get(str(cve_id).upper(), {})
        return {
            "evidence_type": "kev_listing",
            "source": "CISA KEV",
            "source_authority": "authoritative",
            "source_identifier": str(cve_id).upper(),
            "date_added": added.isoformat() if added else None,
            "known_ransomware": e.get("known_ransomware"),
            "vendor_project": e.get("vendor_project"),
            "product": e.get("product"),
            "classification": "REAL_EXTERNAL_DATA",
        }

    def run(self, decisions, as_of_now, events_by_decision=None):
        events_by_decision = events_by_decision or {}
        return [self.evaluate(d, as_of_now, events_by_decision.get(d.decision_id, ()))
                for d in decisions]


def build_engine():
    return ReLitigationEngine(KnowledgeOracle(KevCatalog.load()))
