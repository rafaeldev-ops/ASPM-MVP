"""
Vocabulario do dominio. Puro: sem I/O, sem framework, sem SQL.

Este arquivo existe principalmente por causa de B2 e B3.

O `phase0/v1_backtest.py` colapsava razoes de fechamento distintas por regex:
`Mitigated` virava `fixed` (e sumia do relatorio) e `Won't Fix` virava
`false_positive`. As duas estao erradas, e de formas diferentes:

  - **Mitigado nao e corrigido.** Um achado fechado porque existe um controle
    compensatorio e exatamente a decisao de NAO remediar. ADR-0016 diz que essa
    supressao e perecivel: o controle pode deixar de valer, ou o CVE pode entrar
    no KEV. Tratar como corrigido apaga o caso central do produto.

  - **Won't fix nao e falso positivo.** Um e "o problema e real e escolhemos
    conviver", o outro e "o problema nao existe". Confundi-los nao muda o total
    de divida, mas corrompe a divisao entre as pilhas -- que e a suposicao A4 de
    competitive-positioning.md, e que o protocolo diz nunca ter sido medida.

A distincao vive aqui, num so lugar, e o teste de regressao esta em
tests/test_closure_reasons.py.
"""

from enum import Enum


class ClosureReason(str, Enum):
    """Por que um achado foi fechado. Seis valores, nao tres."""

    FIXED = "fixed"
    MITIGATED = "mitigated"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"
    WONT_FIX = "wont_fix"
    UNKNOWN = "unknown"

    @property
    def is_decision_to_not_act(self):
        """A decisao de nao remediar. E o objeto do produto.

        `fixed` fica de fora porque nao ha decisao a re-litigar: o problema
        acabou. `unknown` fica de fora porque nao sabemos o que foi decidido, e
        tratar ignorancia como decisao inflaria o numero principal.
        """
        return self in (ClosureReason.MITIGATED, ClosureReason.ACCEPTED_RISK,
                        ClosureReason.FALSE_POSITIVE, ClosureReason.WONT_FIX)

    @property
    def is_perishable(self):
        """A supressao depende de um estado que pode mudar (ADR-0016).

        `false_positive` tambem e perecivel -- "nao se aplica" pode deixar de ser
        verdade quando a faixa afetada de um advisory e corrigida.
        """
        return self.is_decision_to_not_act

    @property
    def label(self):
        return {
            ClosureReason.FIXED: "Corrigido",
            ClosureReason.MITIGATED: "Mitigado (controle compensatorio)",
            ClosureReason.ACCEPTED_RISK: "Risco aceito",
            ClosureReason.FALSE_POSITIVE: "Falso positivo",
            ClosureReason.WONT_FIX: "Nao sera corrigido",
            ClosureReason.UNKNOWN: "Nao informado",
        }[self]


# Ordem importa: a primeira regra que casa vence, e as mais especificas vem
# antes. `mitigated` e testado ANTES de `fixed` porque "mitigated" contem
# palavras que a regra de corrigido tambem aceitaria -- foi exatamente assim que
# B2 nasceu.
_CLOSURE_RULES = [
    (ClosureReason.MITIGATED, (
        "mitigat", "mitigado", "compensating control", "controle compensatorio",
        "workaround", "contorno", "waf rule", "virtual patch")),
    (ClosureReason.ACCEPTED_RISK, (
        "risk accept", "accepted risk", "risco aceito", "aceitacao de risco",
        "exception", "excecao", "waiver", "deferred", "adiado", "risk_accepted")),
    (ClosureReason.WONT_FIX, (
        "won't fix", "wont fix", "wontfix", "will not fix", "nao sera corrigido",
        "no fix", "by design", "as designed", "por design", "out of scope",
        "fora de escopo")),
    (ClosureReason.FALSE_POSITIVE, (
        "false positive", "false-positive", "falso positivo", "not applicable",
        "nao se aplica", "invalid", "invalido", "not exploitable",
        "nao explorav", "used in tests", "test code", "dismissed", "no risk")),
    (ClosureReason.FIXED, (
        "fixed", "corrigido", "remediat", "patched", "patch aplicado",
        "resolved", "resolvido", "done", "upgraded", "atualizado")),
]


def classify_closure_reason(text):
    """Texto livre de export -> ClosureReason.

    Nao devolve `fixed` para "Mitigated", nem `false_positive` para "Won't Fix".
    Texto vazio ou desconhecido devolve UNKNOWN -- nunca um chute.
    """
    t = str(text or "").strip().lower()
    if not t:
        return ClosureReason.UNKNOWN
    for reason, needles in _CLOSURE_RULES:
        if any(n in t for n in needles):
            return reason
    return ClosureReason.UNKNOWN


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"

    @property
    def rank(self):
        return {"critical": 4, "high": 3, "medium": 2, "low": 1,
                "informational": 0}[self.value]


class Criticality(str, Enum):
    """Criticidade do ativo. DP4 em risk-model.md."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Exposure(str, Enum):
    """DP2. `not_deployed` foi adicionado por exp-002."""
    NOT_DEPLOYED = "not_deployed"
    UNKNOWN = "unknown"
    INTERNAL = "internal"
    CONTROLLED = "controlled"
    OPEN = "open"


class AssetType(str, Enum):
    REPOSITORY = "repository"
    APPLICATION = "application"
    SERVICE = "service"
    CONTAINER = "container"
    DEPENDENCY = "dependency"
    HOST = "host"
    API = "api"
    CLOUD_RESOURCE = "cloud_resource"


class FindingStatus(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    REOPENED = "reopened"


class Band(str, Enum):
    """Bandas de risk-model.md 4.2, na ordem de urgencia."""
    ACT_NOW = "act_now"
    ACT_SOON = "act_soon"
    SCHEDULED = "scheduled"
    TRACK = "track"
    DEPRIORITIZE_CANDIDATE = "deprioritize_candidate"

    @property
    def rank(self):
        return {"act_now": 0, "act_soon": 1, "scheduled": 2,
                "track": 3, "deprioritize_candidate": 4}[self.value]

    @property
    def label(self):
        return {"act_now": "Agir agora", "act_soon": "Agir em breve",
                "scheduled": "Agendado", "track": "Acompanhar",
                "deprioritize_candidate": "Candidato a despriorizar"}[self.value]


class RemediationConfidence(str, Enum):
    """Quanto se pode confiar na orientacao de correcao (briefing 9)."""
    VERIFIED = "verified"        # advisory do fornecedor com versao corrigida
    RECOMMENDED = "recommended"  # derivado de fonte autoritativa
    HISTORICAL = "historical"    # a organizacao ja resolveu assim antes
    UNCERTAIN = "uncertain"      # nao ha fonte; diga isso, nao invente

    @property
    def label(self):
        return {"verified": "Verificado", "recommended": "Recomendado",
                "historical": "Historico", "uncertain": "Incerto"}[self.value]


class EvidenceClass(str, Enum):
    REAL_EXTERNAL = "REAL_EXTERNAL_DATA"
    DERIVED = "DERIVED_DATA"
    SYNTHETIC = "SYNTHETIC_DATA"


class ChangeKind(str, Enum):
    """O que o monitoramento continuo detecta (briefing 10)."""
    FINDING_NEW = "finding_new"
    FINDING_CLOSED = "finding_closed"
    FINDING_REOPENED = "finding_reopened"
    SEVERITY_CHANGED = "severity_changed"
    KEV_LISTED = "kev_listed"
    ADVISORY_CHANGED = "advisory_changed"
    ASSET_CONTEXT_CHANGED = "asset_context_changed"
    DECISION_POTENTIALLY_STALE = "decision_potentially_stale"

    @property
    def is_material(self):
        """Materialidade decide se a mudanca pode acordar uma decisao.

        EPSS nao esta nesta lista e nao esta no enum: EXP-001 e EXP-004 mediram
        que um deslocamento de score move dezenas de milhares de CVEs sem que
        nada tenha mudado no mundo. EPSS e sinal contextual, nunca gatilho.
        """
        return self in (ChangeKind.KEV_LISTED, ChangeKind.ADVISORY_CHANGED,
                        ChangeKind.SEVERITY_CHANGED, ChangeKind.FINDING_REOPENED,
                        ChangeKind.ASSET_CONTEXT_CHANGED)

    @property
    def label(self):
        return {
            "finding_new": "Novo achado", "finding_closed": "Achado fechado",
            "finding_reopened": "Achado reaberto", "severity_changed": "Severidade mudou",
            "kev_listed": "Entrou no CISA KEV", "advisory_changed": "Advisory mudou",
            "asset_context_changed": "Contexto do ativo mudou",
            "decision_potentially_stale": "Decisao potencialmente obsoleta",
        }[self.value]
