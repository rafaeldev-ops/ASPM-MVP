"""
Modelo de persistencia do MVP ASPM.

Compartilha o mesmo `Base` e a mesma engine de `app/db.py` -- o backtest legado
e o ASPM vivem no mesmo SQLite, e nenhuma tabela existente foi alterada.

`org_id` esta em toda tabela desde a primeira migration, com um default de
tenant unico. O MVP nao implementa multi-tenancy (nao ha auth), mas ADR-0003 e
explicito: retrofitar tenancy custa ~4 meses-engenheiro contra ~2 semanas agora,
e a coluna e a parte que nao da para acrescentar depois sem reescrever o dado.
Colocar a coluna agora nao e construir a feature; e nao inviabilizar a feature.

`first_seen` / `last_seen` existem em Asset e Finding porque o monitoramento
continuo depende deles e eles sao impossiveis de reconstruir retroativamente.
"""

import json
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey, Index, Integer, String, Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from app.db import Base

DEFAULT_ORG = "org-local"


def utcnow():
    return datetime.now(timezone.utc)


class JsonMixin:
    """Campos JSON serializados. Sao dados de apresentacao/proveniencia, nunca
    consultados por campo -- normalizar aqui seria schema sem consumidor."""

    @staticmethod
    def _load(raw, default):
        try:
            return json.loads(raw) if raw else default
        except (ValueError, TypeError):
            return default


class Asset(Base, JsonMixin):
    """O ativo afetado. Responde 'qual ativo?' e 'qual a criticidade dele?'."""

    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("org_id", "identifier", name="uq_asset_org_identifier"),
        Index("ix_asset_org_criticality", "org_id", "criticality"),
    )

    id = Column(Integer, primary_key=True)
    org_id = Column(String(60), nullable=False, default=DEFAULT_ORG, index=True)

    # Chave natural estavel vinda da fonte (ex: "github.com/owner/repo").
    identifier = Column(String(300), nullable=False)
    name = Column(String(300), nullable=False)
    type = Column(String(40), nullable=False)
    owner = Column(String(200))
    criticality = Column(String(20))          # NULL = nao resolvido -> falha fechado
    environment = Column(String(30))          # prod | staging | dev | unknown
    repository = Column(String(300))
    exposure = Column(String(30))             # DP2
    internet_facing = Column(Boolean)
    status = Column(String(30), default="active", nullable=False)
    source_system = Column(String(80), nullable=False)
    tags_json = Column(Text, default="[]")

    first_seen = Column(DateTime, default=utcnow, nullable=False)
    last_seen = Column(DateTime, default=utcnow, nullable=False)

    findings = relationship("Finding", back_populates="asset", lazy="selectin")

    @property
    def tags(self):
        return self._load(self.tags_json, [])

    @property
    def criticality_resolved(self):
        return self.criticality is not None


class Finding(Base, JsonMixin):
    """Um achado normalizado, de qualquer fonte."""

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("org_id", "fingerprint", name="uq_finding_org_fingerprint"),
        Index("ix_finding_org_band", "org_id", "band"),
        Index("ix_finding_org_status", "org_id", "status"),
    )

    id = Column(Integer, primary_key=True)
    org_id = Column(String(60), nullable=False, default=DEFAULT_ORG, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), index=True)
    group_id = Column(Integer, ForeignKey("finding_groups.id"), index=True)

    fingerprint = Column(String(64), nullable=False)
    source_system = Column(String(80), nullable=False)
    source_finding_id = Column(String(200))
    source_rule_id = Column(String(200))

    title = Column(String(400), nullable=False)
    description = Column(Text)
    severity = Column(String(20))
    cve = Column(String(30), index=True)
    cwe_json = Column(Text, default="[]")
    package_name = Column(String(200))
    package_version = Column(String(80))
    fixed_version = Column(String(80))
    file_path = Column(String(500))
    line = Column(Integer)

    cvss_base = Column(Float)
    epss_score = Column(Float)
    epss_percentile = Column(Float)

    status = Column(String(20), default="open", nullable=False)
    first_seen = Column(DateTime, default=utcnow, nullable=False)
    last_seen = Column(DateTime, default=utcnow, nullable=False)
    closed_at = Column(DateTime)

    # Saida do motor deterministico. Versionada para uma mudanca de modelo ser
    # visivel em vez de silenciosa.
    band = Column(String(30), index=True)
    ordering_score = Column(Float)
    risk_model_version = Column(String(60))
    assessment_json = Column(Text, default="{}")

    raw_json = Column(Text, default="{}")

    # Carregamento ansioso: as telas de lista renderizam o ativo e o grupo DEPOIS
    # que a sessao fecha. Com lazy load isso vira DetachedInstanceError na
    # template, que e um erro de tempo de execucao dificil de ver em teste de
    # unidade -- resolver na relacao e mais seguro que lembrar em cada rota.
    asset = relationship("Asset", back_populates="findings", lazy="selectin")
    group = relationship("FindingGroup", back_populates="findings", lazy="selectin")
    evidence = relationship("Evidence", back_populates="finding",
                            cascade="all, delete-orphan", lazy="selectin")
    decisions = relationship("Decision", back_populates="finding",
                             cascade="all, delete-orphan", lazy="selectin")

    @property
    def cwes(self):
        return self._load(self.cwe_json, [])

    @property
    def assessment(self):
        return self._load(self.assessment_json, {})

    @property
    def raw(self):
        return self._load(self.raw_json, {})

    @property
    def current_decision(self):
        """A decisao vigente. Decisoes sao append-only (ADR-0001): a atual e a
        ultima, e as anteriores continuam existindo."""
        if not self.decisions:
            return None
        return sorted(self.decisions, key=lambda d: (d.decided_at, d.id))[-1]


class FindingGroup(Base):
    """Achados que sao o mesmo problema, de fontes ou locais diferentes.

    Agrupar nao apaga: cada Finding continua existindo com sua proveniencia, e
    `correlation_basis` registra POR QUE foram agrupados, para a re-correlacao
    ser possivel quando o algoritmo melhorar (CLAUDE.md 25).
    """

    __tablename__ = "finding_groups"

    id = Column(Integer, primary_key=True)
    org_id = Column(String(60), nullable=False, default=DEFAULT_ORG, index=True)
    group_key = Column(String(200), nullable=False, index=True)
    correlation_basis = Column(String(60), nullable=False)
    title = Column(String(400))
    member_count = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    findings = relationship("Finding", back_populates="group", lazy="selectin")


class Evidence(Base, JsonMixin):
    """Evidencia com proveniencia. CLAUDE.md 8."""

    __tablename__ = "evidence"
    __table_args__ = (Index("ix_evidence_finding_type", "finding_id", "evidence_type"),)

    id = Column(Integer, primary_key=True)
    org_id = Column(String(60), nullable=False, default=DEFAULT_ORG, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False, index=True)

    evidence_type = Column(String(60), nullable=False)
    source = Column(String(120), nullable=False)
    source_id = Column(String(200))
    source_url = Column(String(600))
    source_authority = Column(String(30), default="authoritative", nullable=False)
    classification = Column(String(30), nullable=False)

    content = Column(Text)
    content_hash = Column(String(64))
    retrieved_at = Column(DateTime, default=utcnow, nullable=False)
    # Data do FATO (ex: dateAdded do KEV), distinta de quando nos lemos.
    observed_at = Column(DateTime)
    freshness_note = Column(String(300))

    finding = relationship("Finding", back_populates="evidence")


class Decision(Base, JsonMixin):
    """Uma decisao sobre um achado. Append-only: revisar cria uma nova.

    `classification` separa decisao real de decisao fabricada. E obrigatoria por
    construcao para tornar impossivel apresentar dado sintetico como historico
    de cliente.
    """

    __tablename__ = "decisions"
    __table_args__ = (Index("ix_decision_org_reason", "org_id", "reason"),)

    id = Column(Integer, primary_key=True)
    org_id = Column(String(60), nullable=False, default=DEFAULT_ORG, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False, index=True)

    reason = Column(String(30), nullable=False)          # ClosureReason
    rationale = Column(Text)
    decided_at = Column(DateTime, default=utcnow, nullable=False)
    decided_by = Column(String(120))
    classification = Column(String(30), nullable=False)  # REAL/DERIVED/SYNTHETIC
    source_system = Column(String(80))

    # Estado do mundo no momento da decisao. Sem isto nao ha divida de decisao:
    # e a fotografia contra a qual o "depois" e comparado.
    knowledge_snapshot_json = Column(Text, default="{}")

    supersedes_id = Column(Integer, ForeignKey("decisions.id"))
    is_review = Column(Boolean, default=False, nullable=False)

    # Concordancia analista x modelo. Gravada no momento da decisao porque e
    # impossivel de reconstruir depois: quando a analise que sugeriu esta razao
    # for uma entre varias no historico do achado, ninguem consegue dizer qual
    # delas o analista tinha na tela. Nulo quando a decisao nao veio de sugestao
    # nenhuma -- que e o caso padrao, e precisa continuar distinguivel de
    # "veio de sugestao e o analista concordou".
    ai_analysis_id = Column(Integer, ForeignKey("ai_analyses.id"))
    ai_suggested_reason = Column(String(30))

    finding = relationship("Finding", back_populates="decisions", foreign_keys=[finding_id])

    @property
    def agreed_with_ai(self):
        """`True`, `False` ou `None` -- e os tres significam coisas diferentes.

        `None` nao e "discordou": e "nao havia sugestao". Colapsar os dois
        arruinaria a taxa de concordancia, que e a metrica pela qual esta coluna
        existe (CLAUDE.md §31).
        """
        if not self.ai_suggested_reason:
            return None
        return self.reason == self.ai_suggested_reason

    @property
    def knowledge_snapshot(self):
        return self._load(self.knowledge_snapshot_json, {})


class DecisionDebt(Base, JsonMixin):
    """Uma decisao que o mundo pode ter invalidado."""

    __tablename__ = "decision_debt"

    id = Column(Integer, primary_key=True)
    org_id = Column(String(60), nullable=False, default=DEFAULT_ORG, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False, index=True)
    decision_id = Column(Integer, ForeignKey("decisions.id"), nullable=False)

    trigger = Column(String(60), nullable=False)
    detected_at = Column(DateTime, default=utcnow, nullable=False)
    event_date = Column(DateTime)
    days_after_decision = Column(Integer)

    validity = Column(String(40), nullable=False)
    explanation = Column(Text)
    evidence_ids_json = Column(Text, default="[]")

    resolved = Column(Boolean, default=False, nullable=False)
    resolved_at = Column(DateTime)
    resolution_decision_id = Column(Integer, ForeignKey("decisions.id"))

    finding = relationship("Finding", foreign_keys=[finding_id])
    decision = relationship("Decision", foreign_keys=[decision_id])

    @property
    def evidence_ids(self):
        return self._load(self.evidence_ids_json, [])


class Remediation(Base, JsonMixin):
    """Orientacao de correcao. Nunca inventada: sempre com fonte e confianca."""

    __tablename__ = "remediations"

    id = Column(Integer, primary_key=True)
    org_id = Column(String(60), nullable=False, default=DEFAULT_ORG, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False, index=True)

    confidence = Column(String(20), nullable=False)   # RemediationConfidence
    action = Column(Text, nullable=False)
    detail = Column(Text)
    source = Column(String(200))
    source_url = Column(String(600))
    evidence_ids_json = Column(Text, default="[]")
    generated_by = Column(String(60), default="deterministic", nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    finding = relationship("Finding")

    @property
    def evidence_ids(self):
        return self._load(self.evidence_ids_json, [])


class ScanSnapshot(Base, JsonMixin):
    """Uma importacao. O monitoramento continuo compara snapshots."""

    __tablename__ = "scan_snapshots"

    id = Column(Integer, primary_key=True)
    org_id = Column(String(60), nullable=False, default=DEFAULT_ORG, index=True)
    label = Column(String(200), nullable=False)
    source_system = Column(String(80), nullable=False)
    taken_at = Column(DateTime, default=utcnow, nullable=False)

    assets_seen = Column(Integer, default=0, nullable=False)
    findings_seen = Column(Integer, default=0, nullable=False)
    findings_new = Column(Integer, default=0, nullable=False)
    findings_closed = Column(Integer, default=0, nullable=False)
    findings_reopened = Column(Integer, default=0, nullable=False)

    knowledge_versions_json = Column(Text, default="{}")

    @property
    def knowledge_versions(self):
        return self._load(self.knowledge_versions_json, {})


class Setting(Base, JsonMixin):
    """Configuracao persistida, uma linha por chave.

    Linha por chave em vez de tabela larga de proposito: acrescentar um ajuste
    depois nao exige `ALTER TABLE`, o que importa muito quando o banco ja e dado
    instalado na maquina de alguem.

    **Segredo nunca entra aqui.** A configuracao guarda uma *referencia*
    (`ai.key_ref`); a chave vive no cofre de credenciais do sistema
    (`app/infrastructure/credentials.py`). E a mesma regra da ADR-0011 §5: token
    e somente-escrita, nenhum endpoint jamais devolve um.
    """

    __tablename__ = "settings"
    __table_args__ = (UniqueConstraint("org_id", "key", name="uq_setting_org_key"),)

    id = Column(Integer, primary_key=True)
    org_id = Column(String(60), nullable=False, default=DEFAULT_ORG, index=True)
    key = Column(String(80), nullable=False)
    value_json = Column(Text)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    updated_by = Column(String(120))

    @property
    def value(self):
        return self._load(self.value_json, None)


class AIAnalysis(Base, JsonMixin):
    """Uma execucao de analise por modelo.

    Serve a dois propositos ao mesmo tempo: e o resultado que a tela mostra e o
    registro de observabilidade. Append-only por convencao (ADR-0001):
    reanalisar insere, nunca atualiza.

    **Analise que falhou tambem e gravada.** Um provider que recusa 40% de um
    corpus de seguranca precisa ser visivel, e a ADR-0015 §2 diz que taxa de
    recusa pode ser o criterio que decide o fornecedor. Registrar so sucesso
    destrói exatamente essa metrica.

    O que NUNCA entra: texto do prompt, resposta alem dos campos validados, a
    chave, qualquer valor de segredo casado pelo detector, `raw_json`, caminho
    de arquivo completo.
    """

    __tablename__ = "ai_analyses"
    __table_args__ = (
        Index("ix_ai_org_finding", "org_id", "finding_id"),
        Index("ix_ai_org_outcome", "org_id", "outcome"),
    )

    id = Column(Integer, primary_key=True)
    org_id = Column(String(60), nullable=False, default=DEFAULT_ORG, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False, index=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    outcome = Column(String(30), nullable=False)

    # Proveniencia emitida pelo SISTEMA, nunca pelo modelo. Se estes campos
    # estivessem no schema de saida, o modelo poderia mentir sobre a propria
    # identidade e o registro deixaria de valer como auditoria.
    provider = Column(String(40), nullable=False)
    model = Column(String(120))
    egress = Column(String(20), nullable=False)
    redaction_tier = Column(String(20), nullable=False)
    key_source = Column(String(20))

    prompt_version = Column(String(40))
    prompt_hash = Column(String(16))
    context_schema_version = Column(String(40))
    context_hash = Column(String(16))
    analysis_version = Column(String(120))

    # Prova que o modelo nao mexeu na banda: o valor deterministico e gravado
    # junto, e um teste afirma que nenhum outcome o altera.
    deterministic_band = Column(String(30))
    risk_model_version = Column(String(60))

    confidence = Column(Float)
    confidence_model_version = Column(String(60))

    latency_ms = Column(Integer)
    attempts = Column(Integer, default=1, nullable=False)
    tokens_in = Column(Integer)
    tokens_out = Column(Integer)
    estimated_cost_usd = Column(Float)

    summary = Column(Text)
    risk_explanation = Column(Text)
    recommended_action = Column(Text)
    suggested_reason = Column(String(30))

    evidence_ids_json = Column(Text, default="[]")
    contradicting_evidence_ids_json = Column(Text, default="[]")
    uncertainty_reasons_json = Column(Text, default="[]")
    evidence_gaps_json = Column(Text, default="[]")
    evidence_dropped_json = Column(Text, default="[]")
    # Campo + detector + contagem. NUNCA o valor casado.
    redactions_json = Column(Text, default="[]")

    contains_synthetic = Column(Boolean, default=False, nullable=False)
    error_detail = Column(String(300))

    finding = relationship("Finding")

    @property
    def evidence_ids(self):
        return self._load(self.evidence_ids_json, [])

    @property
    def contradicting_evidence_ids(self):
        return self._load(self.contradicting_evidence_ids_json, [])

    @property
    def uncertainty_reasons(self):
        return self._load(self.uncertainty_reasons_json, [])

    @property
    def evidence_gaps(self):
        return self._load(self.evidence_gaps_json, [])

    @property
    def evidence_dropped(self):
        return self._load(self.evidence_dropped_json, [])

    @property
    def redactions(self):
        return self._load(self.redactions_json, [])

    @property
    def ok(self):
        return self.outcome in ("ok", "ok_degraded")

    @property
    def confidence_band(self):
        """Faixa, nao numero solto.

        A ADR-0010 §2 e explicita: nunca renderizar confianca como numero cru
        para um humano. A faixa vem com os insumos a vista na tela.
        """
        c = self.confidence
        if c is None:
            return "desconhecida"
        if c >= 0.75:
            return "alta"
        if c >= 0.45:
            return "media"
        return "baixa"


class ChangeEvent(Base, JsonMixin):
    """A linha do tempo. Alimenta a divida de decisao."""

    __tablename__ = "change_events"
    __table_args__ = (Index("ix_change_org_at", "org_id", "occurred_at"),)

    id = Column(Integer, primary_key=True)
    org_id = Column(String(60), nullable=False, default=DEFAULT_ORG, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), index=True)
    snapshot_id = Column(Integer, ForeignKey("scan_snapshots.id"), index=True)

    kind = Column(String(60), nullable=False, index=True)
    occurred_at = Column(DateTime, default=utcnow, nullable=False)
    detected_at = Column(DateTime, default=utcnow, nullable=False)
    is_material = Column(Boolean, default=False, nullable=False)
    summary = Column(Text)
    old_value = Column(String(200))
    new_value = Column(String(200))
    source = Column(String(120))

    finding = relationship("Finding")
    asset = relationship("Asset")
