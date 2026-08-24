"""
Persistencia. SQLite via SQLAlchemy: o objetivo e historico navegavel entre
execucoes, nao escala -- ADR-0003 (tenancy) e o schema completo em
docs/data/database-model.md descrevem o Postgres que a plataforma usaria.
Trocar o dialeto depois e uma mudanca de URL, nao de modelo.
"""

import json
import os
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Integer, String, Text, create_engine,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# SDIP_DB_PATH existe para o container apontar o banco para um volume; sem ele
# o comportamento local nao muda -- sdip.db na raiz do repositorio.
DB_PATH = os.environ.get("SDIP_DB_PATH") or os.path.join(BASE_DIR, "..", "sdip.db")
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
Base = declarative_base()


def utcnow():
    return datetime.now(timezone.utc)


class Analysis(Base):
    __tablename__ = "analyses"

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    source_name = Column(String(200), nullable=False)
    is_demo = Column(Boolean, default=False, nullable=False)

    total_rows = Column(Integer, nullable=False)
    analyzed = Column(Integer, nullable=False)
    excluded = Column(Integer, nullable=False)
    debt_count = Column(Integer, nullable=False)
    despite_count = Column(Integer, nullable=False)
    debt_ransomware = Column(Integer, nullable=False, default=0)
    despite_ransomware = Column(Integer, nullable=False, default=0)

    kev_version = Column(String(50))
    id_col = Column(String(120))
    date_col = Column(String(120))
    reason_col = Column(String(120))

    # Serializados: sao dados de apresentacao do resultado, nunca consultados
    # por campo. Normalizar aqui seria schema sem consumidor.
    piles_json = Column(Text, default="{}")
    exclusions_json = Column(Text, default="{}")

    items = relationship("DebtItem", back_populates="analysis",
                         cascade="all, delete-orphan", lazy="selectin")

    @property
    def piles(self):
        return json.loads(self.piles_json or "{}")

    @property
    def exclusions(self):
        return json.loads(self.exclusions_json or "{}")


class DebtItem(Base):
    __tablename__ = "debt_items"

    id = Column(Integer, primary_key=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id"), nullable=False, index=True)

    # "debt"    -> entrou na KEV DEPOIS do fechamento (o mundo mudou)
    # "despite" -> ja estava na KEV NO DIA do fechamento (pior, e outra historia)
    kind = Column(String(10), nullable=False, index=True)

    finding_id = Column(String(80))
    title = Column(String(200))
    cve = Column(String(30), index=True)
    closed_at = Column(DateTime, nullable=False)
    reason = Column(String(30), index=True)
    kev_added = Column(DateTime, nullable=False)
    days = Column(Integer, nullable=False)
    ransomware = Column(Boolean, default=False, nullable=False, index=True)
    vendor = Column(String(120))
    product = Column(String(120))
    in_session_sample = Column(Boolean, default=False, nullable=False)

    analysis = relationship("Analysis", back_populates="items")


def init_db():
    Base.metadata.create_all(engine)


def save_analysis(source_name, is_demo, summary, debt, despite, sample, excl):
    sample_keys = {(r["id"], r["cve"]) for r in sample}
    with SessionLocal() as s:
        a = Analysis(
            source_name=source_name,
            is_demo=is_demo,
            total_rows=summary["total_rows"],
            analyzed=summary["analyzed"],
            excluded=summary["excluded"],
            debt_count=summary["debt_count"],
            despite_count=summary["despite_count"],
            debt_ransomware=summary["debt_ransomware"],
            despite_ransomware=summary["despite_ransomware"],
            kev_version=summary["kev_version"],
            id_col=summary["id_col"],
            date_col=summary["date_col"],
            reason_col=summary["reason_col"],
            piles_json=json.dumps(summary["piles"]),
            exclusions_json=json.dumps(dict(excl)),
        )
        s.add(a)
        s.flush()

        for kind, rows in (("debt", debt), ("despite", despite)):
            for r in rows:
                s.add(DebtItem(
                    analysis_id=a.id,
                    kind=kind,
                    finding_id=r["id"],
                    title=r["title"],
                    cve=r["cve"],
                    closed_at=r["closed"],
                    reason=r["reason"],
                    kev_added=r["kev_added"],
                    days=r["days"],
                    ransomware=r["ransomware"],
                    vendor=str(r["kev_entry"].get("vendorProject", ""))[:120],
                    product=str(r["kev_entry"].get("product", ""))[:120],
                    in_session_sample=(r["id"], r["cve"]) in sample_keys,
                ))
        s.commit()
        return a.id
