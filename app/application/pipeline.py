"""
O pipeline ASPM ponta a ponta.

    Asset Discovery -> Finding Ingestion -> Risk Correlation ->
    Prioritization -> Evidence/Context -> Remediation Guidance ->
    Continuous Monitoring -> Analyst Review

Uma funcao roda o fluxo inteiro sobre um lote importado. A ordem importa e nao e
arbitraria: correlacao antes de priorizacao (o grupo alimenta o precedente
historico), enriquecimento antes de priorizacao (o KEV move DP1), e
monitoramento depois de tudo (compara contra o estado capturado ANTES).
"""

from app.application import (
    correlation, decision_debt, ingestion, monitoring, prioritization, remediation,
)
from app.domain.models import DEFAULT_ORG


def run_import(session, rows, source_system, label, org_id=DEFAULT_ORG,
               discover_assets=True, asset_rows=None):
    """Importa um lote e roda o pipeline inteiro sobre ele."""
    # A fotografia do antes tem que sair primeiro, senao nao ha o que comparar.
    previous = monitoring.capture_state(session, org_id)
    snapshot = ingestion.start_snapshot(session, label, source_system, org_id)

    assets_result = {"created": 0, "updated": 0}
    if asset_rows:
        assets_result = ingestion.import_assets(session, asset_rows,
                                                source_system, org_id)

    ingest_result = ingestion.import_findings(
        session, rows, source_system, snapshot, org_id, discover_assets)

    corr = correlation.correlate(session, org_id)
    enrich = correlation.enrich(session, org_id)
    prio = prioritization.prioritize_all(session, org_id)
    rem = remediation.generate_all(session, org_id)

    changes = monitoring.detect_changes(session, snapshot,
                                        ingest_result["seen_ids"], previous, org_id)
    kev_changes = monitoring.detect_kev_changes(session, org_id)
    debt = decision_debt.scan(session, org_id)

    from sqlalchemy import func, select
    from app.domain.models import Asset
    snapshot.assets_seen = session.scalar(
        select(func.count(Asset.id)).where(Asset.org_id == org_id)) or 0

    session.commit()
    return {
        "snapshot_id": snapshot.id,
        "assets": assets_result,
        "ingestion": {k: v for k, v in ingest_result.items() if k != "seen_ids"},
        "correlation": corr,
        "enrichment": enrich,
        "prioritization": prio,
        "remediation": rem,
        "changes": {k: v for k, v in changes.items() if v},
        "kev_events": kev_changes["kev_events"],
        "decision_debt": {k: v for k, v in debt.items() if k != "rows"},
    }


def reprocess(session, org_id=DEFAULT_ORG):
    """Recomputa correlacao, priorizacao, remediacao e divida sem reimportar.

    Serve para quando o conhecimento externo mudou (novo catalogo KEV) mas os
    achados nao -- que e exatamente o caso que gera divida de decisao.
    """
    corr = correlation.correlate(session, org_id)
    enrich = correlation.enrich(session, org_id)
    prio = prioritization.prioritize_all(session, org_id)
    rem = remediation.generate_all(session, org_id)
    kev_changes = monitoring.detect_kev_changes(session, org_id)
    debt = decision_debt.scan(session, org_id)
    session.commit()
    return {"correlation": corr, "enrichment": enrich, "prioritization": prio,
            "remediation": rem, "kev_events": kev_changes["kev_events"],
            "decision_debt": {k: v for k, v in debt.items() if k != "rows"}}
