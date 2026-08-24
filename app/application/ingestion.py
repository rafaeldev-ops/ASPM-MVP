"""
Ingestao: Asset Discovery + Finding Ingestion.

Aceita o que uma organizacao consegue exportar sem projeto de integracao:
CSV, JSON, SARIF do CodeQL, e o formato canonico do proprio MVP. Descoberta
automatica de infraestrutura esta fora do MVP de proposito.

Duas regras que o codigo abaixo respeita:

  - **Nada do original e destruido** (CLAUDE.md 24). `raw_json` guarda a linha
    inteira da fonte, mesmo os campos que o modelo canonico nao representa.
  - **Campo ausente e None, nunca inferido.** Se o export nao diz a criticidade
    do ativo, ela fica nula -- e o modelo de risco falha fechado tratando nulo
    como critico, em vez de inventar "medium".

A ingestao e idempotente por `fingerprint`: reimportar o mesmo export atualiza
`last_seen` em vez de duplicar. E isso que torna o monitoramento continuo
possivel sem uma tabela de deduplicacao a parte.
"""

import csv
import hashlib
import io
import json
import re
import zipfile
from datetime import datetime, timezone

from sqlalchemy import select

from app.domain.enums import AssetType, ClosureReason, classify_closure_reason
from app.domain.models import DEFAULT_ORG, Asset, Finding, ScanSnapshot

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
CWE_RE = re.compile(r"CWE-(\d+)", re.I)

DATE_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d/%m/%Y %H:%M", "%d/%m/%Y",
                "%m/%d/%Y %H:%M", "%m/%d/%Y", "%d-%b-%Y", "%d %b %Y",
                "%b %d, %Y", "%Y/%m/%d", "%d.%m.%Y")

SEVERITY_MAP = {
    "critical": "critical", "crit": "critical", "error": "high", "high": "high",
    "warning": "medium", "medium": "medium", "moderate": "medium", "note": "low",
    "low": "low", "info": "informational", "informational": "informational",
}


def utcnow():
    return datetime.now(timezone.utc)


def parse_date(s):
    if not s:
        return None
    s = str(s).strip()
    if not s or s.lower() in ("none", "null", "n/a", "-", ""):
        return None
    s = re.sub(r"(Z|[+-]\d{2}:?\d{2})$", "", s.split(".")[0]).strip().replace("T", " ")
    for fmt in DATE_FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def normalize_severity(v):
    return SEVERITY_MAP.get(str(v or "").strip().lower())


def fingerprint_of(*parts):
    return hashlib.sha256("|".join(str(p or "") for p in parts).encode()).hexdigest()[:48]


def _flatten(o, prefix=""):
    out = {}
    if isinstance(o, dict):
        for k, v in o.items():
            out.update(_flatten(v, f"{prefix}{k}."))
    elif isinstance(o, list):
        out[prefix[:-1]] = " ".join(str(x) for x in o if not isinstance(x, (dict, list)))
        for i, v in enumerate(o[:5]):
            if isinstance(v, (dict, list)):
                out.update(_flatten(v, f"{prefix}{i}."))
    else:
        out[prefix[:-1]] = o
    return out


def parse_tabular(raw, is_json):
    """CSV ou JSON -> lista de dicionarios planos."""
    if is_json:
        d = json.loads(raw)
        if isinstance(d, dict):
            for k in ("results", "findings", "alerts", "issues", "value",
                      "data", "assets", "records"):
                if isinstance(d.get(k), list):
                    d = d[k]
                    break
        rows = [_flatten(x) if isinstance(x, (dict, list)) else {"value": x} for x in d] \
            if isinstance(d, list) else []
    else:
        try:
            dialect = csv.Sniffer().sniff(raw[:8192], delimiters=",;\t") \
                if len(raw) > 32 else csv.excel
        except csv.Error:
            dialect = csv.excel
        rows = list(csv.DictReader(io.StringIO(raw), dialect=dialect))
    return [{(k or "").strip(): v for k, v in r.items()} for r in rows if r]


def _pick(row, *names):
    """Primeiro campo presente, comparando por nome normalizado."""
    norm = {re.sub(r"[^a-z0-9]", "", (k or "").lower()): v for k, v in row.items()}
    for n in names:
        key = re.sub(r"[^a-z0-9]", "", n.lower())
        if key in norm and str(norm[key]).strip():
            return norm[key]
    return None


# --------------------------------------------------------------------------
# Asset Discovery
# --------------------------------------------------------------------------

def upsert_asset(session, identifier, name=None, type_=None, org_id=DEFAULT_ORG, **kw):
    """Cria ou atualiza um ativo. Idempotente por (org_id, identifier).

    Atualizar NUNCA apaga um valor conhecido com None: um export mais pobre que
    o anterior nao deve degradar o que ja se sabia sobre o ativo.
    """
    asset = session.scalars(
        select(Asset).where(Asset.org_id == org_id, Asset.identifier == identifier)
    ).first()
    now = utcnow()
    if asset is None:
        asset = Asset(
            org_id=org_id, identifier=identifier, name=name or identifier,
            type=type_ or AssetType.REPOSITORY.value,
            source_system=kw.pop("source_system", "manual"),
            first_seen=now, last_seen=now)
        session.add(asset)
    else:
        asset.last_seen = now
        if name:
            asset.name = name
        if type_:
            asset.type = type_
    for field in ("owner", "criticality", "environment", "repository",
                  "exposure", "internet_facing", "status"):
        v = kw.get(field)
        if v is not None:
            setattr(asset, field, v)
    if "tags" in kw and kw["tags"] is not None:
        asset.tags_json = json.dumps(kw["tags"])
    return asset


def import_assets(session, rows, source_system="csv", org_id=DEFAULT_ORG):
    """Importa ativos de linhas tabulares."""
    created, updated = 0, 0
    for row in rows:
        identifier = _pick(row, "identifier", "id", "asset_id", "repository",
                           "repo", "name", "asset", "service")
        if not identifier:
            continue
        identifier = str(identifier).strip()
        existed = session.scalars(
            select(Asset).where(Asset.org_id == org_id,
                                Asset.identifier == identifier)).first() is not None

        internet = _pick(row, "internet_facing", "internetfacing", "public", "exposed")
        internet_bool = None
        if internet is not None:
            internet_bool = str(internet).strip().lower() in ("true", "1", "yes", "sim", "y")

        upsert_asset(
            session, identifier,
            name=_pick(row, "name", "asset", "service", "application") or identifier,
            type_=(str(_pick(row, "type", "asset_type", "kind") or
                       AssetType.REPOSITORY.value).strip().lower()),
            org_id=org_id, source_system=source_system,
            owner=_pick(row, "owner", "team", "responsible", "dono"),
            criticality=(str(_pick(row, "criticality", "critical", "importance",
                                   "business_criticality") or "").strip().lower() or None),
            environment=(str(_pick(row, "environment", "env", "stage") or
                             "").strip().lower() or None),
            repository=_pick(row, "repository", "repo", "git", "url"),
            exposure=(str(_pick(row, "exposure") or "").strip().lower() or None),
            internet_facing=internet_bool,
        )
        if existed:
            updated += 1
        else:
            created += 1
    session.flush()
    return {"created": created, "updated": updated}


def asset_for_finding(session, row, source_system, org_id=DEFAULT_ORG):
    """Descobre o ativo a partir do proprio achado.

    E aqui que Asset Discovery acontece na pratica no MVP: a maior parte dos
    exports de scanner nomeia o repositorio ou o servico, e criar o ativo a
    partir disso e o que evita exigir um inventario que a organizacao
    provavelmente nao tem.
    """
    ident = _pick(row, "repository", "repo", "project", "asset", "service",
                  "component", "application")
    if not ident:
        return None
    ident = str(ident).strip()
    return upsert_asset(session, ident, name=ident,
                        type_=AssetType.REPOSITORY.value,
                        org_id=org_id, source_system=source_system,
                        repository=ident)


# --------------------------------------------------------------------------
# Finding Ingestion
# --------------------------------------------------------------------------

def _finding_from_row(row, source_system):
    blob = " ".join(str(v) for v in row.values() if v is not None)
    cves = sorted({m.upper() for m in CVE_RE.findall(blob)})
    cwes = sorted({f"CWE-{m}" for m in CWE_RE.findall(blob)},
                  key=lambda c: int(c.split("-")[1]))

    title = (_pick(row, "title", "name", "summary", "vulnerabilityname", "rule",
                   "message", "description") or (cves[0] if cves else "achado sem titulo"))
    return {
        "source_finding_id": _pick(row, "id", "key", "finding_id", "alert_number",
                                   "number", "issue"),
        "source_rule_id": _pick(row, "rule_id", "ruleid", "rule", "check_id", "test"),
        "title": str(title)[:400],
        "description": (_pick(row, "description", "shortdescription", "details",
                              "message") or None),
        "severity": normalize_severity(_pick(row, "severity", "level", "risk",
                                             "priority", "criticality")),
        "cve": cves[0] if cves else None,
        "cwes": cwes,
        "package_name": _pick(row, "package", "package_name", "component",
                              "library", "dependency"),
        "package_version": _pick(row, "version", "package_version",
                                 "installed_version", "current_version"),
        "fixed_version": _pick(row, "fixed_version", "fix_version", "fixedin",
                               "remediation_version", "patched_version"),
        "file_path": _pick(row, "file", "path", "file_path", "location"),
        "line": _to_int(_pick(row, "line", "line_number", "startline")),
        "cvss_base": _to_float(_pick(row, "cvss", "cvss_base", "cvss_score",
                                     "cvssv3", "base_score")),
        "closed_at": parse_date(_pick(row, "closed_date", "closeddate", "closed_at",
                                      "resolved_date", "resolution_date",
                                      "mitigated", "date_closed")),
        "closure_text": _pick(row, "resolution", "reason", "status", "state",
                              "disposition", "justification", "verdict"),
        "raw": row,
    }


def _to_int(v):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _to_float(v):
    try:
        return float(str(v).strip())
    except (TypeError, ValueError):
        return None


def import_findings(session, rows, source_system, snapshot=None,
                    org_id=DEFAULT_ORG, discover_assets=True):
    """Importa achados. Idempotente por fingerprint.

    Devolve os ids tocados para o monitoramento saber o que estava presente
    neste import -- e, por diferenca, o que sumiu.
    """
    seen_ids, created, updated = [], 0, 0
    now = utcnow()

    for row in rows:
        data = _finding_from_row(row, source_system)
        asset = asset_for_finding(session, row, source_system, org_id) \
            if discover_assets else None

        fp = fingerprint_of(source_system, data["source_rule_id"] or data["title"],
                            data["cve"], data["file_path"], data["package_name"],
                            asset.identifier if asset else data["source_finding_id"])

        f = session.scalars(select(Finding).where(
            Finding.org_id == org_id, Finding.fingerprint == fp)).first()

        if f is None:
            f = Finding(org_id=org_id, fingerprint=fp, source_system=source_system,
                        title=data["title"], first_seen=now, last_seen=now)
            session.add(f)
            created += 1
        else:
            f.last_seen = now
            updated += 1

        f.asset = asset
        f.source_finding_id = str(data["source_finding_id"] or "")[:200] or None
        f.source_rule_id = str(data["source_rule_id"] or "")[:200] or None
        f.title = data["title"]
        f.description = data["description"]
        f.severity = data["severity"]
        f.cve = data["cve"]
        f.cwe_json = json.dumps(data["cwes"])
        f.package_name = str(data["package_name"] or "")[:200] or None
        f.package_version = str(data["package_version"] or "")[:80] or None
        f.fixed_version = str(data["fixed_version"] or "")[:80] or None
        f.file_path = str(data["file_path"] or "")[:500] or None
        f.line = data["line"]
        f.cvss_base = data["cvss_base"]
        f.raw_json = json.dumps(data["raw"], default=str)[:200000]

        if data["closed_at"]:
            f.status = "closed"
            f.closed_at = data["closed_at"]

        session.flush()
        seen_ids.append(f.id)

    if snapshot is not None:
        snapshot.findings_seen = len(seen_ids)
        snapshot.findings_new = created

    return {"created": created, "updated": updated, "seen_ids": seen_ids}


def parse_sarif(blob):
    """SARIF 2.1.0 -> linhas tabulares.

    Le o formato real do artefato ISSTA/EMBOSS, incluindo as tags
    `external/cwe/cwe-N` e `security-severity` que ficam na definicao da regra,
    nao no resultado.
    """
    doc = json.loads(blob) if isinstance(blob, (str, bytes)) else blob
    rows = []
    for run in doc.get("runs", []):
        drv = run.get("tool", {}).get("driver", {})
        tool = f"{drv.get('name', 'sarif')} {drv.get('semanticVersion') or drv.get('version') or ''}".strip()
        rules = {}
        for rule in drv.get("rules", []) or []:
            props = rule.get("properties", {}) or {}
            tags = props.get("tags", []) or []
            rules[rule.get("id")] = {
                "name": rule.get("name") or rule.get("id"),
                "desc": (rule.get("shortDescription") or {}).get("text"),
                "cwes": " ".join(sorted({f"CWE-{m.group(1)}" for t in tags
                                         for m in [re.search(r"cwe-(\d+)", t, re.I)] if m})),
                "level": (rule.get("defaultConfiguration") or {}).get("level"),
                "sec_sev": props.get("security-severity"),
            }
        for res in run.get("results", []) or []:
            rid = res.get("ruleId")
            meta = rules.get(rid, {})
            locs = res.get("locations") or []
            phys = (locs[0] or {}).get("physicalLocation", {}) if locs else {}
            rows.append({
                "rule_id": rid,
                "title": meta.get("desc") or rid or "achado SARIF",
                "message": (res.get("message") or {}).get("text"),
                "severity": res.get("level") or meta.get("level"),
                "cwe": meta.get("cwes", ""),
                "file": (phys.get("artifactLocation") or {}).get("uri"),
                "line": (phys.get("region") or {}).get("startLine"),
                "cvss": meta.get("sec_sev"),
                "tool": tool,
            })
    return rows


def parse_sarif_zip(path, limit_projects=None):
    """Le SARIF de dentro de um zip sem extrair, preservando owner/repo/commit
    do caminho -- que e proveniencia real, nao inferida."""
    out = []
    with zipfile.ZipFile(path) as z:
        members = [m for m in z.namelist()
                   if m.endswith(".sarif") and "mypy_cache" not in m]
        projects = {}
        for m in members:
            parts = m.split("/")
            if len(parts) < 5:
                continue
            owner, repo, commit = parts[-4], parts[-3], parts[-2]
            projects.setdefault(f"{owner}/{repo}", []).append((m, commit))
        names = sorted(projects)
        if limit_projects:
            names = names[:limit_projects]
        for proj in names:
            for member, commit in projects[proj]:
                for row in parse_sarif(z.read(member).decode("utf-8")):
                    row["repository"] = proj
                    row["commit"] = commit
                    out.append(row)
    return out


def start_snapshot(session, label, source_system, org_id=DEFAULT_ORG):
    from app.application import knowledge
    snap = ScanSnapshot(org_id=org_id, label=label, source_system=source_system,
                        taken_at=utcnow(),
                        knowledge_versions_json=json.dumps(knowledge.versions()))
    session.add(snap)
    session.flush()
    return snap


def import_decisions(session, rows, source_system, org_id=DEFAULT_ORG,
                     classification="SYNTHETIC_DATA"):
    """Importa decisoes historicas de fechamento.

    `classification` e obrigatoria e nao tem default seguro por acidente: o
    chamador tem que dizer se aquilo veio de uma organizacao real ou foi
    fabricado. Aqui o default e SYNTHETIC porque, no MVP, e o que existe.
    """
    from app.domain.models import Decision
    created = 0
    for row in rows:
        fp_hint = _pick(row, "fingerprint", "finding_fingerprint")
        fid = _pick(row, "finding_id", "id", "key")
        f = None
        if fp_hint:
            f = session.scalars(select(Finding).where(
                Finding.org_id == org_id, Finding.fingerprint == str(fp_hint))).first()
        if f is None and fid:
            f = session.scalars(select(Finding).where(
                Finding.org_id == org_id,
                Finding.source_finding_id == str(fid))).first()
        if f is None:
            continue

        reason = classify_closure_reason(
            _pick(row, "resolution", "reason", "status", "closure_reason"))
        decided = parse_date(_pick(row, "closed_date", "decided_at", "closed_at",
                                   "date")) or utcnow()

        from app.application import knowledge
        snap = knowledge.kev().knowledge_as_of(f.cve, decided) if f.cve else {}

        session.add(Decision(
            org_id=org_id, finding_id=f.id, reason=reason.value,
            rationale=_pick(row, "rationale", "comment", "note", "justification"),
            decided_at=decided,
            decided_by=_pick(row, "closed_by", "decided_by", "analyst", "user"),
            classification=classification, source_system=source_system,
            knowledge_snapshot_json=json.dumps(snap, default=str)))
        f.status = "closed"
        f.closed_at = decided
        created += 1
    session.flush()
    return {"created": created}
