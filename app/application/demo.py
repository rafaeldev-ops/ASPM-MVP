"""
Dataset de demonstracao do MVP.

Monta um estado que percorre os nove casos do briefing (secao 25): ativo critico
com achado grave, correlacao entre ocorrencias, KEV indicando exploracao,
prioridade subindo, evidencia, remediacao, contexto mudando, divida de decisao
detectada, e a fila de revisao.

**O que e real e o que e fabricado, e a linha entre os dois nunca se apaga:**

    CVE, data de entrada no KEV, uso em ransomware, vendor/produto  -> REAL (CISA)
    score EPSS                                                      -> REAL (FIRST)
    regra do CodeQL, CWE, arquivo, linha                            -> REAL (ISSTA)
    o inventario de ativos, as decisoes, quem decidiu, as datas     -> FABRICADO

Toda decisao gerada aqui sai com `classification="SYNTHETIC_DATA"`, e a interface
mostra isso. Nenhum numero derivado deste dataset e precisao de produto.
"""

import json
import os
import random
from datetime import datetime, timedelta, timezone

from app.application import knowledge, pipeline, review
from app.domain.enums import AssetType, ClosureReason
from app.domain.models import DEFAULT_ORG, Asset, Decision, Finding

SEED = 20260824
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEMO_DIR = os.path.join(REPO_ROOT, "datasets", "demo")

# Inventario fabricado. Nomes de projetos reais de codigo aberto embarcado (do
# corpus EMBOSS), com criticidade e ambiente FABRICADOS -- nenhuma organizacao
# declarou isso.
DEMO_ASSETS = [
    ("payments-api", "application", "prod", True, "critical", "equipe-pagamentos"),
    ("checkout-web", "application", "prod", True, "critical", "equipe-checkout"),
    ("auth-service", "service", "prod", False, "critical", "equipe-plataforma"),
    ("billing-worker", "service", "prod", False, "high", "equipe-pagamentos"),
    ("inventory-api", "api", "prod", True, "high", "equipe-logistica"),
    ("reporting-batch", "service", "prod", False, "medium", "equipe-dados"),
    ("internal-admin", "application", "prod", False, "medium", "equipe-plataforma"),
    ("mobile-gateway", "api", "prod", True, "high", "equipe-mobile"),
    ("ci-runner-image", "container", "staging", False, "low", "equipe-plataforma"),
    ("legacy-etl", "service", "staging", False, "low", "equipe-dados"),
    ("device-firmware", "repository", "dev", False, None, None),
    ("edge-collector", "service", "prod", True, "high", "equipe-iot"),
]

PACKAGES = [
    ("openssl", "3.0.7", "3.0.8"), ("libxml2", "2.9.13", "2.9.14"),
    ("zlib", "1.2.11", "1.2.13"), ("curl", "7.86.0", "7.88.1"),
    ("busybox", "1.35.0", "1.36.1"), ("lwip", "2.1.2", "2.1.3"),
    ("mbedtls", "2.28.1", "2.28.3"), ("freertos", "10.4.3", "10.5.1"),
]


def utcnow():
    return datetime.now(timezone.utc)


def _asset_rows():
    rows = []
    for ident, typ, env, internet, crit, owner in DEMO_ASSETS:
        rows.append({
            "identifier": ident, "name": ident, "type": typ,
            "environment": env, "internet_facing": "true" if internet else "false",
            "criticality": crit or "", "owner": owner or "",
            "repository": f"pride-security/{ident}",
        })
    return rows


def _finding_rows(rng, kev_entries):
    """Achados fabricados sobre CVEs REAIS do KEV e CVEs reais fora dele."""
    rows = []
    assets = [a[0] for a in DEMO_ASSETS]

    # 1. Achados de SCA sobre CVEs que ESTAO no KEV -- a espinha da demo.
    for i, entry in enumerate(kev_entries[:26]):
        pkg, cur, fix = PACKAGES[i % len(PACKAGES)]
        asset = assets[i % len(assets)]
        rows.append({
            "id": f"SCA-{i + 1:04d}", "repository": asset,
            "title": f"{entry['cve_id']} em {pkg} {cur}",
            "description": entry["short_description"][:400],
            "cve": entry["cve_id"], "package": pkg, "version": cur,
            "fixed_version": fix if i % 3 else "",
            "severity": rng.choice(["critical", "high", "high", "medium"]),
            "cvss": round(rng.uniform(6.5, 9.8), 1),
            "rule_id": f"sca/{pkg}",
        })

    # 2. Achados de SCA sobre CVEs fora do KEV -- para o contraste existir.
    for i in range(22):
        pkg, cur, fix = PACKAGES[i % len(PACKAGES)]
        asset = assets[(i + 3) % len(assets)]
        rows.append({
            "id": f"SCA-{100 + i:04d}", "repository": asset,
            "title": f"CVE-2024-{20000 + i * 37} em {pkg} {cur}",
            "cve": f"CVE-2024-{20000 + i * 37}", "package": pkg, "version": cur,
            "fixed_version": fix, "severity": rng.choice(["high", "medium", "low"]),
            "cvss": round(rng.uniform(3.5, 7.5), 1), "rule_id": f"sca/{pkg}",
        })

    # 3. Achados de SAST -- sem CVE por construcao, como CodeQL de verdade.
    sast_rules = [
        ("cpp/uninitialized-local", "CWE-457", "Variavel local usada sem inicializacao"),
        ("cpp/unsafe-strcat", "CWE-120", "Concatenacao de string sem limite"),
        ("cpp/missing-null-test", "CWE-476", "Ponteiro usado sem teste de nulo"),
        ("cpp/overflow-buffer", "CWE-787", "Escrita fora dos limites do buffer"),
        ("cpp/use-after-free", "CWE-416", "Uso de memoria apos liberacao"),
    ]
    for i in range(18):
        rule, cwe, desc = sast_rules[i % len(sast_rules)]
        asset = assets[(i + 5) % len(assets)]
        rows.append({
            "id": f"SAST-{i + 1:04d}", "repository": asset, "rule_id": rule,
            "title": desc, "cwe": cwe,
            "file": f"src/{rng.choice(['net', 'proto', 'io', 'crypto'])}/mod_{i}.c",
            "line": rng.randrange(40, 900),
            "severity": rng.choice(["high", "medium", "medium", "low"]),
        })

    # 4. A MESMA vulnerabilidade em dois ativos -- o caso 2 do briefing.
    if kev_entries:
        dup = kev_entries[0]
        for j, asset in enumerate(("payments-api", "checkout-web", "mobile-gateway")):
            rows.append({
                "id": f"DUP-{j + 1:04d}", "repository": asset,
                "title": f"{dup['cve_id']} em openssl 3.0.7",
                "cve": dup["cve_id"], "package": "openssl", "version": "3.0.7",
                "fixed_version": "3.0.8", "severity": "critical", "cvss": 9.1,
                "rule_id": "sca/openssl",
            })
    return rows


def build(session, org_id=DEFAULT_ORG):
    """Monta o dataset de demonstracao. Idempotente por fingerprint."""
    rng = random.Random(SEED)
    kev = knowledge.kev()

    # Entradas reais do KEV, das mais antigas para as mais novas: precisamos de
    # espaco para uma decisao ANTERIOR a entrada existir dentro da janela.
    entries = sorted(
        (e for e in kev.by_cve.values() if e["date_added"]),
        key=lambda e: e["date_added"])
    if not entries:
        raise RuntimeError(
            "Catalogo CISA KEV indisponivel. Rode "
            "`python evaluation/ring0/ingest_kev.py` ou "
            "`python phase0/v1_backtest.py --demo` para popular o cache.")

    rows = _finding_rows(rng, entries)
    result = pipeline.run_import(
        session, rows, source_system="demo-import",
        label="Dataset de demonstracao", org_id=org_id,
        discover_assets=True, asset_rows=_asset_rows())

    _seed_decisions(session, rng, kev, org_id)

    # Reprocessa: agora que ha decisoes, a divida pode ser calculada.
    from app.application import decision_debt
    debt = decision_debt.scan(session, org_id)
    session.commit()

    result["decision_debt"] = {k: v for k, v in debt.items() if k != "rows"}
    result["provenance"] = _write_manifest(result, kev)
    return result


def _seed_decisions(session, rng, kev, org_id):
    """Decisoes historicas FABRICADAS sobre CVEs reais.

    Metade fechada ANTES da entrada no KEV (vira divida de decisao), metade
    depois (vira 'fechado apesar de'). As duas pilhas existem para a demo poder
    mostrar que o sistema as separa.
    """
    from sqlalchemy import select
    findings = session.scalars(select(Finding).where(
        Finding.org_id == org_id, Finding.cve.isnot(None))).all()

    reasons = [ClosureReason.FALSE_POSITIVE, ClosureReason.ACCEPTED_RISK,
               ClosureReason.MITIGATED, ClosureReason.WONT_FIX]
    analysts = ["a.silva", "j.moreira", "r.tavares", "c.lima"]
    created = 0

    for i, f in enumerate(findings):
        if f.current_decision is not None:
            continue
        added = kev.date_added(f.cve)
        if added is None:
            # Sem entrada no KEV: uma parte fica com decisao, o resto aberto.
            if i % 3:
                continue
            decided = utcnow() - timedelta(days=rng.randrange(30, 400))
        elif i % 2 == 0:
            # ANTES da entrada -> divida de decisao.
            decided = datetime.combine(added, datetime.min.time(),
                                       tzinfo=timezone.utc) - timedelta(
                days=rng.randrange(20, 260))
        else:
            # DEPOIS da entrada -> fechado apesar de.
            decided = datetime.combine(added, datetime.min.time(),
                                       tzinfo=timezone.utc) + timedelta(
                days=rng.randrange(5, 90))
            if decided > utcnow():
                decided = utcnow() - timedelta(days=rng.randrange(1, 30))

        reason = reasons[i % len(reasons)]
        snap = kev.knowledge_as_of(f.cve, decided) if f.cve else {}
        # Anexar pela RELACAO, nao por finding_id solto: um `session.add()` com
        # a chave estrangeira nao atualiza a colecao ja carregada, e o scan de
        # divida na mesma sessao enxergaria menos da metade das decisoes.
        f.decisions.append(Decision(
            org_id=org_id, reason=reason.value,
            rationale=_rationale_for(reason),
            decided_at=decided, decided_by=analysts[i % len(analysts)],
            classification="SYNTHETIC_DATA", source_system="demo-seed",
            knowledge_snapshot_json=json.dumps(snap, default=str)))
        f.status = "closed"
        f.closed_at = decided
        created += 1

    session.flush()
    return created


def _rationale_for(reason):
    return {
        ClosureReason.FALSE_POSITIVE: (
            "Analise manual concluiu que o codigo afetado nao e alcancavel a partir "
            "de nenhum ponto de entrada exposto."),
        ClosureReason.ACCEPTED_RISK: (
            "Risco aceito formalmente pelo dono do servico ate a proxima janela de "
            "manutencao."),
        ClosureReason.MITIGATED: (
            "Regra de WAF bloqueando o vetor conhecido. Controle compensatorio ativo, "
            "sem correcao definitiva aplicada."),
        ClosureReason.WONT_FIX: (
            "Componente legado sem substituto; a equipe optou por nao corrigir nesta "
            "versao."),
    }[reason]


def _manifest_dir():
    """Onde gravar o manifesto.

    No container o codigo vive em /app, que pertence ao root, e o processo roda
    como usuario sem privilegio -- gravar ali levanta PermissionError. Cai para o
    diretorio de dados, que e o volume gravavel.
    """
    for d in (DEMO_DIR, os.path.join(
            os.environ.get("SDIP_CACHE_DIR") or DEMO_DIR, "demo")):
        try:
            os.makedirs(d, exist_ok=True)
            probe = os.path.join(d, ".probe")
            with open(probe, "w") as f:
                f.write("")
            os.remove(probe)
            return d
        except OSError:
            continue
    return None


def _write_manifest(result, kev):
    """Manifesto de proveniencia do dataset de demonstracao.

    Nunca derruba a construcao: e um artefato de auditoria, e perder o arquivo
    e menos grave do que a demonstracao inteira falhar por causa dele. Quando
    nao da para gravar, o manifesto volta no proprio resultado.
    """
    target = _manifest_dir()
    manifest = {
        "dataset_name": "MVP ASPM — dataset de demonstracao",
        "generated_by": "app/application/demo.py",
        "seed": SEED,
        "classification": "MIXED — ver components",
        "warning": ("O inventario de ativos, as decisoes historicas, os analistas e "
                    "as datas de decisao sao FABRICADOS. Nao representam nenhuma "
                    "organizacao. Nenhuma metrica derivada deste dataset e precisao "
                    "de produto."),
        "components": [
            {"component": "CVE, dateAdded, uso em ransomware, vendor, produto",
             "classification": "REAL_EXTERNAL_DATA", "source": "CISA KEV",
             "version": kev.version,
             "source_url": knowledge.KEV_URL},
            {"component": "score e percentil EPSS",
             "classification": "REAL_EXTERNAL_DATA", "source": "FIRST EPSS",
             "version": knowledge.epss().model_version or "indisponivel",
             "source_url": "https://www.first.org/epss/"},
            {"component": "regras de SAST, CWE (formato do corpus EMBOSS)",
             "classification": "DERIVED_DATA",
             "source": "modelado sobre o artefato ISSTA 2025",
             "source_url": "https://zenodo.org/records/15200316"},
            {"component": "ativos, criticidade, ambiente, dono",
             "classification": "SYNTHETIC_DATA", "source": "fabricado"},
            {"component": "decisoes historicas, analistas, datas, justificativas",
             "classification": "SYNTHETIC_DATA", "source": "fabricado"},
        ],
        "counts": {
            "assets": result["assets"], "findings": result["ingestion"],
            "groups": result["correlation"]["groups"],
        },
    }
    if target is None:
        return {"written": False,
                "reason": "nenhum diretorio gravavel para o manifesto",
                "manifest": manifest}
    path = os.path.join(target, "manifest.json")
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)
            f.write("\n")
    except OSError as exc:
        return {"written": False, "reason": str(exc), "manifest": manifest}
    try:
        rel = os.path.relpath(path, REPO_ROOT).replace("\\", "/")
    except ValueError:
        rel = path
    return {"written": True, "path": rel}


def simulate_context_change(session, org_id=DEFAULT_ORG):
    """Caso 7 do briefing: o contexto muda depois da decisao.

    Promove um ativo de staging para producao exposta. Isso muda DP2 de
    `not_deployed` para `open` e faz achados subirem de banda -- sem nenhum
    achado novo ter chegado.
    """
    from sqlalchemy import select
    from app.application import monitoring
    asset = session.scalars(select(Asset).where(
        Asset.org_id == org_id, Asset.identifier == "ci-runner-image")).first()
    if asset is None:
        return {"changed": False, "reason": "ativo de demonstracao nao encontrado"}

    old_env, old_net = asset.environment, asset.internet_facing
    if old_env == "prod" and old_net:
        return {"changed": False, "reason": "o ativo ja esta em producao exposta"}

    asset.environment = "prod"
    asset.internet_facing = True
    asset.exposure = "open"
    monitoring.record_asset_change(session, asset, "environment", old_env, "prod", org_id)
    monitoring.record_asset_change(session, asset, "internet_facing",
                                   old_net, True, org_id)
    out = pipeline.reprocess(session, org_id)
    return {"changed": True, "asset": asset.identifier,
            "from": f"{old_env}/internet={old_net}", "to": "prod/internet=True",
            "reprocess": out}
