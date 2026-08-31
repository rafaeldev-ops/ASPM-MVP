"""
Benchmark da camada de IA contra um modelo local de verdade.

Existe porque a L13 dizia que nenhum LLM tinha sido executado, e uma camada de IA
cuja unica prova sao servidores falsos prova transporte, nao qualidade. A ADR-0015
§2 exige benchmark antes de escolher fornecedor; isto e a menor versao honesta
desse benchmark.

O que se mede, e por que cada um:

  aderencia ao schema   quantas respostas passam a validacao sem coercao pesada
  fundamentacao         id de evidencia citado que o modelo nao recebeu
  estabilidade da banda a banda deterministica NAO pode mudar. Se mudar, e defeito
  coerencia da sugestao razao sugerida que contradiz a banda -- o risco de falso
                        negativo que o CLAUDE.md §33 nomeia como o dano pior
  latencia              mediana e p90, porque um desktop de um usuario espera
  recusa                taxa de recusa sobre corpus de seguranca

Rodar:  python evaluation/ollama_bench.py [--model qwen2.5:3b] [--n 12]

Nao usa dado de cliente: os achados vem do catalogo KEV publico mais um inventario
fabricado, e todo numero que sai daqui e sobre o instrumento, nunca sobre uma
organizacao.
"""

import argparse
import json
import os
import statistics
import sys
import time
from datetime import datetime, timezone

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

# Antes de qualquer `app.*`: a engine nasce no import de `app.db`.
os.environ.setdefault("SDIP_DB_PATH", os.path.join(REPO, "evaluation", "bench.db"))
os.environ.pop("SDIP_AI_PROVIDER", None)   # env venceria o banco

from app.application import ai, correlation, knowledge, prioritization  # noqa: E402
from app.application.ai import prompt as ai_prompt  # noqa: E402
from app.application.ai import service, settings as ai_settings  # noqa: E402
from app.application.ingestion import fingerprint_of, upsert_asset  # noqa: E402
from app.db import Base, SessionLocal, engine, init_db  # noqa: E402
from app.domain.models import Finding  # noqa: E402

# Bandas que exigem acao. Uma sugestao de fechar um achado nestas bandas e o modo
# de falha caro: o analista aceita o formulario pre-preenchido e um risco ativo
# fica fechado com carimbo de "revisado".
BANDAS_DE_ACAO = {"act_now", "act_soon"}
FECHAMENTOS = {"accepted_risk", "false_positive", "wont_fix", "fixed", "mitigated"}

# --------------------------------------------------------------------------
# Ablacao de prompt.
#
# So existe aqui, no instrumento de avaliacao. O prompt de producao continua
# sendo constante de modulo byte-estavel (ADR-0015 §5); trocar em runtime seria
# exatamente o botao de ajuste que aquela regra proibe. O que se quer medir e
# quanto do ganho vem do prompt e quanto vem do portao estrutural -- e sem
# separar os dois nao da para saber se a regra de prompt paga o proprio custo.
#
# v1  o prompt original, que nunca disse que recommended_reason e fechamento
# v2  v1 + duas regras numeradas explicitas (a primeira correcao)
# v3  v1 + uma frase, sem regra numerada nova
# --------------------------------------------------------------------------

_MARCA = "O campo recommended_reason"

_V1 = """O campo recommended_reason, quando preenchido, e uma SUGESTAO para um analista
humano confirmar ou recusar. Ele nunca fecha um achado sozinho."""

_V3 = """O campo recommended_reason e uma razao de FECHAMENTO: deixe-o vazio ("")
sempre que o achado deva ser corrigido em vez de encerrado. Quando preenchido, e
uma SUGESTAO para um analista humano confirmar ou recusar, e nunca fecha um
achado sozinho."""


def aplicar_prompt(variante):
    """Reescreve o system prompt no processo do bench. Nunca em producao."""
    if variante == "v2":
        return ai_prompt.SYSTEM_PROMPT
    cabeca = ai_prompt.SYSTEM_PROMPT.split(_MARCA)[0].rstrip()
    corpo = _V1 if variante == "v1" else _V3
    ai_prompt.SYSTEM_PROMPT = cabeca + "\n\n" + corpo
    return ai_prompt.SYSTEM_PROMPT


PERFIS = [
    # (criticidade, ambiente, exposto, tem correcao)
    ("critical", "prod", True, True),
    ("critical", "prod", True, False),
    ("high", "prod", True, True),
    ("high", "prod", False, True),
    ("medium", "staging", False, True),
    ("low", "dev", False, False),
]


def montar_corpus(session, n):
    """Metade KEV, metade nao-KEV -- e a metade nao-KEV e o ponto.

    A primeira versao deste corpus era 100% KEV e produziu 12 de 12 achados em
    `act_now`: estar na KEV torna o achado nao-suprimivel e domina a arvore de
    risco, entao variar criticidade e exposicao do ativo nao muda nada. Um corpus
    assim nao consegue responder a pergunta que importa sobre o portao de
    sugestao -- se ele dispara **demais**, apagando sugestao legitima em achado
    que de fato pode ser encerrado.

    O inventario e sintetico e esta declarado como tal. Os CVEs, as datas de
    entrada na KEV e o EPSS sao reais.
    """
    kev = knowledge.kev()
    if not kev.by_cve:
        raise SystemExit("catalogo KEV indisponivel; rode com rede uma vez")

    entradas = sorted((e for e in kev.by_cve.values() if e["date_added"]),
                      key=lambda e: e["date_added"], reverse=True)[:max(1, n // 2)]

    itens = []
    for entrada in entradas:
        itens.append((entrada["cve_id"],
                      f"{entrada['product']}: {entrada['name']}"[:380],
                      str(entrada["product"]).lower().replace(" ", "-")[:60],
                      f"Vulnerabilidade em {entrada['vendor']} {entrada['product']}."))

    # CVEs de forma valida que NAO estao na KEV. Ausencia num catalogo completo e
    # um fato -- e o que permite a arvore chegar a uma banda que nao exige acao.
    for i in range(n - len(itens)):
        cve = f"CVE-2019-{10000 + i * 7}"
        if cve in kev.by_cve:
            continue
        itens.append((cve, f"Dependencia desatualizada em biblioteca interna ({cve})",
                      "lib-interna", "Versao antiga de dependencia sem exploracao conhecida."))

    for i, (cve, titulo, pacote, descricao) in enumerate(itens):
        crit, env, exposto, tem_fix = PERFIS[i % len(PERFIS)]
        ativo = upsert_asset(session, f"svc-bench-{i:02d}", name=f"svc-bench-{i:02d}",
                             source_system="bench", criticality=crit,
                             environment=env, internet_facing=exposto)
        session.flush()
        f = Finding(
            org_id="org-local", source_system="bench",
            title=titulo, cve=cve,
            severity="critical" if cve in kev.by_cve else "medium",
            package_name=pacote, package_version="1.0.0",
            fixed_version="1.0.1" if tem_fix else None,
            description=descricao,
            fingerprint=fingerprint_of(titulo, cve, i))
        f.asset = ativo
        session.add(f)
    session.flush()
    correlation.correlate(session)
    correlation.enrich(session)
    prioritization.prioritize_all(session)
    session.commit()
    return session.query(Finding).order_by(Finding.id).all()


def rodar(model, base_url, n, timeout, variante="v2"):
    Base.metadata.drop_all(engine)
    init_db()

    with SessionLocal() as s:
        achados = montar_corpus(s, n)
        ai_settings.save(s, {"provider": "ollama", "base_url": base_url,
                             "model": model, "timeout_s": str(timeout)})
        s.commit()
        ai.reset()

        info = ai.provider_info(s)
        if info["provider"] != "ollama":
            raise SystemExit(f"provider ativo e {info['provider']}, nao ollama")

        st = ai.get_provider(s).status(timeout=5)
        if not st.available:
            raise SystemExit(f"Ollama indisponivel: {st.detail}")

        aplicar_prompt(variante)
        print(f"modelo   : {model}")
        print(f"prompt   : {variante} ({len(ai_prompt.SYSTEM_PROMPT)} chars, "
              f"hash {ai_prompt.prompt_hash()[:12]})")
        print(f"achados  : {len(achados)}")
        print(f"egresso  : {info['egress']} (loopback verificado)")
        print("-" * 78)

        linhas = []
        for i, f in enumerate(achados, 1):
            banda_antes = f.band
            score_antes = f.ordering_score
            t0 = time.time()
            rec = service.analyze_finding(s, f, confirmed_egress="localhost")
            s.commit()
            s.refresh(f)

            citados = set(rec.evidence_ids or [])
            sugestao = rec.suggested_reason or ""
            incoerente = bool(banda_antes in BANDAS_DE_ACAO and sugestao in FECHAMENTOS)

            linha = {
                "n": i, "cve": f.cve, "band": banda_antes,
                "outcome": rec.outcome,
                "latency_ms": rec.latency_ms or int((time.time() - t0) * 1000),
                "attempts": rec.attempts,
                "tokens_in": rec.tokens_in, "tokens_out": rec.tokens_out,
                "cited": sorted(citados),
                # Id inventado nao chega aqui como lista: a validacao rejeita a
                # resposta inteira. E por isso que o outcome e a medida.
                "ungrounded": rec.outcome == "rejected_ungrounded",
                "suggested_reason": sugestao,
                "incoherent_suggestion": incoerente,
                "band_moved": f.band != banda_antes or f.ordering_score != score_antes,
                "confidence": rec.confidence,
                "summary": (rec.summary or "")[:220],
            }
            linhas.append(linha)
            # O portao so pode agir em banda de acao. Sugestao em banda calma
            # tem que sobreviver intacta -- e o teste de que ele nao dispara demais.
            linha["gate_fired"] = any("descartada" in r for r in
                                      (rec.uncertainty_reasons or []))
            linha["gate_overfired"] = bool(linha["gate_fired"]
                                           and banda_antes not in BANDAS_DE_ACAO)
            marca = "!!" if (incoerente or linha["band_moved"] or linha["ungrounded"]
                             or linha["gate_overfired"]) else "  "
            print(f"{marca} {i:2d}. {f.cve:<16} {banda_antes:<12} {rec.outcome:<10} "
                  f"{linha['latency_ms']:>6}ms  sug={sugestao or '-':<15} "
                  f"cit={sorted(citados)}")

    return linhas


def relatar(linhas, model):
    total = len(linhas)
    ok = [l for l in linhas if l["outcome"] == "ok"]
    lat = sorted(l["latency_ms"] for l in linhas)
    ungrounded = [l for l in linhas if l["ungrounded"]]
    moved = [l for l in linhas if l["band_moved"]]
    incoerentes = [l for l in linhas if l["incoherent_suggestion"]]
    sem_citacao = [l for l in ok if not l["cited"]]

    outcomes = {}
    for l in linhas:
        outcomes[l["outcome"]] = outcomes.get(l["outcome"], 0) + 1

    def pct(x):
        return f"{100.0 * x / total:.1f}%" if total else "n/a"

    print()
    print("=" * 78)
    print(f"RESULTADO — {model}, {total} achados")
    print("=" * 78)
    print(f"outcomes                     : {outcomes}")
    print(f"aderencia ao schema (ok)     : {len(ok)}/{total}  {pct(len(ok))}")
    print(f"citou alguma evidencia       : {len(ok) - len(sem_citacao)}/{len(ok)}")
    print(f"resposta rejeitada por id falso: {len(ungrounded)}  {pct(len(ungrounded))}")
    print(f"BANDA ALTERADA               : {len(moved)}   <- tem que ser 0")
    print(f"sugestao incoerente com banda: {len(incoerentes)}  {pct(len(incoerentes))}")
    disparou = [l for l in linhas if l.get("gate_fired")]
    demais = [l for l in linhas if l.get("gate_overfired")]
    calmas = [l for l in linhas if l["band"] not in BANDAS_DE_ACAO]
    com_sug = [l for l in calmas if l["suggested_reason"]]
    print(f"portao disparou              : {len(disparou)}  {pct(len(disparou))}")
    print(f"PORTAO DISPAROU DEMAIS       : {len(demais)}   <- tem que ser 0")
    print(f"bandas: acao {total - len(calmas)} / calma {len(calmas)}"
          f"  (com sugestao preservada: {len(com_sug)})")
    if lat:
        p90 = lat[min(len(lat) - 1, int(0.9 * len(lat)))]
        print(f"latencia mediana / p90       : {statistics.median(lat):.0f}ms / {p90}ms")
        print(f"latencia total do lote       : {sum(lat) / 1000:.1f}s")
    tin = sum(l["tokens_in"] or 0 for l in linhas)
    tout = sum(l["tokens_out"] or 0 for l in linhas)
    print(f"tokens                       : {tin} entrada / {tout} saida")

    if incoerentes:
        print()
        print("SUGESTOES INCOERENTES — o modo de falha caro (CLAUDE.md §33):")
        for l in incoerentes:
            print(f"  {l['cve']}  banda={l['band']}  sugeriu={l['suggested_reason']}")
            print(f"      \"{l['summary'][:150]}\"")

    if ungrounded:
        print()
        print("RESPOSTAS REJEITADAS POR FUNDAMENTACAO:")
        for l in ungrounded:
            print(f"  {l['cve']}  resposta rejeitada por citar evidencia nao entregue")

    return {
        "model": model, "n": total, "outcomes": outcomes,
        "schema_ok": len(ok), "ungrounded": len(ungrounded),
        "band_moved": len(moved), "incoherent_suggestions": len(incoerentes),
        "latency_median_ms": statistics.median(lat) if lat else None,
        "latency_p90_ms": lat[min(len(lat) - 1, int(0.9 * len(lat)))] if lat else None,
        "tokens_in": tin, "tokens_out": tout,
        "run_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "rows": linhas,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="qwen2.5:3b")
    ap.add_argument("--base-url", default="http://127.0.0.1:11434")
    ap.add_argument("--n", type=int, default=12)
    ap.add_argument("--timeout", default="120")
    ap.add_argument("--out", default=None)
    ap.add_argument("--prompt", default="v2", choices=["v1", "v2", "v3"])
    args = ap.parse_args()

    linhas = rodar(args.model, args.base_url, args.n, args.timeout, args.prompt)
    resumo = relatar(linhas, args.model)
    resumo["prompt_variant"] = args.prompt
    resumo["prompt_hash"] = ai_prompt.prompt_hash()

    destino = args.out or os.path.join(
        REPO, "evaluation", "runs",
        f"ollama-{args.model.replace(':', '-')}-{args.prompt}.json")
    os.makedirs(os.path.dirname(destino), exist_ok=True)
    with open(destino, "w", encoding="utf-8") as fh:
        json.dump(resumo, fh, indent=2, ensure_ascii=False)
    print(f"\ngravado: {destino}")


if __name__ == "__main__":
    main()
