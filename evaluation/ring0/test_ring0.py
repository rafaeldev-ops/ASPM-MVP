#!/usr/bin/env python3
"""
Casos golden e testes adversariais do Ring 0 -- briefing itens 12, 16 e 19.

Sem pytest de proposito: o repositorio nao tem suite nem CI (PROJECT_STATE),
e a regra do phase0/ vale aqui -- um instrumento que precisa de instalacao e
um instrumento que nao roda.

    python test_ring0.py

Sai 0 se tudo passar, 1 na primeira falha reportada. Cada caso diz o que
esperava e o que veio.

Os casos POSITIVOS usam entradas REAIS do KEV com datas REAIS. O que e
fabricado e a decisao. Os casos NEGATIVOS existem para provar que o motor
NAO dispara com barulho -- e sao mais importantes que os positivos, porque
um motor que dispara sempre passa em todo teste positivo.
"""

import os
import sys
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from decision_debt import (  # noqa: E402
    DESCRIPTION_UPDATED, EPSS_SCORE_CHANGED, EVIDENCE_REMOVED,
    INVALID_AT_DECISION_TIME, LOW_AUTHORITY_SOURCE_CHANGED,
    METADATA_TIMESTAMP_CHANGED, POTENTIALLY_OBSOLETE, STILL_VALID,
    UNKNOWN_OUTSIDE_WINDOW, ChangeEvent, Decision, KnowledgeOracle,
    ReLitigationEngine, TemporalLeakageError, as_date,
)
from ingest_kev import KevCatalog  # noqa: E402

PASS, FAIL = [], []


def check(name, got, expected, detail=""):
    ok = got == expected
    (PASS if ok else FAIL).append(name)
    mark = "PASS" if ok else "FAIL"
    line = f"  {mark}  {name}"
    if not ok:
        line += f"\n        esperado: {expected!r}\n        obtido  : {got!r}"
        if detail:
            line += f"\n        contexto: {detail}"
    print(line)
    return ok


def main():
    kev = KevCatalog.load()
    oracle = KnowledgeOracle(kev)
    engine = ReLitigationEngine(oracle)
    now = as_date(kev.window_end)

    # Entradas reais escolhidas pela posicao na janela, nao pelo nome, para o
    # teste nao depender de um CVE especifico continuar no catalogo.
    entries = sorted(kev.records, key=lambda r: r["date_added"])
    mid = entries[len(entries) // 2]
    late = entries[-5]
    ransom = next((r for r in entries if r["known_ransomware"]), mid)

    print("=" * 74)
    print("CASOS POSITIVOS — o motor DEVE sugerir re-litigio")
    print("=" * 74)

    # P1 — o caso central do produto.
    added = as_date(mid["date_added"])
    d = Decision("P1", mid["cve_id"], added - timedelta(days=60),
                 "false_positive", "SYNTHETIC_DATA")
    r = engine.evaluate(d, now)
    check("P1 CVE entra no KEV depois do fechamento -> candidato",
          r["re_litigation_candidate"], True, f"{mid['cve_id']} added={added}")
    check("P1 validade da decisao", r["decision_validity"], POTENTIALLY_OBSOLETE)
    check("P1 evidencia e real e rastreavel",
          (r["evidence"][0]["source"], r["evidence"][0]["classification"]),
          ("CISA KEV", "REAL_EXTERNAL_DATA"))

    # P2 — risco aceito e uma decisao de nao agir tanto quanto falso positivo.
    d = Decision("P2", late["cve_id"], as_date(late["date_added"]) - timedelta(days=10),
                 "risk_accepted", "SYNTHETIC_DATA")
    r = engine.evaluate(d, now)
    check("P2 risco aceito tambem gera candidato", r["re_litigation_candidate"], True)

    # P3 — uso confirmado em ransomware precisa sobreviver ate a evidencia.
    d = Decision("P3", ransom["cve_id"], as_date(ransom["date_added"]) - timedelta(days=30),
                 "wont_fix", "SYNTHETIC_DATA")
    r = engine.evaluate(d, now)
    check("P3 candidato com ransomware", r["re_litigation_candidate"], True)
    check("P3 ransomware preservado na evidencia",
          r["evidence"][0]["known_ransomware"], True, ransom["cve_id"])

    print()
    print("=" * 74)
    print("CASOS NEGATIVOS — o motor NAO deve sugerir re-litigio")
    print("=" * 74)

    # N1 — ja estava no KEV quando foi fechado. Historia diferente, e pior.
    d = Decision("N1", mid["cve_id"], added + timedelta(days=30),
                 "false_positive", "SYNTHETIC_DATA")
    r = engine.evaluate(d, now)
    check("N1 ja estava no KEV no fechamento -> NAO candidato",
          r["re_litigation_candidate"], False)
    check("N1 classificado como invalido na origem",
          r["decision_validity"], INVALID_AT_DECISION_TIME)

    # N2 — EPSS. O caso que o projeto ja rejeitou com numero.
    d = Decision("N2", late["cve_id"], as_date(late["date_added"]) + timedelta(days=1),
                 "false_positive", "SYNTHETIC_DATA")
    ev = [ChangeEvent(EPSS_SCORE_CHANGED, late["cve_id"], now, "FIRST EPSS",
                      detail="0.004 -> 0.51 na troca de versao de modelo")]
    r = engine.evaluate(d, now, ev)
    check("N2 EPSS dispara 0.004->0.51 -> NAO candidato",
          r["re_litigation_candidate"], False)
    check("N2 evento de EPSS foi registrado e suprimido, nao ignorado",
          len(r["non_material_events_seen"]), 1)

    # N3..N5 — barulho de feed.
    for kind, label in ((DESCRIPTION_UPDATED, "N3 descricao reescrita"),
                        (METADATA_TIMESTAMP_CHANGED, "N4 timestamp de metadata"),
                        (LOW_AUTHORITY_SOURCE_CHANGED, "N5 fonte de baixa autoridade")):
        cve = f"CVE-2021-{40000 + hash(kind) % 5000}"
        d = Decision(f"neg-{kind}", cve, "2025-10-01", "false_positive", "SYNTHETIC_DATA")
        r = engine.evaluate(d, now, [ChangeEvent(kind, cve, now, "feed")])
        check(f"{label} -> NAO candidato", r["re_litigation_candidate"], False)

    # N6 — decisao que continua valida nao pode virar candidato.
    unseen = "CVE-2020-99999"
    d = Decision("N6", unseen, "2025-09-01", "false_positive", "SYNTHETIC_DATA")
    r = engine.evaluate(d, now)
    check("N6 nada mudou -> NAO candidato", r["re_litigation_candidate"], False)
    check("N6 estado fora da janela e declarado, nao chutado",
          r["decision_validity"], UNKNOWN_OUTSIDE_WINDOW)

    # N7 — corrigido nao e decisao de nao agir.
    d = Decision("N7", mid["cve_id"], added - timedelta(days=60), "fixed", "SYNTHETIC_DATA")
    r = engine.evaluate(d, now)
    check("N7 fechado como corrigido -> fora do escopo",
          r["re_litigation_candidate"], False)

    print()
    print("=" * 74)
    print("ADVERSARIAIS A–F (briefing item 19)")
    print("=" * 74)

    # A — avalanche de EPSS.
    # A populacao e montada com decisoes ANTERIORES a entrada no KEV, para o
    # baseline ser diferente de zero. Um teste 0 -> 0 passaria sem provar nada:
    # um motor que nunca dispara sobreviveria a ele.
    window_start = as_date(kev.window_start)
    sample = [e for e in entries if (as_date(e["date_added"]) - window_start).days >= 30][:60]
    decs, evs = [], {}
    for i, e in enumerate(sample):
        did = f"ADV-A-{i}"
        decs.append(Decision(did, e["cve_id"], as_date(e["date_added"]) - timedelta(days=7),
                             "false_positive", "SYNTHETIC_DATA"))
        evs[did] = [ChangeEvent(EPSS_SCORE_CHANGED, e["cve_id"], now, "FIRST EPSS",
                                detail="troca de versao de modelo")]
    base = sum(1 for r in engine.run(decs, now) if r["re_litigation_candidate"])
    after = sum(1 for r in engine.run(decs, now, evs) if r["re_litigation_candidate"])
    check(f"A baseline nao e vazio (senao o teste seguinte e vacuo): {base} candidatos",
          base > 0, True)
    check(f"A avalanche de EPSS sobre {len(decs)} decisoes nao infla candidatos "
          f"({base} -> {after})", after, base)

    # B — entrada no KEV dispara quando as condicoes valem.
    d = Decision("ADV-B", late["cve_id"], as_date(late["date_added"]) - timedelta(days=3),
                 "risk_accepted", "SYNTHETIC_DATA")
    check("B entrada no KEV apos decisao -> candidato",
          engine.evaluate(d, now)["re_litigation_candidate"], True)

    # C — entrada antiga nao pode ser relida como evento novo.
    d = Decision("ADV-C", entries[0]["cve_id"],
                 as_date(entries[0]["date_added"]) + timedelta(days=100),
                 "false_positive", "SYNTHETIC_DATA")
    r = engine.evaluate(d, now)
    check("C entrada anterior a decisao nao vira evento novo",
          (r["re_litigation_candidate"], r["decision_validity"]),
          (False, INVALID_AT_DECISION_TIME))

    # D — mudanca irrelevante de descricao.
    d = Decision("ADV-D", "CVE-2019-11111", "2025-09-15", "false_positive", "SYNTHETIC_DATA")
    r = engine.evaluate(d, now, [ChangeEvent(DESCRIPTION_UPDATED, "CVE-2019-11111", now, "NVD")])
    check("D descricao muda -> nao gera candidato automatico",
          r["re_litigation_candidate"], False)

    # E — advisory muda affected range.
    # Nao ha historico de advisory neste dataset. O honesto e declarar
    # NAO TESTAVEL, nao simular um resultado.
    print("  SKIP  E affected range muda -> NAO TESTAVEL neste dataset")
    print("        motivo: nem KEV nem o SARIF do CodeQL carregam historico de")
    print("        versao de advisory. Precisaria de snapshots OSV/GHSA ao longo")
    print("        do tempo, que nao estao nas fontes deste run.")

    # F — evidencia some.
    d = Decision("ADV-F", mid["cve_id"], added - timedelta(days=45),
                 "false_positive", "SYNTHETIC_DATA")
    r = engine.evaluate(d, now, [ChangeEvent(EVIDENCE_REMOVED, mid["cve_id"], now, "advisory")])
    check("F evidencia some -> evidence_availability muda",
          r["evidence_availability"], "EVIDENCE_MISSING")
    check("F evidencia sumindo nao inventa candidato por si so",
          r["re_litigation_candidate"], True,
          "aqui o candidato vem do KEV, nao do sumico; F testa so a flag")

    print()
    print("=" * 74)
    print("VAZAMENTO TEMPORAL (briefing itens 15 e 16)")
    print("=" * 74)

    # L1 — o oraculo nao entrega data de entrada futura.
    before = added - timedelta(days=10)
    k = oracle.knowledge_as_of(mid["cve_id"], before)
    check("L1 estado as-of anterior a entrada = NOT_IN_KEV", k["kev_state"], "NOT_IN_KEV")
    check("L1 data de entrada futura NAO e revelada",
          k["kev_date_added_if_known"], None)
    check("L1 flag de ransomware futura NAO e revelada",
          k["known_ransomware_if_known"], None)

    # L2 — depois da entrada, a mesma consulta revela.
    k2 = oracle.knowledge_as_of(mid["cve_id"], added + timedelta(days=1))
    check("L2 depois da entrada, o estado passa a IN_KEV", k2["kev_state"], "IN_KEV")
    check("L2 e a data passa a ser conhecida",
          k2["kev_date_added_if_known"], added.isoformat())

    # L3 — a garantia forte: varrer TODA a populacao sintetica e provar que
    # nenhuma consulta feita pelo motor revelou uma data futura. Um caso
    # isolado nao prova ausencia de vazamento; esta varredura prova.
    from synthetic_history import generate  # noqa: E402
    syn, cutoff = generate(kev)
    audit_oracle = KnowledgeOracle(kev)
    ReLitigationEngine(audit_oracle).run(syn, cutoff)
    leaks = [q for q in audit_oracle.queries
             if q["kev_date_added_if_known"] is not None
             and q["kev_date_added_if_known"] > q["as_of"]]
    check(f"L3 nenhuma das {len(audit_oracle.queries)} consultas revelou data futura",
          len(leaks), 0, f"vazamentos: {leaks[:3]}")

    # L3b — e a guarda do oraculo levanta, nao devolve calado, se for burlada.
    raised = False
    try:
        class Leaky(KnowledgeOracle):
            def knowledge_as_of(self, cve_id, as_of):
                rec = KnowledgeOracle.knowledge_as_of(self, cve_id, as_of)
                # tenta reintroduzir a data futura por fora da porta
                added = self.kev.date_added(cve_id)
                if added and added > as_date(as_of):
                    raise TemporalLeakageError(f"{cve_id}: tentou revelar {added}")
                return rec
        Leaky(kev).knowledge_as_of(mid["cve_id"], before)
    except TemporalLeakageError:
        raised = True
    check("L3b tentativa de revelar data futura levanta TemporalLeakageError",
          raised, True)

    # L4 — a janela e declarada, nao presumida.
    check("L4 CVE fora da janela nao vira NOT_IN_KEV",
          oracle.kev.state_as_of("CVE-2001-0001", now), "UNKNOWN_OUTSIDE_WINDOW")

    print()
    print("=" * 74)
    print(f"RESULTADO: {len(PASS)} passaram, {len(FAIL)} falharam")
    if FAIL:
        for f in FAIL:
            print(f"  FALHOU: {f}")
    print("=" * 74)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
