#!/usr/bin/env python3
"""
Roda a suite inteira do MVP.

    python tests/run.py            # tudo
    python tests/run.py -q         # so o resultado
    python tests/run.py risk       # so os modulos cujo nome casa

Usa `unittest` da stdlib: nao ha pytest neste projeto, e adicionar um framework
de teste como dependencia contraria a regra de manter o MVP instalavel sem
cerimonia. As dependencias sao as mesmas de `requirements.txt`.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests import support  # noqa: E402,F401  (define SDIP_DB_PATH antes de app.*)

MODULOS = [
    "tests.test_closure_reasons",   # regressao de B2/B3
    "tests.test_risk_tree",         # o modelo deterministico
    "tests.test_pipeline",          # ingestao, correlacao, priorizacao, monitoramento
    "tests.test_decision_debt",     # regra temporal e revisao
    "tests.test_e2e",               # fluxo completo e os 9 casos da demo
    "tests.test_migrations",        # versionamento de schema, banco antigo
    "tests.test_credentials",       # cofre de credencial, round-trip real
    "tests.test_ai_provider",       # selecao de provider, falhas, egresso
    "tests.test_ai_privacy",        # a fronteira de redacao
    "tests.test_api",               # contrato das telas e da API
]


def main(argv):
    filtro = next((a for a in argv[1:] if not a.startswith("-")), None)
    quieto = "-q" in argv

    nomes = [m for m in MODULOS if not filtro or filtro in m]
    if not nomes:
        print(f"Nenhum modulo casa com {filtro!r}. Disponiveis:")
        for m in MODULOS:
            print(f"  {m.split('.')[-1]}")
        return 2

    from app.application import knowledge
    kev = knowledge.kev()
    if not quieto:
        print("=" * 70)
        print("Suite do MVP ASPM — Pride Security")
        print("=" * 70)
        print(f"Python        : {sys.version.split()[0]}")
        print(f"Banco de teste: {os.environ['SDIP_DB_PATH']}")
        print(f"Catalogo KEV  : {kev.version} ({len(kev.by_cve)} entradas)"
              if kev.by_cve else
              "Catalogo KEV  : INDISPONIVEL — testes que dependem dele serao pulados")
        print(f"Provedor de IA: {os.environ.get('SDIP_AI_PROVIDER', 'null')}")
        print("=" * 70)
        print()

    suite = unittest.TestLoader().loadTestsFromNames(nomes)
    resultado = unittest.TextTestRunner(verbosity=1 if quieto else 2).run(suite)

    if not quieto:
        print()
        print("=" * 70)
        print(f"{resultado.testsRun} testes · "
              f"{len(resultado.failures)} falhas · "
              f"{len(resultado.errors)} erros · "
              f"{len(resultado.skipped)} pulados")
        if resultado.skipped:
            print("\nPulados:")
            for caso, motivo in resultado.skipped:
                print(f"  {caso} — {motivo}")
        print("=" * 70)

    return 0 if resultado.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
