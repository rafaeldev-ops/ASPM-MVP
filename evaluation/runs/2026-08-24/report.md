# Ring 0 — run de 2026-08-24

Resumo gerado por `evaluation/ring0/run_all.py`. Análise completa e
conclusões em [`docs/evaluation/ring0-real-data-validation.md`](../../../docs/evaluation/ring0-real-data-validation.md).

> **As decisões deste run são SINTÉTICAS.** CVEs, datas de entrada no KEV e uso
> em ransomware são reais (CISA). Nenhum parceiro, nenhum cliente, nenhuma
> decisão de analista real. Nada aqui move K1, K2 ou K3.

## Fontes

| Dataset | Classe | Registros |
|---|---|---:|
| CISA KEV (2025-08-25 … 2026-08-21) | REAL_EXTERNAL_DATA | 273 |
| CodeQL SARIF (EMBOSS/ISSTA) | REAL_EXTERNAL_DATA | 100627 |
| EPSS snapshot v2026.06.15 | REAL_EXTERNAL_DATA | 359229 |
| Histórico de decisões | **SYNTHETIC_DATA** | 360 |

## Dívida de decisão (as-of 2026-08-21)

| Pilha | Contagem |
|---|---:|
| Dívida de decisão | **109** |
| Fechado apesar de (já no KEV) | **101** |
| Fora da janela do catálogo | 111 |
| Excluído (fechado como corrigido) | 39 |

## Métricas

| Métrica | Valor |
|---|---:|
| Precision (rótulo de construção) | 1.0 |
| Recall (rótulo de construção) | 1.0 |
| False re-litigation rate | 0.0 |
| Candidate inflation sob EPSS | 1.0× |
| Evidence coverage | 1.0 |
| Temporal correctness | 1.0 (642 consultas, 0 vazamentos) |

**Precision 1.0 é contra o rótulo de construção do dataset sintético.** Mede a implementação contra a especificação, não o mundo. Não é K3.

## Comparação com phase0/v1_backtest.py (evidência idêntica)

| | Dívida | Fechado apesar de |
|---|---:|---:|
| Motor deste run | 109 | 101 |
| `v1_backtest.py` | 94 | 92 |

Concordam: **não**. Causa isolada e confirmada:

- `classify_reason('Mitigated')` → `fixed` — exclui do escopo
- `classify_reason("Won't Fix")` → `false_positive` — nao muda a contagem de divida; corrompe a divisao de piles

## Correlação KEV × CodeQL

- Junção por identidade (CVE): **100.0% unmatched**. CodeQL não emite CVE.
- Classe (CWE): 13 CWEs compartilhados, 1.12% dos achados.
- Repositório: 19 pares candidatos, nenhum promovido a vínculo.

## EPSS

- 22358 CVEs a ±10% do limiar 0.01 (medida real).
- Deslocamento simulado de 25% move 22877 CVEs (DERIVED_DATA).
- KEV no mesmo período: 23.0 entradas/mês (medida real).

## Corpus CodeQL

- 100627 achados, 150 projetos, 116 regras dispararam.
- Cobertura de CWE 73.5%, CVE 0.0%.
- Concentração: cleanflight/cleanflight = 60.77% do corpus.
- Ground truth de falso positivo: **False**.

