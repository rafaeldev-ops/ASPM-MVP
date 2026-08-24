# datasets/

Dados do run de validação do Ring 0. Ver a análise em
[`docs/evaluation/ring0-real-data-validation.md`](../docs/evaluation/ring0-real-data-validation.md).

```
raw/          arquivos originais. NUNCA modificados, NUNCA extraídos.
processed/    datasets normalizados, cada um com o bloco `_provenance` dentro.
metadata/     manifest.json — a proveniência de tudo, com SHA-256.
```

## A regra

Todo dataset carrega uma classificação, e ela é obrigatória no construtor —
não há default:

| Classe | O que é |
|---|---|
| `REAL_EXTERNAL_DATA` | Veio de fonte externa real. Não foi produzido por nós |
| `DERIVED_DATA` | Calculado por uma regra deste experimento a partir de dado real |
| `SYNTHETIC_DATA` | Fabricado. **Não é o que nenhuma organização decidiu** |

O `synthetic_decision_history.json` é `SYNTHETIC_DATA`. Os CVEs e as datas de
entrada no KEV dentro dele são reais; a decisão, a data dela e a razão são
fabricadas. Nenhuma linha ali pode ser lida como decisão de analista real.

## O que está versionado e o que não está

Versionado: o manifesto com todos os SHA-256, o KEV bruto (CSV + JSON), o
snapshot do KEV processado e o histórico sintético.

Ignorado por tamanho, e regenerável: os `.zip` de `raw/` (92 MB) e
`processed/codeql_emboss_findings.json` (137 MB). **O que torna o run
auditável é o hash no manifesto, não o blob.**

## Reconstruir

```bash
# 1. O artefato ISSTA (94,7 MB). Confira o md5 contra o Zenodo.
curl -L -o datasets/raw/issta2025-artifact.zip \
  "https://zenodo.org/api/records/15200316/files/issta2025-artifact.zip/content"
md5sum datasets/raw/issta2025-artifact.zip   # 41e28ac547e847919d07bb62666d0dc4

# 2. Reingerir. Os SHA-256 gravados no manifesto devem bater com os atuais.
python evaluation/ring0/ingest_kev.py
python evaluation/ring0/ingest_sarif.py
python evaluation/ring0/synthetic_history.py
```

`ISSTA-2025-EMBOSS-Artifact-main.zip` é o export do repositório GitHub e **não
contém os SARIF** — `OSSEmbeddedResults/` só é distribuído pelo Zenodo. Foi
mantido porque estava entre os arquivos de entrada, mas não é usado.
