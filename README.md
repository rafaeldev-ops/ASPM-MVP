# SDIP — Security Decision Intelligence Platform

Working name for a platform that turns large volumes of application-security
findings into a small number of defensible security decisions — not a
scanner, and not another dashboard on top of scanners. Full mission and
constraints: [`CLAUDE.md`](CLAUDE.md).

**Status: MVP ASPM funcional (Sprint 3) · validação Phase 0 ainda em aberto.**
As duas coisas são verdade ao mesmo tempo, e confundi-las é o erro a evitar: o
produto roda e é testado, mas nenhuma organização real forneceu dados ainda, então
a hipótese central continua **não validada**. O que segue é o que é verdade hoje,
não a arquitetura aspiracional.

---

## Rodar a aplicação

### Com Docker (recomendado para demonstrar)

```bash
docker compose up -d --build
```

Duas superfícies, no mesmo processo e no mesmo banco:

| URL | O que é |
|---|---|
| <http://127.0.0.1:8000/aspm> | **O MVP ASPM.** Ativos, riscos priorizados, evidência, remediação, dívida de decisão, revisão e linha do tempo. Clique em **Carregar dataset de demonstração** para popular |
| <http://127.0.0.1:8000/> | O instrumento de backtest de dívida de decisão (anterior, intacto) |
| <http://127.0.0.1:8000/api/v1/overview> | API JSON — todo número das telas é conferível aqui |

Para parar: `docker compose down` — o histórico de
execuções sobrevive num volume nomeado. `docker compose down -v` apaga o histórico
junto.

A porta é publicada em `127.0.0.1` de propósito: a aplicação não tem autenticação nem
isolamento por organização, e não deve ficar exposta na rede.

Na primeira análise o container baixa o catálogo CISA KEV para o volume. É a única
chamada externa, e depois disso ele roda offline — **inclusive nunca mais atualiza o
catálogo sozinho** (ver a limitação L1 em [`docs/PROJECT_STATE.md`](docs/PROJECT_STATE.md)).
Para forçar um catálogo novo: `docker compose down -v` e suba de novo.

### Sem Docker

```bash
pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

Nesse modo o banco fica em `sdip.db` na raiz e o cache da KEV é reaproveitado de
`phase0/.cache/`. As variáveis `SDIP_DB_PATH` e `SDIP_CACHE_DIR` mudam os dois
caminhos; sem elas, nada muda.

### O instrumento de backtest, em `/`

Envie um export de achados fechados (.csv ou .json), ou clique em **Rodar export
sintético**. Cada execução vira uma folha no livro de registro:

| Tela | O que faz |
|---|---|
| `/` | Livro de registro: envio de export e histórico de execuções |
| `/analyses/{id}` | Laudo: as duas pilhas, linha do tempo, e a tabela filtrável por razão de fechamento e por uso em ransomware |
| `/analyses/{id}/session` | Sessão de revisão: a amostra estratificada de 20 achados, uma ficha por achado, para percorrer com o analista |

Nenhuma requisição externa além de uma chamada ao catálogo CISA KEV, cacheada
localmente após a primeira vez. Nada do que é enviado sai da máquina.

### Testes

```bash
python tests/run.py      # 101 testes, sem instalar framework nenhum
```

### O instrumento de linha de comando

A mesma análise existe como script de arquivo único, sem instalar nada — é
o formato pensado para rodar na máquina de um parceiro que não vai instalar
uma aplicação web para avaliar uma ideia:

```bash
cd phase0
python v1_backtest.py --demo
python v1_backtest.py caminho/para/export.csv
```

## The one-sentence thesis

Security teams don't lack scanners; they lack a reliable way to know which
past "close this, it's fine" decisions quietly stopped being fine. A finding
closed as a false positive or accepted risk a year ago can be sitting on a
CVE that entered CISA's Known Exploited Vulnerabilities catalog last week —
and nothing today tells anyone that happened.

`v1_backtest.py` answers exactly that question, for free, from data an
organization already has.

## What is actually validated, not just designed

This repository was built under a rule: a specification that has never been
executed is a draft. Two design documents were run against real inputs
specifically to find out where they were wrong, and both were:

- **The deterministic risk-scoring tree** (`docs/decisions/risk-model.md`)
  left 19% of its own input space undefined and contained a rule that could
  never fire. Both were bugs in a document that had only ever been read, not
  run. Fixed — see [`docs/evaluation/exp-002-risk-model-executed.md`](docs/evaluation/exp-002-risk-model-executed.md).
- **Using EPSS scores to detect "risk went up since we closed this"** was
  tested against real snapshot data and rejected: a single EPSS model
  version change moved 71,885 CVEs across a common threshold in ten days,
  against 306 for ten days of the world actually changing — 235× inflation.
  See [`docs/evaluation/exp-001-epss-model-boundary.md`](docs/evaluation/exp-001-epss-model-boundary.md).
  This is why the backtest above uses KEV, not EPSS.

## Repository map

| Path | What's in it |
|---|---|
| [`docs/PROJECT_STATE.md`](docs/PROJECT_STATE.md) · [`docs/SESSION_HANDOFF.md`](docs/SESSION_HANDOFF.md) | **Comece por aqui.** Estado atual do projeto e a transição da última sessão: o que existe, o que falta, o que está bloqueado e o próximo passo exato. |
| [`app/`](app/) | A aplicação. `domain/` (modelo e árvore de risco, sem I/O), `application/` (os cinco componentes ASPM), `interfaces/` (telas e API), e o instrumento de backtest anterior. |
| [`tests/`](tests/) | 101 testes, só stdlib: `python tests/run.py`. |
| [`phase0/`](phase0/) | Instrumentos de validação: arquivo único, só biblioteca padrão, sem instalação — de propósito, para rodar na máquina de um parceiro. |
| [`docs/adr/`](docs/adr/) | 18 architecture decisions, with alternatives and consequences, not just conclusions. |
| [`docs/product/`](docs/product/) | Product critique, competitive teardown, MVP backlog (MoSCoW), design-partner recruitment kit, [escopo e limitações do MVP ASPM](docs/product/mvp-aspm.md). |
| [`docs/evaluation/`](docs/evaluation/) | Pre-registered Phase 0 validation protocols, and the two experiments above. |
| [`docs/architecture/`](docs/architecture/) | Architecture critique, diagrams, repository structure for the eventual platform. |
| [`docs/data/`](docs/data/) | Domain model and database schema for the full platform. |
| [`docs/api/`](docs/api/) | OpenAPI contract for the full platform. |
| [`docs/threat-model/`](docs/threat-model/) | Threat model and OWASP ASVS 5.0.0 verification mapping. |

## O MVP ASPM

Entregue na Sprint 3 (2026-08-24). Demonstra os cinco componentes de uma ASPM —
Asset Discovery, Risk Correlation, Prioritization, Remediation Guidance e
Continuous Monitoring — mais o diferencial do projeto: evidência com procedência,
histórico de decisões append-only, dívida de decisão e revisão humana.

A priorização é a árvore determinística de
[`docs/decisions/risk-model.md`](docs/decisions/risk-model.md) §4.2 — **não um
LLM**, e os testes comparam as 720 combinações contra o instrumento do `phase0`
para as duas cópias não divergirem em silêncio.

Escopo, decisões e **limitações** em
[`docs/product/mvp-aspm.md`](docs/product/mvp-aspm.md).

> **"O MVP funciona" não é "a hipótese foi validada".** O inventário e as decisões
> do dataset de demonstração são fabricados e marcados como tais em cada tela.
> Nenhum número derivado deles é precisão de produto.

## What is deliberately not built yet

Sem LLM no caminho de decisão, sem integração com scanner ao vivo, sem
multi-tenancy ativa. O MVP implementa a *lógica* de vários itens do **Ring 0**
([`docs/product/mvp-backlog.md`](docs/product/mvp-backlog.md)) — importar decisões
fechadas, enriquecer, diferenciar por data e relatar — mas **nenhum como o backlog
especifica**: não há migration, RLS, worker agendado nem endpoint sob o contrato de
`docs/api/openapi.yaml`. "Existe a lógica" e "o item está feito" são coisas
diferentes. O **Ring 1** (~62 semanas de engenheiro: a plataforma completa)
não vale ser construído enquanto a tese do Ring 0 não for confirmada contra
dado organizacional real — construí-lo antes é literalmente o modo de falha
que este projeto tenta evitar.

Um sinal foi deliberadamente **não** implementado: EPSS como gatilho de
re-litígio. Ele foi testado e rejeitado com dado medido (ver acima). Estaria
fácil adicionar e inflaria os números; é exatamente por isso que não está lá.

## Where this stands right now

Phase 0 validation (`docs/evaluation/phase-0-protocols.md`) is in progress:
pre-registered thresholds, five external design-partner validations planned.
None of those require this repository to grow before they can happen —
recruiting partners and running the backtest on their real data is the
actual next step, not more code.
