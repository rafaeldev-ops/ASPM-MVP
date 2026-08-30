# Project State — SDIP

**Última atualização:** 2026-08-30
**Commit base:** `2607b73` + Fase A (camada de IA) · branch `master`
**Como este arquivo deve ser lido:** é o estado *persistente* do projeto. A transição
específica entre sessões está em [`SESSION_HANDOFF.md`](SESSION_HANDOFF.md); as regras
permanentes estão em [`../CLAUDE.md`](../CLAUDE.md); as decisões arquiteturais e suas
justificativas estão em [`adr/`](adr/). Nada aqui substitui esses arquivos.

> **Convenção de rigor deste documento.** Toda linha é **[F] fato verificado**,
> **[H] hipótese** ou **[D] decisão registrada**. Se algo não foi medido, está escrito
> "não medido" — não está estimado.

---

## Current Phase

**[F] Duas coisas ao mesmo tempo, e confundi-las é o erro a evitar:**

- **Phase 0 — validação: em aberto e bloqueada em V0.** Nenhum export organizacional
  real foi recebido. K1, K2 e K3 continuam **não avaliáveis**.
- **Sprint 3 — MVP ASPM: entregue e testado** (2026-08-24). Aplicação funcional que
  demonstra os cinco componentes de uma ASPM sobre dados públicos reais mais um
  inventário fabricado.

**[F] "O MVP funciona" não é "a hipótese foi validada".** O MVP não mede prevalência
de dívida de decisão em organização nenhuma e não move nenhum critério de kill.

## Current Ring

**[F] Nenhum Ring completo.** O MVP da Sprint 3 implementa a *lógica* de vários itens
do Ring 0 sem a *plataforma* deles (migration, RLS, worker, endpoint sob contrato).
Estado item a item em § Pending.

O `mvp-backlog.md` §3 é explícito: `V1 falsification test → R0`. O gate V1 não foi
executado contra dado real de nenhuma organização, portanto R0-1 não deve começar.

**[F] Cuidado com uma leitura fácil e errada:** o MVP implementa a *lógica* de vários
itens do Ring 0 — importar, correlacionar, priorizar, detectar dívida — mas **nenhum
deles como o backlog especifica**: não há migration, RLS, worker agendado nem endpoint
versionado sob contrato. "Existe a lógica" e "o item está feito" são coisas diferentes.

## Current Objective

**[F] Entregue na Sprint 3:** MVP ASPM funcional e testado
([`product/mvp-aspm.md`](product/mvp-aspm.md)).

**[F] Continua sendo o gargalo: V0.** Um export organizacional real com achados +
decisões + lifecycle. Sem ele, K1/K2/K3 não podem ser avaliados e o Ring 0 não pode
passar — por mais completo que o MVP fique.

**[H] O MVP muda a conversa de V0, não a substitui.** Antes o pedido era "rode este
script e confie no resultado"; agora dá para mostrar o produto funcionando sobre dado
público antes de pedir dado privado.

## Overall Progress

| Camada | Estado |
|---|---|
| Documentação de arquitetura, produto, dados, API, ameaças, avaliação | **[F] Completa como *design*.** 48 arquivos em `docs/` — 46 de design mais os 2 de estado — e **18 ADRs** |
| Instrumentos Phase 0 (`phase0/`) | **[F] 4 instrumentos executáveis, todos rodando** |
| Instrumento de backtest (`/`, commit `021b981`) | **[F] Roda; 3 telas** |
| **MVP ASPM (`/aspm`, Sprint 3)** | **[F] Roda.** Monólito modular, 5 componentes, 6 telas, API `/api/v1`, **101 testes passando** |
| Experimentos executados | **[F] 3** (EXP-001, EXP-002, run do Ring 0 de 2026-08-24) |
| Validação com organização real | **[F] Zero.** Nenhum export de parceiro foi recebido ou analisado |
| Código de produto Ring 0 / Ring 1 conforme o backlog | **[F] Zero itens completos** — ver § Pending |

---

## Completed

### Documentação (commit `f1427b9`, 2026-08-19)

- **[F] 43 documentos** em `docs/` no commit `f1427b9`, incluindo:
- **[F] 18 ADRs** (`docs/adr/0001`…`0018`), 17 com status *Accepted*, **1 com status
  *Proposed*: ADR-0017 (cross-tenant priors) — decisão humana pendente, ver § Blocked.**
  A ADR-0018 (2026-08-24) **emenda a 0015 §1** e é o passo 0 da Fase A.
- **[F] 4 críticas** (arquitetura, produto, segurança, AI/RAG) em `docs/*/critique-*.md`.
- **[F] Modelo de domínio e schema PostgreSQL completos** (`docs/data/`), incluindo
  estratégia de retenção. Nada disso foi implementado.
- **[F] Contrato OpenAPI** (`docs/api/openapi.yaml`, 1143 linhas). Nenhum endpoint
  implementado.
- **[F] Threat model + mapeamento OWASP ASVS 5.0.0** (`docs/threat-model/`), com o CSV
  do ASVS versionado no repositório.
- **[F] Backlog MoSCoW com sizing** (`docs/product/mvp-backlog.md`): Ring 0 ≈ 14 ew,
  Ring 1 ≈ 62 ew, total ≈ 76 ew ≈ 6 meses com 3 engenheiros.
- **[F] Protocolos Phase 0 pré-registrados** (`docs/evaluation/phase-0-protocols.md`),
  com o log de mudança de threshold (§8) **vazio** — nenhum threshold foi movido.
- **[F] Kit de recrutamento de design partner** (`docs/product/design-partner-kit.md`).
- **[F] Kit de anotação V4** (`docs/evaluation/v4-annotation-kit.md`).

### Instrumentos Phase 0 (`phase0/`) — todos arquivo único, só stdlib, sem instalação

| Arquivo | Estado |
|---|---|
| `v1_backtest.py` | **[F] Funciona.** Backtest de dívida de decisão contra CISA KEV. Rodado apenas com `--demo` (dado sintético) |
| `v2_riskmodel.py` | **[F] Funciona.** Executa a árvore de `risk-model.md`; gates `--assert` e `--selftest` passam |
| `v4_corpus.py` | **[F] Funciona.** Constrói e valida o corpus de 50 achados; `--check` passa |
| `v4_kappa.py` | **[F] Funciona como instrumento.** Fleiss κ com CI bootstrap. **Só rodado com `--demo` (dado sintético)** |

### Experimentos executados (resultados reais, dado público)

- **[F] EXP-001 (2026-08-16) — fronteira de versão do modelo EPSS.**
  71.885 CVEs cruzaram o limiar 0.01 para cima na troca v4→v5 em 10 dias, contra 306 num
  controle de 10 dias sob o mesmo modelo — **inflação de 235×, com 0,0% dos scores
  inalterados.** Consequência registrada: **EPSS foi excluído como gatilho de
  re-litígio no V1.** Documento: `docs/evaluation/exp-001-epss-model-boundary.md`.
- **[F] EXP-002 (2026-08-17) — a árvore de risco, executada.**
  A árvore publicada em `risk-model.md` §4.2 deixava **19,4% (112 de 576) do próprio
  espaço de entrada sem regra**, continha uma regra que nunca podia disparar, e não
  produzia discriminação nenhuma para 36% dos achados de um corpus realista. Os dois
  primeiros defeitos foram corrigidos; **o terceiro não é bug e permanece aberto** — é a
  forma do modelo. Documento: `docs/evaluation/exp-002-risk-model-executed.md`.
  **[F] O reparo mudou o tamanho do espaço de decisão:** DP2 ganhou um quinto valor
  (`not_deployed`), então 4×4×3×4×3 = 576 virou 4×5×3×4×3 = **720**. Um número não
  contradiz o outro — 576 é o espaço antes do reparo (e é sobre ele que os 19,4% foram
  medidos), 720 é o espaço de hoje e é o que `v2_riskmodel.py --assert` verifica.

### Aplicação web de demonstração (commit `021b981`, 2026-08-19)

- **[F] Roda.** FastAPI + Jinja2 + SQLAlchemy sobre SQLite (`sdip.db`, gitignorado).
- **[F] 3 telas:** `/` (livro de registro + histórico), `/analyses/{id}` (laudo, com
  filtro por razão de fechamento e por uso em ransomware, e linha do tempo mensal),
  `/analyses/{id}/session` (amostra estratificada de 20 para a sessão de revisão do
  protocolo V1 §1.5).
- **[F] Uma única chamada externa:** o catálogo CISA KEV, cacheado em disco.
- **[F] `app/analysis.py` porta a lógica de `phase0/v1_backtest.py` sem importar dela**
  (a regra em `phase0/README.md` — "Never imported by `app/`" — está respeitada).
  A única adição é o campo `knownRansomwareCampaignUse` da própria KEV.
- **[F] Os dois instrumentos concordam numericamente** no mesmo export sintético:
  900 linhas → 698 analisadas, 202 excluídas, **100 de dívida de decisão**, **88 de
  "fechado apesar de"**. Verificado em 2026-08-23 comparando
  `phase0/decision-debt-report.html` com a tabela `analyses` do `sdip.db`.

### Camada de IA com escolha de provider — Fase A (2026-08-30)

- **[F] Existe LLM no caminho pela primeira vez.** Três providers, e três é teto imposto
  por teste (`test_teto_de_tres_providers`), não por intenção: `null` (determinístico,
  padrão), `ollama` (loopback) e `openai` (terceiro). Governança em
  [`adr/0018`](adr/0018-local-first-provider-selection.md), que emenda a ADR-0015 §1.
- **[F] O bug latente de egresso foi fechado no mesmo commit que tornou o egresso
  possível.** `routes.py` chamava `get_provider().summarize_risk(...)` dentro do handler
  **GET** de `/aspm/findings/{id}`. Era inofensivo enquanto só o `NullProvider` existia;
  no instante em que um provider cloud pudesse ser selecionado, cada visualização de
  página — cada F5, cada prefetch de navegador — enviaria dados de achado para fora.
  Hoje o caminho de renderização chama a síntese determinística diretamente e **análise
  com modelo só acontece por POST consentido**.
- **[F] Egresso é classe verificada, não booleano declarado.** `none` / `localhost` /
  `third_party`. O adaptador Ollama **resolve o host e recusa** se algum endereço não for
  loopback, e constrói o opener com `ProxyHandler({})` — sem isso, `HTTP_PROXY` rotearia
  um pedido "127.0.0.1" pelo proxy corporativo enquanto a tela exibe o selo `local`.
  Os dois mecanismos, cada um com teste próprio.
- **[F] A fronteira de redação é um tipo:** `FindingContext → redact() → RedactedContext`,
  e `analyze()` é template method **final** que faz o `isinstance`. `FindingContext` é
  não-serializável por construção (`__reduce__` levanta). A ADR-0011 pressupõe MyPy
  strict, **que este repositório não tem** — o substituto é estrutural em tempo de
  execução mais um teste de reflexão que afirma que nenhum provider sobrescreve `analyze`.
- **[F] `raw_json` está fora de alcance em todo tier e todo provider, inclusive o local.**
  Idem `Decision.rationale` e `file_path` completo. Provado por canário: uma string única
  plantada no `raw_json` não aparece na carga, no registro nem em nenhum `str()`.
- **[F] Com egresso a terceiros, acerto de detector falha fechado** — `RedactionBlocked`,
  e o contador do servidor falso fica em **zero**. Nunca enviar carga parcialmente
  higienizada a um fornecedor.
- **[F] `confidence` continua determinístico** (completude de evidência, versionado). O
  schema de saída não tem `confidence`, nem proveniência: se tivesse, o modelo poderia
  mentir sobre a própria identidade e o registro deixaria de valer como auditoria.
- **[F] Nenhum outcome move a banda determinística** — afirmado por teste, **inclusive
  para `ok`**. A IA sintetiza; ela não decide.
- **[F] Análise que falha é persistida assim mesmo.** Registrar só sucesso destruiria a
  taxa de recusa, que a ADR-0015 §2 diz poder ser o critério que decide o fornecedor.
- **[F] Zero dependência nova.** `requirements.txt` continua com os mesmos 5 pins;
  transporte por `urllib.request` e credencial por `ctypes` contra `advapi32`.
- **[F] Chave de API no Windows Credential Manager**, nunca no banco e nunca no
  `Setting`. Fora do Windows, `EnvCredentialStore` somente-leitura. `key_source` é
  gravado; a chave nunca é logada, devolvida por endpoint, nem exibida parcialmente.
- **[F] Existe versionamento de schema** (`app/db_migrations.py`, `schema_version` +
  migrações idempotentes), e ele **já foi usado**: a migração 2 acrescenta
  `ai_analysis_id` e `ai_suggested_reason` a `decisions`, que é o primeiro `ALTER` de
  verdade do projeto. Alembic foi descartado porque descobre revisões por caminho em
  disco, o que quebra sob PyInstaller.
- **[F] A concordância analista×modelo é gravada no momento da decisão.** `Decision`
  carrega o que a IA sugeriu **mesmo quando o analista escolheu outra coisa** — é da
  divergência que sai a medida. `agreed_with_ai` devolve `True`/`False`/`None`, e `None`
  significa "não havia sugestão", nunca "discordou": colapsar os dois arruinaria a
  métrica (CLAUDE.md §31). Impossível de reconstruir depois, por isso foi gravado agora.

---

## In Progress

**[F] Nada em edição.** A Sprint 3 foi concluída e commitada; não há trabalho pela
metade em nenhum arquivo versionado.

**[F] A única atividade da sessão anterior visível no disco** é a regeneração dos
artefatos de demo em 2026-08-23 22:45–22:46 (horário local): `phase0/demo-export.csv`,
`phase0/decision-debt-report.html` e uma segunda execução demo gravada no `sdip.db`
(análise `id=2`, `created_at=2026-08-24 01:46 UTC`). Isso corresponde exatamente aos
dois primeiros itens do checklist de
[`demo-presentation-outline.md`](product/demo-presentation-outline.md) — os checkboxes
no documento continuam desmarcados, mas os artefatos existem com esse timestamp.

---

## Pending

### Phase 0 — o que falta, item a item

| Item | Estado real | Bloqueado por |
|---|---|---|
| **V0** — recrutar 5 design partners | **[F] Não iniciado *no repositório*.** O kit existe; o tracker do §6 do kit é um *schema*, e **não existe nenhum arquivo de tracker preenchido**. Se houve contato com algum parceiro, isso não está registrado em lugar nenhum | — (é o gargalo) |
| **V1** — backtest de dívida de decisão | **[F] Instrumento pronto, experimento não executado.** Zero exports reais | V0 |
| **V2** — ablação determinística | **[F] Não executado.** Precisa de 200 achados e labels de analistas do parceiro | V0 |
| **V3** — join vs. retrieval | **[F] Não executado.** Parcialmente executável in-house sobre advisories públicos | Nada estrutural |
| **V4** — probe de concordância (κ) | **[F] Parcialmente pronto.** Corpus `v4-corpus-v1.0` construído e validado; instrumento de análise pronto. **A sessão real com 3 anotadores nunca aconteceu** — não existe `annotations.csv` no repositório | Nada externo. É o item mais barato e mais adiado |
| **V5** — verificação competitiva | **[F] Parcialmente quitado em 2026-08-16** (Brinqa, Phoenix, Cycode, Semgrep verificados; Seemplicity, Apiiro, OX indisponíveis publicamente). **Resta T-1: as quatro perguntas Nucleus numa demo — prazo era 2026-08-22, que já passou, e não há registro de ter acontecido** | Agendar a demo |
| **V6** — instrumento de baseline | **[F] Não executado, e não existe script.** Só o método em `phase-0-protocols.md` §6 | V0 |

### Ring 0 — status por item, após o run de 2026-08-24

**Nada disto é código de produto:** não há banco, migration, tenancy, API nem
agendamento. O que existe em `evaluation/ring0/` é código de avaliação, e os
"parciais" abaixo são todos parciais na mesma direção — **existe a lógica, não
existe a plataforma.**

| Item | Especificado | Estado |
|---|---|---|
| R0-1 | Migration #1, `org_id` em chaves compostas, RLS + FORCE, enums, gate de CI | **Não.** O MVP tem `org_id` em toda tabela (ADR-0003: a coluna é a parte que não dá para retrofitar), mas não há migration, RLS nem gate de CI |
| R0-2 | Import de decisões fechadas → `decision` + `suppression` canônicos com `source_system` | **Parcial, e bem mais perto.** O MVP persiste `Decision` com `source_system`, `classification` obrigatória e a fotografia do conhecimento na data. Falta o objeto `suppression` separado com condições de invalidação |
| R0-3 | KEV + EPSS (versão pinada) + OSV/GHSA com **snapshots, content hashes e authority tiers** | **Parcial.** KEV e EPSS com snapshot, SHA-256, versão e `source_authority`; o MVP grava a versão do catálogo em cada `ScanSnapshot`. Falta OSV/GHSA |
| R0-4 | Detector de estreitamento de faixa afetada | **Não.** Nenhuma fonte deste run tem histórico de advisory |
| R0-5 | Avaliador de condições de invalidação (watch-worker) | **Parcial.** O avaliador roda no pipeline e no reprocessamento, com materiais e não-materiais separados. Não é worker agendado: continua sendo disparado por importação ou por botão |
| R0-6 | `reopen_event` + reconstrução de `evidence_availability` | **Parcial, e bem mais perto.** O MVP persiste `ChangeEvent` (incluindo reabertura) e `DecisionDebt`, com o estado conhecido na data da decisão gravado em cada `Decision`. Falta o nome/contrato exato de `reopen_event` |
| R0-7 | `GET /v1/decision-debt` + artefato estático | **Feito na forma, não no contrato.** `GET /api/v1/decision-debt` existe e responde, com aviso de dado sintético. Não é o contrato de `docs/api/openapi.yaml`, e não há testes de contrato contra aquele arquivo |

**[F] Ring 0 ainda não passou, e o MVP não muda isso.** O gate não é a lista acima —
é **precisão de re-litígio ≥50% em dado histórico de parceiro**, que continua sem
nenhum dado. Um MVP completo com dado público não é evidência sobre o gate.

### Ring 1

**[F] Não iniciado.** 23 itens, ≈62 ew. `mvp-backlog.md` §3: **se o gate do Ring 0
falhar, Ring 1 não deve ser construído.**

---

## Blocked

| O quê | Bloqueado por | Consequência de não resolver |
|---|---|---|
| **[F] Todo o Phase 0 quantitativo (V1, V2, V6)** | **V0** — nenhum design partner registrado | Nenhum gate pode ser avaliado. O projeto não pode nem passar nem falhar |
| **[F] ADR-0017 (cross-tenant priors)** | Status *Proposed*. Requer decisão humana | `docs/adr/README.md`: "bloqueia a narrativa de moat, não o build" |
| **[F] V5 / T-1 (as quatro perguntas Nucleus)** | Só uma demo do produto responde. **Prazo pré-registrado 2026-08-22 vencido em 2026-08-23** | `competitive-teardown.md` §167: "o pitch sai com uma alegação competitiva não verificada" |
| **[H] A demo de 2026-08-24** | Nada técnico. Os artefatos estão gerados e a aplicação sobe | — |

---

## Recent Changes

| Quando | O quê |
|---|---|
| 2026-08-19 03:03 | Commit `f1427b9`: primeiro commit — `phase0/` + toda a documentação (44 arquivos, 17 ADRs) |
| 2026-08-19 04:38 | Commit `021b981`: aplicação web — 10 arquivos em `app/`, 13 arquivos no commit (com `requirements.txt` e o README reescrito), 1.797 linhas inseridas |
| 2026-08-23 22:45 | **[F] Sem commit.** Regeneração de `phase0/demo-export.csv` e `phase0/decision-debt-report.html` (artefatos gitignorados, preparação da demo) |
| 2026-08-23 22:46 | **[F] Sem commit.** Segunda execução demo gravada em `sdip.db` (gitignorado) |
| 2026-08-23 (esta sessão) | Criação de `docs/PROJECT_STATE.md` e `docs/SESSION_HANDOFF.md`; `CLAUDE.md` ganhou o §0 "Start here, every session"; `README.md` ganhou uma linha no mapa. Commit `3fd89d0` |
| 2026-08-23 | **Containerização da aplicação web:** `Dockerfile`, `docker-compose.yml`, `.dockerignore`, e duas variáveis de ambiente (`SDIP_DB_PATH`, `SDIP_CACHE_DIR`). **Defaults inalterados.** Commit `326840a` |
| 2026-08-24 | **Fase A, passo 0 — governança.** `docs/adr/0018-local-first-provider-selection.md` (emenda a ADR-0015 §1): egresso é escolha do usuário, teto de três providers imposto por teste, `confidence` continua determinístico, `raw_json` fora de alcance em todo tier. A linha WON'T de `mvp-backlog.md` §2.5 ganhou o registro do gatilho que disparou, com o texto original preservado |
| 2026-08-24 | **Sprint 3 — MVP ASPM funcional.** Monólito modular em `app/` (domain / application / interfaces), 5 componentes ASPM, 6 telas, API `/api/v1`, dataset de demonstração com proveniência. **B2 e B3 corrigidos.** **101 testes passando.** Detalhe: [`product/mvp-aspm.md`](product/mvp-aspm.md) |
| 2026-08-30 | **Fase A, passos 1 a 9 — camada de IA.** `app/infrastructure/http.py` e `credentials.py`, `app/db_migrations.py`, `Setting` e `AIAnalysis`, o pacote `app/application/ai/` (settings, provider, context, detectors, redaction, prompt, contract, providers, service), **o conserto do egresso em GET**, tela de configuração, tela de pré-voo e as rotas de análise. **169 testes passando** (101 + 68). Quatro módulos novos: `test_migrations.py`, `test_credentials.py`, `test_ai_provider.py` e `test_ai_privacy.py`. `Decision` ganhou `ai_analysis_id` e `ai_suggested_reason` (migração 2, o primeiro `ALTER` de verdade) para a concordância analista×modelo ser mensurável |
| 2026-08-24 | **Run de validação do Ring 0 com dados públicos reais.** Ingestão de CISA KEV (273 entradas), CodeQL SARIF do artefato ISSTA 2025 (100.627 achados) e snapshot EPSS (359.229 CVEs), todos com proveniência e SHA-256. Motor de dívida de decisão, 31 testes golden/adversariais, 4 experimentos. **Dois defeitos encontrados em `phase0/v1_backtest.py`.** Relatório: [`evaluation/ring0-real-data-validation.md`](evaluation/ring0-real-data-validation.md) |

---

## Important Architectural Decisions

As decisões estão nos ADRs; aqui ficam apenas as que mais restringem o próximo passo.
**Não desfaça nenhuma sem ler o ADR correspondente.**

| # | Decisão | Por que não desfazer |
|---|---|---|
| **ADR-0001** | Observações append-only, identidade versionada | Irreversível: histórico anterior à mudança não pode ser fabricado |
| **ADR-0003** | Tenancy no dia 1 (`org_id` na frente das chaves, RLS FORCE) | ~2 semanas agora vs. ~4 meses-engenheiro depois |
| **ADR-0007** | O policy engine decide; o modelo recomenda e pode escalar, **nunca suprimir** | É onde mora toda a exposição de responsabilidade |
| **ADR-0011** | Fronteira de redação por tipo; `no_code` por padrão; ingestão push-only | Um segredo vazado não é recuperável |
| **ADR-0012** | Cadeia de hash de auditoria + `evidence_availability` em todo registro de decisão | Retrofit de dado imutável é a pior classe de migração |
| **ADR-0016** | Não existe supressão terminal: `deprioritized_until(conditions[])` | É a tese do produto inteira |
| **ADR-0013** | Pinagem de versão, snapshot, authority tiers no conhecimento externo | Confirmado por EXP-001 com número medido |

**[D] Decisão de sequenciamento, registrada em `mvp-backlog.md` §0 e §3:** Ring 0 antes
de Ring 1 não é conveniência de faseamento — é a única ordem em que a empresa descobre
se a tese é verdadeira **antes** de gastar seis meses na plataforma.

**[F] Lacuna de registro (inconsistência, não decisão):** a aplicação web em `app/`
introduziu SQLite + SQLAlchemy + FastAPI como camada de persistência e apresentação, e
**essa escolha não tem ADR.** A justificativa existe, mas só no docstring de
`app/db.py` e no README. Ver § Known Limitations, item L6.

---

## Rejected Approaches

**[F] Rejeitados com dado medido — não desfazer sem novo experimento:**

- **EPSS como gatilho de re-litígio no V1.** Rejeitado por EXP-001 (235× de inflação).
  Está fácil de adicionar e inflaria os números do relatório; é exatamente por isso que
  não está lá. Qualquer Claude futuro que "adicione EPSS porque melhora os números"
  está desfazendo um resultado experimental.
- **Comparação as-of-hoje em vez de as-of-data-de-fechamento.** O `v1_backtest.py`
  documenta: ler as-of-hoje acende ~um quarto de um estate por razões que não têm
  relação com nada ter mudado.
- **Fundir "dívida de decisão" com "fechado apesar de já estar na KEV".** São histórias
  diferentes; fundir infla o número numa direção que quem recebe o relatório notaria.

**[F] Rejeitados por design, com o gatilho que mudaria a decisão** — a tabela WON'T em
`mvp-backlog.md` §2.5 (reachability, autofix, workflow de remediação, graph database,
Kafka/Kubernetes, multi-agent, fine-tuning, abstração multi-provider de LLM, supressão
automática sem revisão humana, credencial de leitura de repositório). Cada linha tem o
gatilho que a reabriria. **Não reabra nenhuma sem o gatilho.**

---

## Current Experimental Results

**[F] Só dois experimentos produziram resultado real. Ambos usam dado público, nenhum
usa dado de organização.**

| ID | Data | Resultado | Efeito |
|---|---|---|---|
| EXP-001 | 2026-08-16 | 71.885 vs 306 cruzamentos de limiar (235×); 0,0% dos scores EPSS inalterados na fronteira de modelo | EPSS excluído do V1; ADR-0013 confirmado com número |
| EXP-002 | 2026-08-17 | Árvore de risco: 19,4% do espaço de entrada sem regra; 1 regra morta; 36% sem discriminação num corpus realista | 2 defeitos corrigidos; o terceiro achado permanece aberto |
| **Ring 0 run** | **2026-08-24** | Ver [`evaluation/ring0-real-data-validation.md`](evaluation/ring0-real-data-validation.md). 100.627 achados CodeQL e 273 entradas KEV reais ingeridos; **100% unmatched por identidade** (CodeQL não emite CVE); **22.358 CVEs a ±10% do limiar 0,01 de EPSS**; 31 testes passam, 0 vazamentos temporais em 642 consultas | **2 defeitos abertos em `phase0/v1_backtest.py`** (§ Known Bugs, B2 e B3) |

**[F] O que NÃO é resultado experimental, e não pode ser citado como se fosse:**
a saída de `python v4_kappa.py --demo` (κ_holistic 0.190, κ_derived 0.759, delta +0.570).
**Isso é dado sintético gerado pelo próprio script** para exercitar o pipeline. O V4 real
nunca rodou. Se esse número aparecer em qualquer slide ou documento como medição, é
fabricação.

### Follow-ups em aberto dos experimentos

**[F] Os dois experimentos deixaram 10 follow-ups, e eles não estão rastreados em lugar
nenhum além do rodapé dos próprios documentos.** Nenhum foi executado, exceto onde
indicado. Reproduzidos aqui para que não sumam:

**De EXP-001** (`exp-001-epss-model-boundary.md` §7):

| # | Item | Estado |
|---|---|---|
| F-1 | Medir a fronteira v3→v4 (2025-03-10 vs 2025-03-20) — 235× é típico ou v5 foi anômalo? | Aberto |
| F-2 | Fixture de fronteira de modelo no eval harness: dois snapshots, assertar **zero** `ReopenEvent` atribuível ao bump | Aberto (não há eval harness) |
| F-3 | Verificar se a mesma descontinuidade existe em KEV (mudança de schema) e NVD CVSS (rescoring) | Aberto |
| F-4 | Decidir o threshold de EPSS **junto com** o tratamento de época de modelo | Aberto |

**De EXP-002** (`exp-002-risk-model-executed.md` §8):

| # | Item | Estado |
|---|---|---|
| F-1 | Decidir o que a camada determinística pode dizer sobre SAST — e se a resposta for "nada", dizer isso na ADR-0008 e re-derivar a alegação dos 80% e o modelo de custo a partir de um teto de 65% | **Aberto, e é o de maior consequência: a economia do ADR-0008 depende dele** |
| F-2 | Reportar a ablação padrão **por classe de achado**, nunca misturada | Aberto |
| F-3 | Promover a árvore reparada para `risk-model.md` §4.2 com o fixture de 720 linhas | **[F] Já feito** — `risk-model.md` §4.2 tem as 20 linhas e a nota do espaço de 720. **A tabela de follow-ups do exp-002 está desatualizada** e ainda diz que "o documento publica uma árvore que não termina" |
| F-4 | Assertion de CI: a árvore deve ser total e nenhuma linha pode ser morta | **[F] Meio feito** — a assertion existe (`v2_riskmodel.py --assert`) e passa; **não existe CI para rodá-la** |
| F-5 | Reconsiderar se o fundamento de deprioritização "low+enforcing" vale a pena com 2 de 720 combinações | Aberto |
| F-6 | Decidir se `not_deployed` deve também barrar elegibilidade de auto-deprioritização, separado da banda | Aberto |

---

## Current Test Status

**[F] Existe suíte de testes desde a Sprint 3: `tests/`, 169 testes, `unittest` da
stdlib.** Continua sem `pytest`, sem `pyproject.toml`, sem `.github/workflows/`, sem
lint e sem type checking. O `repository-structure.md` prevê tudo isso; só a suíte existe.

**[F] A ausência de type checking passou a ter consequência de segurança.** A ADR-0011
impõe a fronteira de redação por tipo, *verificada por MyPy strict*. Sem MyPy o portão
de build não existe; o substituto é estrutural e está descrito em `adr/0018` §4. Isso
não é equivalente — é o melhor disponível, e está registrado como tal.

```
python tests/run.py     # 169 testes · 0 falhas · 0 erros · 0 pulados (2026-08-30)
```

| Módulo | Testes | Cobre |
|---|---:|---|
| `test_closure_reasons.py` | 14 | **Regressão de B2 e B3** + divergência documentada com `phase0/v1_backtest.py` |
| `test_risk_tree.py` | 17 | Totalidade da árvore, linhas mortas, fail-closed, **paridade das 720 combinações com o instrumento do phase0**, EPSS não move banda |
| `test_pipeline.py` | 26 | Asset discovery, ingestão idempotente, SARIF, correlação, priorização, remediação, monitoramento |
| `test_decision_debt.py` | 18 | Regra temporal, as duas pilhas, escopo de B2/B3, revisão append-only |
| `test_e2e.py` | 14 | Fluxo import→review e os 9 casos da demonstração |
| `test_migrations.py` | 11 | O runner de schema, e sobretudo o **banco que já existia**: um `decisions` sem as colunas novas ganha as colunas sem perder linha, e a decisão antiga não ganha vínculo inventado. Mais: idempotência, tabela ausente sem levantar, e `SCHEMA_VERSION` acompanhando a lista |
| `test_credentials.py` | 11 | Round-trip **real** contra o Windows Credential Manager (grava, lê, sobrescreve, apaga, unicode, blob longo), env store somente-leitura, e que `info()`/`describe()` não devolvem a chave **nem os últimos quatro caracteres dela** |
| `test_ai_provider.py` | 23 | Seleção e precedência, teto de três, disponibilidade sem sondar o caminho quente, loopback verificado, **`HTTP_PROXY` ignorado**, timeout, malformada, recusa, `choices: []`, retry só onde deve, prompt byte-estável |
| `test_ai_privacy.py` | 23 | **A fronteira de redação.** Canários de `raw_json` e `rationale`, `file_path` só como forma no externo, detector sem falso positivo em KEV+EPSS real, bloqueio com contador em zero, contexto cru rejeitado por tipo, reflexão sobre `analyze`, nenhum outcome move a banda, fundamentação dura de `evidence_ids` |
| `test_api.py` | 12 | 6 telas, filtros, 404, contrato JSON, backtest legado intacto |

**[F] O que existe como verificação executável são os gates de `phase0/README.md`.
Todos foram executados em 2026-08-23 nesta sessão, no diretório `phase0/`,
com Python 3.14.5:**

| Comando | Resultado | Saída |
|---|---|---|
| `python v2_riskmodel.py --assert` | **PASS**, exit 0 | árvore total (720 combinações), sem linhas mortas (20 linhas), nenhum caminho deprioriza `exploitation=active` |
| `python v2_riskmodel.py --selftest` | **PASS**, exit 0 | 3 exemplos de `risk-model.md` §11 batem (`act_now`, `deprioritize_candidate`, `track`) + 1 verificação de inelegibilidade |
| `python v4_corpus.py --check --offline` | **PASS**, exit 0 | "All stratum assertions hold"; 1 `WARN` informativo (18 rule ids verificados upstream). Rodado `--offline` usando `phase0/.cache/` |
| `python v4_kappa.py --demo` | roda, exit 0 | **Dado sintético. Não é resultado.** Ver § Current Experimental Results |

**[F] Smoke test da aplicação web, executado em 2026-08-23 nesta sessão** (uvicorn na
porta 8137, com o `.venv/` do repositório; servidor encerrado depois):

| Verificação | Resultado |
|---|---|
| `python -c "import app.main"` | OK |
| `GET /health` | 200 · `{"status":"ok"}` |
| `GET /` | 200 |
| `GET /analyses/2` | 200 |
| `GET /analyses/2?kind=despite` | 200 |
| `GET /analyses/2/session` | 200 |
| `GET /analyses/999` (inexistente) | 404 |

**[F] Testes do Ring 0, executados em 2026-08-24** (`python evaluation/ring0/test_ring0.py`,
Python 3.14.5, exit 0):

| Grupo | Resultado |
|---|---|
| Casos positivos P1–P3 | **6/6** |
| Casos negativos N1–N7 | **10/10** |
| Adversariais A–F | **7/7 executáveis**; **E declarado NÃO TESTÁVEL** (sem histórico de advisory nas fontes) |
| Vazamento temporal L1–L4 | **7/7**, incluindo varredura das 642 consultas do run: **0 revelaram data futura** |
| **Total** | **31 passaram, 0 falharam, 1 skip declarado** |

**[F] Verificação no container, executada em 2026-08-23** (`docker compose up -d --build`,
imagem `sdip-web:local`, volume nomeado `aspm_sdip-data` em `/data`):

| Verificação | Resultado |
|---|---|
| `docker compose build` | OK |
| `GET /health` · `GET /` · `/static/css/app.css` · inexistente | 200 · 200 · 200 · 404 |
| `HEALTHCHECK` do Docker | `healthy` |
| `POST /analyses` com `use_demo=1` | 303 → `/analyses/1`. **Baixou o catálogo KEV para o volume**, catálogo `2026.08.21`, 1.674 entradas |
| **`POST /analyses` com upload de arquivo real** (`demo-export.csv`, 69KB, multipart) | 303 → `/analyses/2`. **Fecha a lacuna: o caminho de upload estava marcado como não testado** |
| `docker compose restart` + releitura do banco | As duas análises sobreviveram. **Volume persiste** |

**[F] Ainda não testado:** o limite de 25MB, e o parsing de um export de ferramenta real
(DefectDojo, Jira, GitHub). O que foi testado é o CSV sintético do próprio projeto.
Segundo `design-partner-kit.md`, um CSV plano e o JSON aninhado de dismissed alerts do
GitHub foram verificados em sessão anterior — sem teste automatizado que prove isso hoje.

---

## Known Bugs

| # | Onde | O quê |
|---|---|---|
| **B1** | `app/analysis.py`, docstring de `run_analysis` | Diz retornar 6 valores (`summary, debt, despite, sample, det tuple, excl Counter`); a função retorna 5 e `app/main.py` desempacota 5. Docstring errado, código correto. Cosmético |
| **B2** | `phase0/v1_backtest.py`, `FIXED_WORDS` | **`classify_reason("Mitigated")` → `"fixed"`**, então achados mitigados são descartados como "não é uma decisão de não agir". **Mitigado não é corrigido:** um achado fechado porque existe controle compensatório é exatamente a decisão de não remediar, e a ADR-0016 diz que essa supressão é perecível. `Mitigated` é status do DefectDojo — a primeira fonte listada no `design-partner-kit.md`. Medido em 2026-08-24: **33 de 360 decisões sumiram do relatório**, e removê-las do motor novo reproduz o resultado do instrumento exatamente (94/92). **Aberto** |
| **B3** | `phase0/v1_backtest.py`, `FP_WORDS` | **`classify_reason("Won't Fix")` → `"false_positive"`**. Não altera o total de dívida (ambos ficam em escopo), mas corrompe a divisão entre as duas pilhas — que é exatamente a suposição **A4** de `competitive-positioning.md` §7, a que o protocolo diz nunca ter sido medida. **Aberto** |

**[F] B2 e B3 não foram corrigidos.** `v1_backtest.py` é o instrumento que um parceiro
roda, e havia uma apresentação em 2026-08-24. A correção é de uma linha em cada regex e
é decisão de quem apresenta — mas **B2 sub-reporta dívida de decisão em silêncio** em
qualquer export com status `Mitigated`.

**[F] Nenhum outro bug conhecido.** Isso não significa que não existam — significa que
não existe suíte de testes de produto que pudesse encontrá-los.

---

## Known Limitations

| # | Limitação |
|---|---|
| **L1** | **[F] O cache da KEV nunca expira, e isso foi confirmado empiricamente em 2026-08-23.** `load_kev()` (em `app/analysis.py` e em `phase0/v1_backtest.py`) só baixa se o arquivo não existir. O cache do host é de 2026-08-16: catálogo `2026.08.14`, 1.665 entradas. O container, com volume vazio, baixou `2026.08.21` — **1.674 entradas, 9 a mais, 7 dias de diferença**. As duas máquinas rodam o mesmo código contra catálogos diferentes e nada avisa. Numa máquina de parceiro rodando pela primeira vez isso é irrelevante; numa que já rodou, uma execução meses depois sub-reporta dívida de decisão **em silêncio** |
| **L2** | **[F] Um gatilho e meio, não sete.** V1 testa "entrou na KEV depois do fechamento" (exato) e o seu inverso. Estreitamento de faixa, exploit publicado, EPSS, alcançabilidade e mudança de dono **não são testáveis** com um export. Está declarado no `v1_backtest.py` e no protocolo — e precisa continuar sendo dito ao parceiro *antes*, não depois |
| **L3** | **[F] Só achados com CVE entram na análise.** Achados só-de-regra (SAST, secrets) são excluídos por construção: a KEV é indexada por CVE. No export sintético isso descarta 202 de 900 linhas (22%) junto com as outras exclusões |
| **L4** | **[F] Sem tenancy, sem autenticação, sem autorização na aplicação web.** É um instrumento local de uma pessoa. Qualquer uso multi-usuário viola ADR-0003 e ADR-0011 |
| **L5** | **[F] Detecção de coluna é heurística.** `detect()` escolhe id/data/razão por regex sobre os nomes das colunas e imprime a escolha. Um palpite errado fica visível, não silencioso — mas continua sendo palpite |
| **L6** | **[F] `app/` ocupa o mesmo caminho que `repository-structure.md` reserva para o monólito modular** (`app/domain/`, `app/application/`, `app/infrastructure/`, `app/interfaces/`). Hoje `app/` são 3 módulos planos. Quando o Ring 0 começar, isso precisa ser resolvido explicitamente — mover a demo para `demo/` ou reescrever o documento — e não por acidente |
| **L7** | **[F] `app/analysis.py` lê o cache dentro de `phase0/.cache/`**, e `phase0/README.md` diz que `phase0/` é "deleted or promoted after the V1 gate". Deletar `phase0/` não quebra a aplicação (ela recria o diretório e rebaixa o catálogo), mas deixa um diretório órfão. Acoplamento por caminho, não por import |
| **L10** | **[F] Os dois corpora reais do run de 2026-08-24 não se juntam.** 100% unmatched por identidade: o CodeQL não emite CVE em nenhum dos 100.627 achados, e o KEV é indexado por CVE. Consequência de desenho: os achados reais do CodeQL **não podem ser sujeito** do teste de dívida de decisão, e foi por isso que o experimento usou histórico sintético sobre CVEs reais. Vínculo por CWE é de **classe**, não identidade, e não autoriza re-litígio. **Um export de SCA de parceiro (Trivy, Snyk, Dependabot) traria CVE e resolveria isso** — é a diferença entre SAST e SCA |
| **L11** | **[F] Não há ground truth de falso positivo no artefato ISSTA.** Verificado: o zip traz os SARIF, `embedded-repos.json` e dois PDFs. Os 709 defeitos confirmados do paper estão em prosa, não em arquivo de labels. Nenhuma métrica de qualidade de detecção do CodeQL é reportável a partir dele |
| **L12** | **[F] Janela de KEV de 12 meses deixa 31% da população indeterminável.** 111 de 360 decisões do run caem em `UNKNOWN_OUTSIDE_WINDOW` — o motor recusa dizer `NOT_IN_KEV` para um CVE que pode ter entrado antes da janela. O catálogo completo (1.674 entradas desde 2021-11) eliminaria isso |
| **L9** | **[F] O export sintético do `--demo` depende do catálogo KEV, então os números do demo mudam quando o catálogo muda.** `demo_export_rows()` sorteia CVEs de `sorted(kev)`; um catálogo com 9 entradas a mais produz um export diferente com a mesma seed. Medido em 2026-08-23: sob `2026.08.14` o demo dá **100 dívida / 88 fechado-apesar-de**; sob `2026.08.21` dá **104 / 84**. **A análise em si é estável** — o *mesmo* CSV enviado por upload dá 100/88 nos dois catálogos. Ou seja: o número do botão "Rodar export sintético" não é reproduzível entre máquinas; o número de um arquivo enviado é |
| **L13** | **[F] Nenhum LLM de verdade foi executado. Nem uma vez.** Os 46 testes da camada de IA rodam contra servidores falsos em `127.0.0.1`. Isso prova transporte, retry, timeout, validação, fundamentação e a fronteira de redação — **e não prova nada sobre qualidade de saída de modelo nenhum.** Não existe medida de taxa de recusa, de aderência a schema, de latência real, de custo por achado nem de aderência à evidência. A ADR-0015 §2 exige um benchmark antes de escolher fornecedor; esse benchmark **não foi feito**, e a camada existe para torná-lo possível, não para substituí-lo |
| **L14** | **[F] O suporte a structured output varia por modelo no Ollama e não foi verificado em nenhum.** A tela oferece um botão que roda a análise sobre um achado sintético e reporta se o modelo respeita o schema — o botão existe, o resultado para qualquer modelo específico não está registrado |
| **L15** | **[F] A taxa de falso negativo do detector de segredo é desconhecida.** A resposta real da ADR-0011 são canários em CI, e **não há CI**. O que sustenta a fronteira são os controles estruturais — tier `no_code` e a exclusão de `raw_json`, `rationale` e caminho completo — e o regex é defesa em profundidade, **não a fronteira**. Ler L16 junto: a fronteira não tem portão de build |
| **L16** | **[F] A fronteira de redação da ADR-0011 é verificada em tempo de execução, não por type checker.** A ADR pressupõe MyPy strict; o repositório não tem MyPy, nem lint, nem CI. O substituto (template method final, contexto não-serializável, teste de reflexão) é o melhor disponível **e não é equivalente** — um provider novo escrito fora da suíte não é impedido de nada por ferramenta alguma |
| **L8** | **[F] O roteiro da demo (2026-08-24) demonstra o CLI, não a aplicação web.** O roteiro foi escrito ~1h30 antes de a aplicação existir (mesmo dia, commits `f1427b9` 03:03 e `021b981` 04:38) e nunca foi atualizado. **Qual dos dois demonstrar é uma decisão em aberto** — ver `SESSION_HANDOFF.md` |

---

## Inconsistências registradas (encontradas nesta sessão, **não corrigidas**)

Índice único do que a documentação afirma e o repositório não sustenta. Nenhuma foi
corrigida: um checkpoint não altera código nem arquitetura.

| # | Onde | A inconsistência |
|---|---|---|
| I1 | `README.md` "O que existe cobre o núcleo do **Ring 0**" | Verdadeiro como conceito, falso como implementação — nenhum dos sete itens R0-1…R0-7 está implementado como especificado. Ver § Current Ring e § Pending |
| I2 | `exp-002` §8, follow-up F-3 | Diz que `risk-model.md` "atualmente publica uma árvore que não termina". **Já não é verdade** — §4.2 foi promovida com as 20 linhas e o espaço de 720 |
| I3 | `exp-002` §8, follow-up F-4 | Pede uma assertion de CI. A assertion existe e passa; **o CI não existe** |
| I4 | `phase0/README.md` "CI gates" | Lista três comandos como *CI gates*. Não existe CI neste repositório — são gates manuais |
| I5 | `architecture/repository-structure.md` | Descreve `app/domain/`, `app/application/`, `app/infrastructure/`, `app/interfaces/`. O `app/` real são 3 módulos planos. Mesmo caminho, estruturas incompatíveis. Ver L6 |
| I6 | `product/demo-presentation-outline.md` §4 e checklist | Demonstra o CLI e diz "sem subir servidor". A aplicação web existe desde 1h30 depois de o roteiro ser escrito e não está no roteiro. Ver L8 |
| I7 | `app/db.py` + `README.md` | A escolha de SQLite/SQLAlchemy/FastAPI está justificada apenas em docstring e README. **Sem ADR**, contra CLAUDE.md §38 se a decisão for material. Ver `SESSION_HANDOFF.md` |
| I8 | `app/analysis.py`, docstring de `run_analysis` | Assinatura de retorno errada. Ver B1 |
| I9 | `design-partner-kit.md` §6 | Define o schema de um tracker de parceiros. **O arquivo do tracker não existe** |
| I10 | `phase0/v1_backtest.py` × `docs/adr/0016` | O instrumento descarta achados `Mitigated` como corrigidos; a ADR-0016 trata mitigação como supressão perecível — o caso central do produto. Ver B2 |
| I11 | `datasets/raw/ISSTA-2025-EMBOSS-Artifact-main.zip` | É o export do GitHub e **não contém os SARIF** (`OSSEmbeddedResults/` só existe no Zenodo). O artefato correto foi baixado e verificado por md5; o arquivo antigo foi preservado mas não é usado |

---

## Security Considerations

**[F] Verdadeiro hoje, e é uma propriedade de produto, não um acidente:**

- Nenhuma credencial de entrada. Nenhum token. Nenhum acesso a repositório.
- Uma única saída de rede: `https://www.cisa.gov/.../known_exploited_vulnerabilities.json`.
  Sem telemetria, sem callback, sem upload.
- Tudo o que é enviado à aplicação fica em `sdip.db`, local e gitignorado.
- **[D]** Essa propriedade é o que torna o pedido do V0 respondível (`design-partner-kit.md`
  §0, Modo A: *"o parceiro roda, nós não"*). **Quebrá-la quebra o argumento de venda**,
  não só a arquitetura.

**[F] O que ainda não vale para a aplicação web:** sem autenticação, sem RBAC, sem
tenancy, sem audit log, sem rate limiting, sem headers de segurança. O upload é lido
inteiro em memória com limite de 25MB. `docs_url=None` desativa `/docs` e `/redoc`.
Isso é aceitável para um instrumento local de uma pessoa e **inaceitável para qualquer
coisa exposta em rede.**

**[F] A superfície de prompt injection deixou de ser zero em 2026-08-30.** Até a Fase A
esta seção dizia "zero, não existe LLM no caminho". Existe agora, e a linha antiga está
substituída em vez de removida porque a mudança é exatamente o tipo de coisa que uma
revisão de segurança precisa conseguir datar.

O que contém a superfície hoje, e é pouco de propósito: o modelo **não tem ferramentas**,
não tem rede a partir dele, não escreve em memória, **não altera banda, score nem
estado**; os `evidence_ids` que ele cita são validados contra o conjunto que foi
entregue a ele (id que existe no banco mas foi cortado pelo orçamento continua sendo
alucinação e rejeita a resposta inteira); conteúdo não confiável vai em bloco delimitado
e rotulado; a saída é escapada, nunca `|safe`, nunca em `href`/`src` e **não é renderizada
como Markdown** — carregamento remoto de imagem é o canal de exfiltração sem clique que a
ADR-0007 nomeia.

**Deliberadamente fora:** detector de injeção de prompt. A ADR-0007 diz que detector não
é controle, e um detector parcial convida a uma confiança que ele não merece.

**[F] O egresso é escolha explícita do usuário e o padrão continua sendo `none`.** A
propriedade "nenhum dado sai desta máquina" **deixa de valer por configuração** — não por
acidente: exige selecionar um provider, e cada análise a terceiros passa por uma tela de
pré-voo que mostra a carga redigida de verdade, não uma descrição dela. Consentimento é
por análise; "não perguntar de novo nesta sessão" vale para `none` e `localhost` e
**nunca** para `third_party`.

**[F] O que o registro `ai_analyses` nunca grava:** o texto do prompt, a resposta além dos
campos validados, a chave de API, qualquer valor de segredo casado pelo detector (só
campo, detector e contagem), `raw_json` e caminho completo de arquivo.

**[F] Sem cadeia de hash em `ai_analyses`.** A ADR-0012 §1.3 é explícita que cadeia sem
ancoragem externa não vale contra quem é dono do banco, e entregar metade convidaria a
alegação de "log de auditoria imutável" que a própria ADR chama de marketing.
`context_hash` e `prompt_hash` entram, porque são insumo de reprodutibilidade.

---

## Current Metrics

**[F] Nenhuma métrica de produto foi medida.** Não existe baseline de nenhuma
organização, não existe tempo de triagem medido, não existe taxa de concordância de
analista, não existe precisão de re-litígio.

**[F] Os únicos números reais do projeto** são os de EXP-001 e EXP-002 (§ Current
Experimental Results) e as contagens do export **sintético** abaixo, que medem o
instrumento, não o mundo:

| Número (dado sintético, `--demo`) | Valor |
|---|---|
| Linhas no export | 900 |
| Analisadas | 698 |
| Excluídas | 202 |
| Dívida de decisão | 100 |
| Fechado apesar de já estar na KEV | 88 |
| Catálogo KEV usado | `2026.08.14` |

**[F] Métricas do run do Ring 0 de 2026-08-24** — todas contra **histórico de decisões
sintético**, não contra organização nenhuma:

| Métrica | Valor | Contra o quê |
|---|---:|---|
| Decision-debt precision | 1,000 (109/109) | **rótulo de construção do dataset sintético** |
| Decision-debt recall | 1,000 (109/109) | idem |
| False re-litigation rate | 0,000 | idem |
| Candidate inflation sob 360 eventos de EPSS | 1,00× | medida do motor |
| Evidence coverage | 1,000 | evidência real, rastreável |
| Temporal correctness | 1,000 (642 consultas, 0 vazamentos) | auditoria de consultas |

> **[F] Precision 1,0 não é resultado de produto e não pode ir para slide.** O ground
> truth é o rótulo com que o próprio dataset foi construído — as decisões do bucket A
> foram fabricadas para serem anteriores à entrada no KEV. Prova que a implementação
> segue a especificação em 321 casos. **Não é K3**, e não diz nada sobre frequência de
> dívida de decisão no mundo.

**[F] Nenhum critério de kill pré-registrado foi avaliado ainda:**

| Data | Critério | Estado |
|---|---|---|
| 2026-08-22 | V5 / Nucleus verificado | **[F] Prazo vencido, sem registro de conclusão** |
| — | **K1 / K2 / K3** | **[F] Continuam NÃO AVALIÁVEIS após o run de 2026-08-24.** Zero parceiros. O 1,000 acima é contra rótulo sintético e não é K3 |
| 2026-09-30 | ≥3 de 5 parceiros confirmam que queriam saber (K1) e ≥1 nomeia um achado (K2) | Não avaliado — V0 não começou |
| 2026-10-31 | Precisão de re-litígio ≥50% (K3) | Não avaliado |
| 2026-12-31 | ≥2 parceiros pagando ≥$30k | Não avaliado |
| 2026-12-31 | COGS de inferência ≤$750/cliente/mês | Não aplicável ainda (não há inferência) |

---

## Next Exact Task

**[F] A apresentação de 2026-08-24 passou e o resultado dela não está registrado neste
arquivo.** Quem retomar precisa registrá-lo antes de qualquer outra coisa — inclusive se
o resultado foi "nada aconteceu". O item V0 vive ou morre nesse registro.

1. **Criar `docs/product/partner-tracker.md`** com os campos de `design-partner-kit.md`
   §6 (stage, sinal Q1, pilha fechada existe, sistema de origem, tamanho FP vs risco
   aceito, resposta K1, achado K2 verbatim, resposta Q3 verbatim), **incluindo as
   negativas**. Continua não existindo.
2. **Executar o pedido do §8 do roteiro** — export de 12 meses de achados fechados +
   60 minutos de revisão. Esse pedido *é* o item V0, e continua sendo o gargalo.
3. **[H] Rodar um modelo de verdade uma vez** e registrar o que sair (L13). Com Ollama
   instalado o custo é zero e o resultado decide se a camada da Fase A é utilizável ou
   se o schema precisa mudar. Enquanto isso não acontecer, "a IA funciona" significa
   apenas "o transporte e a fronteira funcionam".

## Recommended Next Steps

Em ordem de valor por esforço, **depois** da demo:

0. **[F] Decidir sobre B2 e B3** (`phase0/v1_backtest.py`). B2 é o urgente: sub-reporta
   dívida de decisão em silêncio em qualquer export com status `Mitigated`, que é status
   nativo do DefectDojo. Uma linha de regex em cada. **Não corrigido nesta sessão porque
   é o instrumento que o parceiro roda e havia apresentação no dia.**
1. **[H] Rodar V4 de verdade.** É o único item de Phase 0 sem dependência externa, o
   corpus está construído e validado, e o instrumento de análise está pronto e testado
   contra dado sintético. O resultado decide se o contrato de decisão é uma pergunta
   holística ou cinco sub-perguntas — **antes** de o schema ser escrito. Custo:
   3 anotadores × ~4h. Está adiado desde 2026-08-16 sem razão registrada.
2. **[F] Agendar a demo do Nucleus (V5 / T-1).** Prazo vencido. `competitive-teardown.md`
   §191 é explícito: **não pesquise de novo** — a documentação foi exaurida em duas
   rodadas; só o acesso ao produto responde.
3. **[H] Consertar L1** (cache de KEV sem expiração). É pequeno, e é a diferença entre um
   relatório correto e um relatório silenciosamente desatualizado na máquina de um
   parceiro que rodar duas vezes.
4. **[H] Decidir ADR-0017** (cross-tenant priors). Está *Proposed* e é decisão humana.
5. **[F] Não começar R0-1.** O backlog exige o gate V1 antes, e V1 exige V0.

## Files Currently Being Worked On

**[F] Nada pela metade.** A Fase A (passos 0 a 9) está completa e commitada; a suíte
roda limpa. O que **não** foi feito, e é Fase B declarada: launcher, PyInstaller,
instalador, e defesa contra CSRF no servidor local — qualquer página aberta no navegador
pode fazer POST para `127.0.0.1`, e hoje há rotas POST que executam análise.

---

## Last Updated

**2026-08-30** · commit base `2607b73` + Fase A · branch `master`
