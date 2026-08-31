# MVP ASPM — o que existe, o que não existe

**Sprint 3** · **Data:** 2026-08-24 · **Status:** funcional e testado
**Código:** [`app/`](../../app/) · **Testes:** [`tests/`](../../tests/) · **Demo:** `POST /aspm/actions/demo`

---

## 0. O que este documento não afirma

> **"O MVP funciona" não é "a hipótese foi validada".**

O MVP demonstra as cinco capacidades de uma ASPM sobre dados públicos reais e um
inventário fabricado. Ele **não** mede prevalência de dívida de decisão em nenhuma
organização, **não** move K1/K2/K3, e **não** substitui o V0. Essas continuam sendo
perguntas abertas, e continuam dependendo de um export organizacional real.

---

## 1. Rodar

```bash
docker compose up -d --build          # ou: python -m uvicorn app.main:app
```

Abra <http://127.0.0.1:8000/aspm> e clique em **Carregar dataset de demonstração**.
O instrumento de backtest anterior continua em `/`.

```bash
python tests/run.py                   # 101 testes, sem instalar nada
```

---

## 2. Os cinco componentes

| Componente | Onde | O que faz |
|---|---|---|
| **Asset Discovery** | `app/application/ingestion.py` | Import de inventário (CSV/JSON) **e** descoberta a partir do próprio achado — a maior parte dos exports de scanner nomeia o repositório, e criar o ativo dali evita exigir um inventário que a organização provavelmente não tem |
| **Risk Correlation** | `app/application/correlation.py` | Deduplica e agrupa por CVE+pacote, CVE, regra+local ou regra+ativo. Registra **qual** base uniu cada grupo |
| **Prioritization Engine** | `app/application/prioritization.py` + `app/domain/risk.py` | A árvore determinística de `risk-model.md` §4.2 (reparada por `exp-002`). Sem LLM |
| **Remediation Guidance** | `app/application/remediation.py` | Quatro níveis de confiança, sempre com fonte. Quando não há fonte, diz `uncertain` e explica o que falta |
| **Continuous Monitoring** | `app/application/monitoring.py` | Snapshots, detecção de novo/fechado/reaberto/severidade, eventos de KEV datados pela CISA, linha do tempo |

E o diferencial:

| Capacidade | Onde |
|---|---|
| **Evidence** | `app/domain/models.py::Evidence` — fonte, autoridade, classificação, quando o fato ocorreu vs. quando lemos |
| **Decision History** | `Decision`, append-only, com a fotografia do que se sabia no dia |
| **Decision Debt** | `app/application/decision_debt.py` |
| **Analyst Review** | `app/application/review.py` — cria decisão nova, nunca sobrescreve |

---

## 3. Decisões de projeto que valem registro

### 3.1 A priorização é a fórmula já documentada, não uma nova

O briefing pedia para não inventar fórmula se houvesse decisão documentada. Há:
`docs/decisions/risk-model.md` §4.2, com 20 linhas sobre 720 combinações, provada
total e sem linhas mortas por `exp-002`.

`app/domain/risk.py` é essa árvore portada. **`tests/test_risk_tree.py` compara as
720 combinações contra `phase0/v2_riskmodel.py`** — duas cópias da mesma regra
divergem em silêncio a menos que algo compare as duas.

### 3.2 EPSS: sinal contextual, nunca gatilho

Mantido de `EXP-001` e `EXP-004`. No MVP:

- **entra** no `ordering_score` (peso 0,20), ordenando *dentro* da banda;
- **não entra** no enum `ChangeKind` — não existe evento material de EPSS;
- `tests/test_risk_tree.py::test_epss_nao_altera_a_banda` trava isso: EPSS 0,01 e
  EPSS 0,99 têm que dar a **mesma banda** e ordens diferentes.

### 3.3 A regra temporal é estrutural

`KevCatalog.knowledge_as_of(cve, as_of)` é a única porta para o estado externo,
toda consulta exige data, e a data de entrada no KEV **não sai da função** se for
posterior ao `as_of`.

### 3.4 Ausência de dado é declarada, não preenchida

- Criticidade de ativo nula → o modelo **falha fechado** e assume crítico.
- `not_applicable` exige sinal positivo; ausência devolve `unknown`.
- Sem versão corrigida e sem advisory → remediação `uncertain` que **diz o que falta**.
- Catálogo KEV completo: ausência de um CVE é um fato (`NOT_IN_KEV`). Recorte de
  janela: ausência é ignorância (`UNKNOWN_OUTSIDE_WINDOW`). O carregador prefere o
  catálogo completo quando os dois existem.

### 3.5 A IA é opcional e não decide

Provider padrão `null`: síntese determinística, **nenhuma chamada externa**. A IA,
quando ligada, reescreve explicação; nunca produz banda, estado ou lógica temporal.
Saída sempre validada contra o contrato.

**Atualizado em 2026-08-30 (Fase A).** A frase acima continua verdadeira e ganhou
mecanismo. Três providers — `null`, `ollama`, `openai` — e três é **teto imposto por
teste**. O que mudou de substantivo:

- **Egresso deixou de ser booleano e virou classe verificada:** `none`, `localhost`,
  `third_party`. `localhost` não é uma alegação — o adaptador resolve o host e recusa se
  algum endereço não for loopback, e ignora `HTTP_PROXY` explicitamente. Sem a segunda
  metade, uma máquina com proxy corporativo rotearia o pedido "127.0.0.1" para fora
  enquanto a tela exibe o selo `local`.
- **Análise nunca é efeito colateral de renderização.** Antes da Fase A, o handler GET
  de `/aspm/findings/{id}` chamava o provider. Era inofensivo com só o `NullProvider`
  existindo, e viraria egresso a cada F5 no instante em que um provider cloud fosse
  selecionável. Hoje é POST consentido, com tela de pré-voo mostrando **a carga redigida
  de verdade**.
- **`confidence` continua determinístico**, calculado por completude de evidência e
  versionado. Não está no schema de saída do modelo, nem a proveniência: se estivesse,
  o modelo poderia mentir sobre a própria identidade.
- **A IA pré-preenche a revisão; o analista decide.** `Decision` ganhou
  `ai_analysis_id` e `ai_suggested_reason`, para que a concordância analista×modelo
  (CLAUDE.md §31) seja mensurável depois — é impossível de reconstruir se não for
  gravada agora.

Governança e as sete outras decisões:
[`../adr/0018-local-first-provider-selection.md`](../adr/0018-local-first-provider-selection.md).

### 3.6 `org_id` desde a primeira tabela

O MVP não tem multi-tenancy (não tem nem autenticação). Mas ADR-0003 é explícito:
retrofitar tenancy custa ~4 meses-engenheiro contra ~2 semanas agora, e a **coluna**
é a parte que não dá para acrescentar depois sem reescrever o dado.

---

## 4. B2 e B3 — corrigidos

`app/domain/enums.py` tem **seis** razões de fechamento, não três:

| Razão | Entra no cálculo de dívida? |
|---|---|
| `mitigated` | **Sim** — controle compensatório é a decisão de não remediar, e ADR-0016 diz que é perecível |
| `accepted_risk` | Sim |
| `false_positive` | Sim |
| `wont_fix` | Sim — e é **distinto** de falso positivo |
| `fixed` | Não — não há decisão a re-litigar |
| `unknown` | Não — ignorância não é decisão |

Regressão travada em `tests/test_closure_reasons.py` (14 testes) e
`tests/test_decision_debt.py::TestEscopoDaDivida`.

`phase0/v1_backtest.py` **não foi alterado** — é o instrumento que um parceiro roda.
Um teste documenta a divergência e falha se o instrumento for corrigido, para a
correção ficar visível.

---

## 5. Defeitos encontrados durante a Sprint 3

Todos achados por execução, nenhum por leitura.

| # | Onde | O quê |
|---|---|---|
| S1 | `demo.py` | `session.add()` com FK solta não atualizava `finding.decisions`; o cálculo de dívida via 14 de 35 decisões |
| S2 | `knowledge.py` | Catálogo de 12 meses fazia `still_valid` ser inalcançável. Com catálogo completo, ausência é fato |
| S3 | `main.py` | `import app.domain.models` religava o nome `app` ao pacote e sobrescrevia a instância FastAPI |
| S4 | `models.py` | `Finding.asset` lazy → `DetachedInstanceError` ao renderizar a lista de riscos |
| S5 | `correlation.py` | Mesmo padrão de S1: evidência não aparecia na mesma sessão, e a remediação concluía `uncertain` para achado **com** advisory |
| S6 | `review.py` | Mesmo padrão: rever duas vezes na mesma sessão perdia a cadeia `supersedes` — a trilha de auditoria do modelo append-only |

**S1, S5 e S6 são o mesmo defeito três vezes:** `session.add()` com chave estrangeira
solta não atualiza a coleção já carregada. A correção é sempre anexar pela relação.
Vale como regra do projeto, não como três consertos.

---

## 6. Limitações

| # | Limitação |
|---|---|
| M1 | **Nenhum dado organizacional.** Inventário e decisões do dataset de demonstração são fabricados e marcados `SYNTHETIC_DATA` |
| M2 | **Sem autenticação, sem RBAC, sem tenancy ativa.** Instrumento local de uma pessoa. A porta é publicada em `127.0.0.1` por isso |
| M3 | **Um gatilho e meio de dívida.** `KEV_LISTED` é exato. Estreitamento de faixa de advisory exige histórico OSV/GHSA, que nenhuma fonte deste MVP tem |
| M4 | **Correlação sem reachability.** DP3 fica `unknown` na maioria dos achados, o que joga muita coisa em `track` — comportamento correto e conservador, mas significa que a discriminação depende de enriquecimento que o MVP não faz |
| M5 | **Comparação de versão é semver simples.** Versões não numéricas devolvem `None`, não um palpite |
| M6 | **SQLite, com um runner de migração mínimo desde 2026-08-30.** `create_all()` seguido de `migrate()` (`app/db_migrations.py`, `schema_version` + migrações idempotentes). Não é Alembic — descartado porque descobre revisões por caminho em disco, o que quebra sob PyInstaller. R0-1 (migration **sob RLS**, gate de CI) continua não feito |
| M7 | **SAST não se junta a KEV.** CodeQL não emite CVE — medido no run do Ring 0, 100% unmatched por identidade. Achados de SAST recebem prioridade e remediação `uncertain`, nunca dívida de decisão por KEV |
| M8 | **Sem lint nem type checking.** Não há `ruff`/`mypy` configurados no projeto. **Desde a Fase A isso tem consequência de segurança:** a ADR-0011 impõe a fronteira de redação por tipo, verificada por MyPy strict; sem MyPy o portão de build não existe e o substituto é estrutural em tempo de execução — melhor disponível, não equivalente |
| ~~M9~~ | **Resolvida em 2026-08-31.** `qwen2.5:3b` local, 48 chamadas: [`../evaluation/ollama-local-model-bench.md`](../evaluation/ollama-local-model-bench.md). Encontrou um defeito real e o corrigiu com portão estrutural |
| M11 | **Um modelo só, 16 achados, um dia.** Nada do benchmark se transfere para modelo maior ou provider externo. **Nenhuma chamada paga foi feita**, então custo por achado e comportamento sob filtro de conteúdo continuam sem medida. E nenhum analista leu os resumos com olhar crítico |
| M12 | **15 s por achado.** Utilizável sob demanda, inviável em lote: 400 achados levariam 1h40. A arquitetura já assume isso (análise é ação consentida, nunca varredura), mas o número limita o que a IA pode ser no produto |
| ~~M10~~ | **Resolvida em 2026-08-31.** Origem verificada em todo método inseguro, mais token de duplo envio nas rotas de formulário. 14 testes, e os centrais **simulam o ataque** |
| M13 | **O instalador não está assinado.** SmartScreen avisa em toda instalação e a reputação zera a cada versão. Não há contorno técnico — só certificado de assinatura de código |
| M14 | **Sem autenticação, também no desktop.** Quem tem acesso à máquina tem acesso aos dados. O CSRF protege contra *página remota dirigindo o navegador local*; não protege contra processo local, e a resposta certa para isso é sistema de arquivos, não cabeçalho HTTP |

---

## 7. Definition of Done — Sprint 3

| Item | Estado | Evidência |
|---|---|---|
| Aplicação inicia de forma reproduzível | ✅ | `docker compose up -d --build`; `tests/test_api.py` sobe o servidor de verdade |
| Asset Discovery funcional | ✅ | `TestAssetDiscovery` (5 testes) |
| Risk Correlation funcional | ✅ | `TestCorrelacao` (6 testes) |
| Prioritization Engine funcional | ✅ | `test_risk_tree.py` (17 testes), paridade com `phase0` |
| Remediation Guidance funcional | ✅ | `TestRemediacao` (4 testes, os 4 níveis) |
| Continuous Monitoring funcional | ✅ | `TestMonitoramento` (4 testes) |
| Evidence Engine integrado | ✅ | `test_caso_5_evidencia_com_proveniencia` |
| Decision Debt demonstrável | ✅ | `test_decision_debt.py` (18 testes) |
| Review workflow funcional | ✅ | `TestRevisao` (6 testes) |
| Dashboard funcional | ✅ | 6 telas, `TestTelas` |
| Dataset de demonstração | ✅ | `datasets/demo/manifest.json` com proveniência por componente |
| Fluxo ponta a ponta testado | ✅ | `test_e2e.py`, os 9 casos |
| Testes passando | ✅ | **207 testes, 0 falhas, 0 erros, 0 pulados** (101 da Sprint 3 + 73 da Fase A + 33 da Fase B) |
| B2 corrigido | ✅ | `TestB2Mitigated` |
| B3 corrigido | ✅ | `TestB3WontFix` |
| Documentação atualizada | ✅ | este documento + `PROJECT_STATE.md` |
| Limitações documentadas | ✅ | §6 |

---

## 8. O que continua igual

**V0 continua bloqueado.** Não existe histórico organizacional real com findings +
decisões + lifecycle. O MVP está preparado para recebê-lo — `import_decisions()`
aceita export com `classification="REAL_EXTERNAL_DATA"` e nada na arquitetura
precisa mudar — mas ele não existe.

**K1, K2 e K3 continuam não avaliáveis.** Zero parceiros.

**Ring 0 continua não passando.** R0-1 e R0-4 não feitos; R0-2, R0-3, R0-5, R0-6 e
R0-7 parciais. O MVP implementa a *lógica* de vários deles sem a *plataforma*
(migration, RLS, worker, endpoint versionado sob contrato).
