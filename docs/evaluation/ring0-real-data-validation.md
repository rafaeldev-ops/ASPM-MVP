# Ring 0 — Validação com dados públicos reais

**Run:** 2026-08-24 · **Artefatos:** [`evaluation/runs/2026-08-24/`](../../evaluation/runs/2026-08-24/)
**Código:** [`evaluation/ring0/`](../../evaluation/ring0/) · **Datasets:** [`datasets/`](../../datasets/)
**Tipo:** validação de mecanismo com dado externo real + histórico de decisões sintético
**Executado por:** sessão Claude Code, sem parceiro de design envolvido

---

## 0. Resultado em uma linha

> **O mecanismo de dívida de decisão funciona e respeita a regra temporal — e as duas fontes reais deste run não se juntam, o que delimita exatamente o que este experimento pode e não pode afirmar.**

Três resultados importam mais que as métricas:

1. **Divergência achada num instrumento já validado.** `phase0/v1_backtest.py` classifica `Mitigated` como `fixed` e descarta esses registros. Mitigado não é corrigido — é a decisão de não remediar, que é o objeto do produto.
2. **Os dois corpora reais têm 100% de *unmatched* por identidade.** CodeQL não emite CVE; o KEV é indexado por CVE. Não é defeito do correlacionador, é uma propriedade das fontes.
3. **EPSS reconfirmado como gatilho ruim, com número novo.** 22.358 CVEs estão a ±10% do limiar 0,01 na distribuição real.

**Nenhuma validação de parceiro ou cliente foi realizada.** Nada aqui move K1, K2 ou K3.

---

## 1. Dataset

### 1.1 Fontes

| # | Dataset | Classificação | Registros | Fonte |
|---|---|---|---|---|
| D1 | CISA KEV, janela de 12 meses | `REAL_EXTERNAL_DATA` | **273** entradas | [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| D2 | CodeQL SARIF sobre repositórios EMBOSS | `REAL_EXTERNAL_DATA` | **100.627** achados | [Zenodo 15200316](https://zenodo.org/records/15200316) |
| D3 | EPSS daily snapshot | `REAL_EXTERNAL_DATA` | **359.229** CVEs | FIRST.org, modelo `v2026.06.15` |
| D4 | Histórico de decisões | **`SYNTHETIC_DATA`** | **360** decisões | gerado por `synthetic_history.py`, seed `20260824` |

### 1.2 Hashes e versões

| Dataset | `content_sha256` | Versão |
|---|---|---|
| D1 | `983ff0f1e9133824…` | janela 2025-08-25 … 2026-08-21 |
| D2 | `fd7a5c78d9e789fe…` | Zenodo record 15200316 (2025-04-11) |
| D3 | — (arquivo bruto, `sha256_file`) | `v2026.06.15 @ 2026-08-14T12:00:27Z` |
| D4 | `2a9f5dd49160dc16…` | seed=20260824, cutoff=2026-08-21 |

Hashes completos, incluindo os dos arquivos brutos, em [`datasets/metadata/manifest.json`](../../datasets/metadata/manifest.json) e em `evaluation/runs/2026-08-24/metadata.json`.

> **Dois hashes, e a diferença importa.** `content_sha256` cobre só os registros, em
> forma canônica — **é o número que uma reexecução tem que reproduzir**, e reproduz.
> `file_sha256` cobre o arquivo inteiro, que inclui o bloco de proveniência com
> `retrieved_at`, e portanto **muda a cada execução**. A primeira versão deste código
> tinha só o segundo, o que tornava o hash inútil para verificar conteúdo. Descoberto
> testando a reprodutibilidade — ver F6.

**O artefato do Zenodo foi verificado contra o checksum publicado:** md5 `41e28ac547e847919d07bb62666d0dc4`, confere. 94.691.838 bytes.

### 1.3 Uma correção sobre o arquivo entregue

O `ISSTA-2025-EMBOSS-Artifact-main.zip` presente em `datasets/raw/` **não contém os SARIF**. É o export do repositório GitHub, e `OSSEmbeddedResults/` é distribuído só pelo Zenodo — o README do próprio repositório diz isso. O artefato correto (`issta2025-artifact.zip`, 94,7 MB) foi baixado do Zenodo e é o que este run usa. Os dois arquivos foram preservados.

### 1.4 Imutabilidade

`datasets/raw/` nunca foi modificado. O zip de 94 MB **não foi extraído** — a ingestão lê os membros direto do arquivo compactado. Todo dataset processado carrega o bloco `_provenance` dentro do próprio arquivo, de modo que um processado separado do manifesto ainda diz de onde veio.

---

## 2. Metodologia

### 2.1 A regra que governa tudo

> **A evidência é lida como estava no dia da decisão, nunca como está hoje.**

Isso não é aplicado por disciplina de quem chama. É estrutural: `KnowledgeOracle.knowledge_as_of(cve, as_of)` é a única porta para o estado externo, todo método exige uma data, e a data de entrada no KEV **não sai da função** se for posterior ao `as_of`. Não existe uma consulta sem data para alguém chamar por engano.

### 2.2 Separação real / derivado / sintético

Obrigatória e verificada em três lugares: `DatasetRecord` recusa uma classificação fora do enum, `Decision` exige `classification` no construtor, e o manifesto registra a classe de cada dataset.

| O quê | Classe |
|---|---|
| CVE, data de entrada no KEV, flag de ransomware, vendor/produto | `REAL_EXTERNAL_DATA` |
| Achado do CodeQL, regra, arquivo, linha, CWE, commit | `REAL_EXTERNAL_DATA` |
| Score EPSS | `REAL_EXTERNAL_DATA` |
| A decisão, a data dela, a razão, quem fechou | **`SYNTHETIC_DATA`** |
| Veredito de re-litígio, banda de risco, rótulo de bucket | `DERIVED_DATA` |

### 2.3 Gatilhos considerados materiais

| Gatilho | Estatuto neste run |
|---|---|
| `KEV_LISTED` | **Testável e testado.** Exato: o KEV carrega `dateAdded` por entrada |
| `ADVISORY_RANGE_NARROWED` | **Não testável.** Nenhuma fonte deste run tem histórico de versão de advisory |
| `EXPLOITABILITY_CHANGED` | Parcial: a flag de ransomware do KEV é o único proxy disponível |
| `EPSS_SCORE_CHANGED` | **Explicitamente não-material.** Ver §4.4 |
| `DESCRIPTION_UPDATED`, `METADATA_TIMESTAMP_CHANGED`, `LOW_AUTHORITY_SOURCE_CHANGED` | Não-materiais, registrados e suprimidos |
| `EVIDENCE_REMOVED` | Muda `evidence_availability`; nunca cria candidato sozinho |

### 2.4 Limitações do método, declaradas antes dos resultados

- O histórico de decisões é **fabricado**. Ele exercita o motor; não mede prevalência de nada.
- A janela do KEV é de 12 meses. Um CVE ausente dela pode nunca ter entrado no KEV **ou** ter entrado antes da janela — o motor responde `UNKNOWN_OUTSIDE_WINDOW`, nunca `NOT_IN_KEV`.
- Um gatilho e meio dos sete do desenho são testáveis com estas fontes.

---

## 3. Experimentos realizados

| # | Experimento | Fontes | Resultado |
|---|---|---|---|
| E1 | Motor de dívida de decisão sobre histórico sintético | D1 + D4 | §4.1 |
| E2 | Comparação contra `phase0/v1_backtest.py` com evidência idêntica | D1 + D4 | §4.2 |
| E3 | Correlação KEV × CodeQL | D1 + D2 | §4.3 |
| E4 | EPSS como gatilho: densidade real + deslocamento simulado | D3 + D1 | §4.4 |
| E5 | Avaliação do corpus CodeQL: parsing, dedup, identidade | D2 | §4.5 |
| E6 | Casos golden, adversariais A–F, vazamento temporal | D1 + D4 | §4.6 |

---

## 4. Resultados

### 4.1 E1 — Dívida de decisão

População: 360 decisões sintéticas, 321 em escopo, `cutoff` = 2026-08-21.

| Pilha | Contagem |
|---|---:|
| **Dívida de decisão** (entrou no KEV depois do fechamento) | **109** |
| **Fechado apesar de** (já estava no KEV no dia) | **101** |
| Fora da janela do catálogo (estado indeterminável) | 111 |
| Excluído — fechado como corrigido | 39 |

As duas primeiras **nunca são somadas**. Contam histórias diferentes, e fundi-las inflaria o número principal.

#### Métricas (item 14 do briefing)

| Métrica | Valor | Contra o quê |
|---|---:|---|
| Decision-debt precision | **1,000** (109/109) | rótulo de construção |
| Decision-debt recall | **1,000** (109/109) | rótulo de construção |
| False re-litigation rate | **0,000** (0/109) | rótulo de construção |
| Candidate inflation sob evento de EPSS | **1,00×** (109 → 109) | 360 eventos injetados |
| Evidence coverage | **1,000** (109/109) | evidência real, rastreável |
| Temporal correctness | **1,000** (642 consultas, 0 vazamentos) | auditoria de consultas |

> ### Aviso sobre precision = 1,0
>
> **Este número não é uma conquista e não deve aparecer em nenhum slide como resultado de produto.** O ground truth é o rótulo com que o próprio dataset foi construído: as decisões do bucket A foram fabricadas para serem anteriores à entrada no KEV, então o motor as encontra por construção.
>
> O que 1,0 prova: a implementação faz o que a especificação diz, de forma consistente, em 321 casos.
> O que 1,0 **não** prova: nada sobre a frequência de dívida de decisão numa organização, nada sobre concordância de analista, nada sobre precisão de re-litígio em dado real. **Isso continua a depender do V1, que continua a depender do V0.**

### 4.2 E2 — Comparação com o instrumento validado, e o defeito que ela achou

Mesma evidência: as 273 entradas foram injetadas no cache do `v1_backtest.py` (por atribuição de módulo em tempo de execução — o arquivo do instrumento **não** foi modificado).

| | Dívida | Fechado apesar de | Excluídos |
|---|---:|---:|---:|
| Motor deste run | 109 | 101 | 39 |
| `phase0/v1_backtest.py` | **94** | **92** | **72** |

**Divergência de 24 achados, causa isolada e confirmada:**

```
v1_backtest.classify_reason("Mitigated")  ->  "fixed"
```

O regex `FIXED_WORDS` do instrumento contém `mitigated`. Os 33 registros com essa razão são descartados como "fechado como corrigido". Removendo `mitigated` do escopo do nosso motor, os números batem **exatamente**: 94 / 92.

#### Por que isso é um defeito, e não uma diferença de gosto

**Mitigado não é corrigido.** Um achado fechado porque existe um controle compensatório é precisamente *a decisão de não remediar* — e a ADR-0016 diz que essa supressão é perecível: o controle pode deixar de ser aplicado, ou o CVE pode entrar no KEV. É o caso central do produto, e o instrumento o descarta em silêncio.

**Isso morde em dado real.** `Mitigated` é um status do DefectDojo, que é a primeira fonte de export listada no `design-partner-kit.md`. Num export de parceiro com essa razão, o relatório sub-reporta dívida de decisão e ninguém percebe.

#### Um segundo defeito, no mesmo lugar

```
v1_backtest.classify_reason("Won't Fix")  ->  "false_positive"
```

"Won't fix" é aceitação de risco, não falso positivo. **Não altera o total** (ambos ficam em escopo), mas corrompe a divisão entre as duas pilhas — que é exatamente a suposição **A4** de `competitive-positioning.md` §7, a que o protocolo diz nunca ter sido medida. Um backtest que mede A4 com esse regex mede a própria classificação errada.

**Nenhum dos dois foi corrigido nesta sessão.** `v1_backtest.py` é o instrumento que um parceiro roda, e há uma apresentação hoje. A correção é de uma linha em cada regex, e é decisão de quem apresenta.

### 4.3 E3 — Correlação KEV × CodeQL

| Chave | Resultado |
|---|---|
| **CVE (identidade)** | **0 de 100.627.** CodeQL não emite CVE. Não existe junção por identidade |
| **CWE (classe)** | 13 CWEs compartilhados. 1.129 achados (1,12%) e 43 entradas KEV (15,75%) caem numa classe comum |
| **Repositório** | 19 pares candidatos por token compartilhado, **nenhum promovido a vínculo** |

Os pares de repositório mostram bem por que semelhança textual não é identidade:

| KEV | CodeQL | Token |
|---|---|---|
| Broadcom / VMware vCenter Server | `vmware/splinterdb` | `vmware` |
| Apache / ActiveMQ | `apache/mynewt-core` | `apache` |
| Microsoft / Visual Basic for Applications | `paladin-t/my_basic` | `basic` |

Nenhum é o mesmo artefato. Promover qualquer um deles a vínculo produziria um re-litígio falso com aparência de rigor.

> **Consequência para o desenho do experimento:** os achados do CodeQL **não podem ser sujeito** do teste de dívida de decisão baseado em KEV. Foi por isso que E1 usa um histórico sintético sobre CVEs reais do KEV, e não os 100.627 achados reais. A alternativa — casar por CWE — teria produzido números maiores e sem significado.

### 4.4 E4 — EPSS

**Medida real** (distribuição de 359.229 CVEs, modelo `v2026.06.15`):

| Limiar | CVEs acima | A ±10% do limiar | Dos quais abaixo (atravessariam) |
|---|---:|---:|---:|
| **0,01** | 144.522 (40,2%) | **22.358** | 11.081 |
| 0,05 | 30.623 (8,5%) | 5.112 | 2.511 |
| 0,10 | 17.303 (4,8%) | 2.513 | 1.246 |
| 0,50 | 4.312 (1,2%) | 970 | 508 |

**Medida simulada** (`DERIVED_DATA`, fator declarado, limiar 0,01):

| Deslocamento | Acima antes | Acima depois | Cruzaram |
|---|---:|---:|---:|
| ×1,10 | 144.522 | 154.869 | +10.347 |
| **×1,25** | 144.522 | 167.399 | **+22.877** |
| ×1,50 | 144.522 | 184.226 | +39.704 |
| ×2,00 | 144.522 | 214.067 | +69.545 |

**Baseline real do KEV:** 273 entradas em 361 dias = **23,0 por mês**.

> Um deslocamento de 25% — menor que uma troca de versão de modelo — move **22.877** CVEs através do limiar. O KEV produz **23** eventos por mês, cada um um fato datado por uma autoridade. A ordem de grandeza entre os dois gatilhos é de ~1.000×.
>
> **Este run não reproduz o 235× de EXP-001, e não tentou.** Aquilo mediu uma fronteira real de versão de modelo com dois snapshots; aqui há um snapshot só. O que este run acrescenta é independente e mais simples: **a fragilidade não precisa de uma troca de modelo para existir — ela está na densidade da distribuição.** 22.358 CVEs a ±10% de um limiar é uma propriedade medida hoje, não uma previsão.

### 4.5 E5 — Corpus CodeQL

100.627 achados · 150 projetos com achados (de 165 varridos) · 168 pares projeto+commit · 116 regras dispararam de 183.

**Cobertura de campo — o que a fonte realmente entrega:**

| Campo | Presente |
|---|---:|
| repository, commit, file, rule, message, severity, precision | 100% |
| line | 99,64% |
| **cwe** | **73,50%** |
| **security_severity** | **2,86%** |
| **cve** | **0%** |

**Identidade e deduplicação:** 94.762 fingerprints distintos para 100.627 achados; 3.627 fingerprints com colisão (9,43% dos registros); 5.858 duplicatas no nível de localização. 100% dos fingerprints usam o `partialFingerprint` do próprio CodeQL.

> Colisão de fingerprint **não é prova de duplicata**: o `primaryLocationLineHash` do CodeQL é por linha, então dois achados distintos da mesma regra na mesma linha colidem legitimamente. O número está reportado como o que é — uma taxa de colisão do esquema de identidade.

**Classificação:** 2.878 achados (2,86%) vêm de regra com tag `security`. Níveis: `note` 92.763 · `warning` 6.775 · `error` 1.089.

**Concentração:** `cleanflight/cleanflight` sozinho responde por **60,77%** dos achados; os cinco maiores projetos somam **75,96%**. Qualquer média sobre este corpus descreve principalmente um projeto.

**Ground truth de falso positivo: NÃO EXISTE neste artefato.** Verificado, conforme o item 17 manda. O zip traz os SARIF, `embedded-repos.json` (a lista de 300 repositórios buscados) e dois PDFs. Os 709 defeitos confirmados do título do paper estão em prosa e tabelas, não em arquivo de labels. **Nenhuma métrica de precisão sobre falso positivo do CodeQL é reportada, porque qualquer uma seria inventada.**

### 4.6 E6 — Casos golden, adversariais e vazamento

`python evaluation/ring0/test_ring0.py` — **31 passaram, 0 falharam, 1 declarado não testável.**

| Grupo | Resultado |
|---|---|
| **Positivos** (P1–P3) | 6/6. Entrada no KEV após fechamento gera candidato; risco aceito também; ransomware preservado na evidência |
| **Negativos** (N1–N7) | 10/10. Já estava no KEV; EPSS 0,004→0,51; descrição reescrita; timestamp; fonte fraca; nada mudou; fechado como corrigido |
| **Adversariais** | A ✓ (60 candidatos de baseline, 60 depois da avalanche de EPSS) · B ✓ · C ✓ · D ✓ · **E não testável** · F ✓ |
| **Vazamento temporal** | 7/7. Incluindo varredura das **642 consultas** do run completo: **0 revelaram data futura** |

**Adversarial E — declarado não testável, não simulado.** Mudança de *affected range* exigiria snapshots de OSV/GHSA ao longo do tempo. Nenhuma fonte deste run os tem. Simular um resultado aqui seria fabricar o gatilho mais fácil de fabricar.

**Sobre o adversarial A:** a primeira versão passou com `0 → 0` — baseline vazio, teste vacuoso, um motor que nunca dispara sobreviveria a ele. Foi refeito com população de baseline não-vazio (60 candidatos) antes de ser aceito.

---

## 5. Falhas encontradas

| # | Onde | O quê | Estado |
|---|---|---|---|
| **F1** | `phase0/v1_backtest.py` | `Mitigated` → `fixed`: 33 de 360 decisões descartadas em silêncio. Mitigado não é corrigido | **Aberto.** Não corrigido nesta sessão — é o instrumento que o parceiro roda, e há apresentação hoje |
| **F2** | `phase0/v1_backtest.py` | `Won't Fix` → `false_positive`: corrompe a divisão de pilhas, que é a suposição A4 | **Aberto**, mesma razão |
| **F3** | dataset entregue | `ISSTA-2025-EMBOSS-Artifact-main.zip` não contém os SARIF | **Resolvido:** artefato correto baixado do Zenodo, md5 conferido |
| **F4** | teste próprio | Adversarial A passava vacuamente com baseline zero | **Corrigido** antes de ser aceito |
| **F5** | relatório próprio | `pct_of_above` do EPSS passava de 100% e lia como erro | **Corrigido** |
| **F6** | `evaluation/ring0/provenance.py` | O hash gravado no manifesto cobria o arquivo inteiro, **incluindo o `retrieved_at` embutido** — então mudava a cada execução e não servia para verificar que o dado é o mesmo. Encontrado rodando a ingestão duas vezes e comparando, não por inspeção | **Corrigido:** `content_sha256` sobre os registros em forma canônica, verificado estável em reexecução |

---

## 6. Limitações

| # | Limitação |
|---|---|
| L1 | **Nenhum dado organizacional.** Nenhum export de parceiro, nenhuma decisão de analista real. O histórico é fabricado |
| L2 | **Precision/recall são contra rótulo de construção.** Medem a implementação contra a especificação, não o mundo |
| L3 | **Um gatilho e meio de sete.** `KEV_LISTED` exato; `ADVISORY_RANGE_NARROWED` não testável; os demais fora de alcance destas fontes |
| L4 | **Janela de 12 meses.** 111 das 360 decisões caem em `UNKNOWN_OUTSIDE_WINDOW`. O catálogo completo (1.674 entradas desde 2021) reduziria isso |
| L5 | **Os dois corpora não se juntam.** 100% unmatched por identidade. Os 100.627 achados reais do CodeQL não puderam ser sujeito do experimento de dívida |
| L6 | **Sem ground truth de falso positivo** no artefato ISSTA. Nenhuma métrica de qualidade de detecção é reportável |
| L7 | **Corpus CodeQL concentradíssimo.** 60,77% num projeto |
| L8 | **EPSS: um snapshot só.** O deslocamento é simulado e rotulado; a densidade é real |
| L9 | **Nada aqui é multi-tenant, autenticado ou persistido.** É código de avaliação, não Ring 0 de produção — ver §8 |

---

## 7. Conclusão por hipótese

| # | Hipótese | Veredito |
|---|---|---|
| H1 | Mudanças no estado externo de uma vulnerabilidade podem tornar uma decisão histórica potencialmente obsoleta, e isso é detectável sem EPSS | **SUPPORTED** — como mecanismo. 109 candidatos com evidência real, rastreável e datada, sobre 321 decisões em escopo, com 0 vazamentos temporais em 642 consultas. Que isso importe para uma organização real permanece **não testado** |
| H2 | A regra as-of pode ser garantida estruturalmente, não por disciplina | **SUPPORTED** — 642 consultas auditadas, 0 revelaram data futura; a guarda levanta exceção quando burlada |
| H3 | EPSS é gatilho ruim de re-litígio | **SUPPORTED** — independentemente de EXP-001: 22.358 CVEs a ±10% do limiar 0,01; um deslocamento de 25% move 22.877 contra 23 entradas KEV/mês |
| H4 | O sistema distingue mudança material de barulho | **SUPPORTED** — 10 casos negativos, inflação 1,00× com 360 eventos não-materiais injetados |
| H5 | Achados de SAST podem ser ligados a inteligência de exploração ativa (KEV) | **NOT_SUPPORTED** — 0% de junção por identidade. CodeQL não emite CVE. Vínculo por CWE é de classe e não autoriza re-litígio |
| H6 | O corpus real do CodeQL permite avaliar normalização, dedup e classificação | **PARTIALLY_SUPPORTED** — parsing, cobertura de campo, identidade e agrupamento sim, sobre 100.627 achados reais. Qualidade de detecção não: não há labels |
| H7 | Dívida de decisão ocorre com frequência material em organizações reais | **INCONCLUSIVE** — este run não tem como responder. Exige V0 → V1 |
| H8 | Detecção de estreitamento de faixa de advisory funciona | **INCONCLUSIVE** — não testável com estas fontes |

---

## 8. Status R0-1 … R0-7

O critério é o backlog, não o esforço gasto. Este run é **avaliação**, não implementação de produto: nada aqui tem migration, tenancy, RLS ou API.

| Item | Antes | Agora | Justificativa |
|---|---|---|---|
| **R0-1** — migration, `org_id`, RLS + FORCE, gate de CI | Não | **Não** | Nada foi feito. Não há banco, nem tenancy, nem migration |
| **R0-2** — import de decisões fechadas → `decision`/`suppression` canônicos | Não | **Parcial (avaliação)** | Existe um modelo de decisão com classificação obrigatória e um importador de export sintético. Não produz registros canônicos com `source_system`, e não persiste |
| **R0-3** — KEV/EPSS/OSV com snapshots, hashes e authority tiers | Não | **Parcial** | KEV e EPSS ingeridos com snapshot, SHA-256, versão e `source_authority`. Falta OSV/GHSA, e não há pinagem de versão de EPSS no caminho de decisão (por escolha: EPSS não é gatilho) |
| **R0-4** — detector de estreitamento de faixa | Não | **Não** | Nenhuma fonte deste run tem histórico de advisory |
| **R0-5** — avaliador de condições de invalidação | Não | **Parcial** | O avaliador existe, com condições materiais e não-materiais separadas e justificadas. Não é um worker: é uma passada única, sem agendamento nem estado |
| **R0-6** — `reopen_event` + reconstrução de `evidence_availability` | Não | **Parcial** | `evidence_availability` é reconstruído e testado (adversarial F). Não há tabela `reopen_event` nem persistência |
| **R0-7** — `GET /v1/decision-debt` + artefato estático | Parcial | **Parcial** | Artefatos versionados em `evaluation/runs/`. Não há endpoint |

> **Ring 0 ainda não passou.** Quatro dos sete itens estão parciais e são todos parciais na mesma direção: existe a lógica, não existe a plataforma (persistência, tenancy, API, agendamento). E o gate do Ring 0 não é uma lista de código — é **precisão de re-litígio ≥50% em dado histórico de parceiro**, que continua sem nenhum dado.

## 9. K1 / K2 / K3

| Critério | Estado |
|---|---|
| **K1** — ≥3 de 5 parceiros dizem que queriam saber | **NÃO AVALIÁVEL.** Zero parceiros |
| **K2** — ≥1 parceiro nomeia um achado que o alarma | **NÃO AVALIÁVEL.** Zero parceiros |
| **K3** — precisão de re-litígio ≥50% em dado histórico | **NÃO AVALIÁVEL.** O 1,000 de §4.1 é contra rótulo de construção sintético e **não é K3** |

Nenhum threshold pré-registrado foi movido. O log de mudanças de `phase-0-protocols.md` §8 continua vazio.

---

## 10. Próximo passo

1. **Decidir sobre F1 e F2** — as duas linhas de regex do `v1_backtest.py`. F1 sub-reporta dívida de decisão em qualquer export do DefectDojo com status `Mitigated`.
2. **V0 continua sendo o gargalo.** Nada neste run substitui um export real, e ele não move K1/K2/K3.
3. **Ampliar a janela do KEV** para o catálogo completo (1.674 entradas desde 2021-11) eliminaria os 111 `UNKNOWN_OUTSIDE_WINDOW` — 31% da população.
4. **Se um parceiro entregar export com SCA** (Trivy, Snyk, Dependabot), os achados terão CVE e a junção que falhou em §4.3 passa a existir. É a diferença entre SAST e SCA, e vale dizer isso na conversa com parceiro.

---

## 11. Reprodução

```bash
python evaluation/ring0/ingest_kev.py          # 273 entradas, valida CSV vs JSON
python evaluation/ring0/ingest_sarif.py --survey
python evaluation/ring0/ingest_sarif.py        # 100.627 achados
python evaluation/ring0/synthetic_history.py   # 360 decisões SINTÉTICAS
python evaluation/ring0/test_ring0.py          # 31 passam, 0 falham
python evaluation/ring0/run_all.py 2026-08-24  # artefatos do run
```

Tudo é biblioteca padrão. O `issta2025-artifact.zip` (94,7 MB) precisa estar em `datasets/raw/`; se faltar, baixe de `https://zenodo.org/api/records/15200316/files/issta2025-artifact.zip/content` e confira o md5 `41e28ac547e847919d07bb62666d0dc4`.
