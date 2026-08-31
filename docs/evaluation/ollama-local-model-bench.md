# Primeiro benchmark contra modelo de verdade — qwen2.5:3b local

**Data:** 2026-08-31
**Instrumento:** [`evaluation/ollama_bench.py`](../../evaluation/ollama_bench.py)
**Artefatos:** `evaluation/runs/ollama-qwen2.5-3b-{v1,v2,v3}.json`
**Status:** executado. Fecha a limitação **L13**.

> **O que este documento não afirma.** Não é uma escolha de fornecedor, não é uma
> medida de qualidade de produto e não diz nada sobre nenhuma organização. Mede um
> modelo, num corpus construído, num dia. O corpus tem 16 achados; nenhuma
> conclusão aqui tem poder estatístico. O que ele estabelece é qualitativo e vale
> mais que o número: **quais modos de falha existem quando há um modelo de verdade
> no caminho.**

---

## 0. Por que este documento existe

Até 2026-08-31 a camada de IA tinha 46 testes, todos contra servidores falsos.
Isso prova transporte, retry, timeout, validação, fundamentação e a fronteira de
redação. **Não prova nada sobre o que um modelo faz.** A L13 dizia isso com essas
palavras, e a ADR-0015 §2 exige benchmark antes de escolher fornecedor.

Este é o menor benchmark honesto que fecha essa lacuna.

---

## 1. Montagem

| | |
|---|---|
| Modelo | `qwen2.5:3b` (1,93 GB), Ollama 0.33.2 |
| Egresso | `localhost`, loopback verificado pelo adaptador |
| Corpus | 16 achados: 8 sobre CVEs **reais** da CISA KEV, 8 sobre CVEs válidos **fora** da KEV |
| Inventário | **fabricado** e declarado como tal — 6 perfis de criticidade/ambiente/exposição |
| Bandas | 9 de ação (`act_now`/`act_soon`), 7 calmas (`scheduled`/`track`/`deprioritize_candidate`) |

**Um defeito do primeiro corpus, corrigido antes das medidas finais.** A primeira
versão era 100% KEV e produziu 12 achados em `act_now` de 12. Estar na KEV torna o
achado não-suprimível e domina a árvore de risco: variar criticidade e exposição do
ativo não mudava nada. Um corpus assim não consegue responder à pergunta que mais
importa sobre um portão de segurança — **se ele dispara demais**. A metade não-KEV
existe por isso.

---

## 2. O achado

**Com o prompt original, `qwen2.5:3b` sugeriu `accepted_risk` para 9 de 9 achados em
banda de ação.** No mesmo objeto de resposta, escreveu que exigiam ação imediata.

```
CVE-2026-20349  banda=act_now  sugeriu=accepted_risk
   "A vulnerabilidade em Cisco Secure Firewall ASA foi coletada e classificada
    por um motor determinístico..."
```

Na primeira execução, sobre o corpus 100% KEV, foram **12 de 12**.

Este é o modo de falha que o `CLAUDE.md` §33 nomeia como o mais caro: *"a wrong
'deprioritize' decision can be far more damaging than a false positive"*. E não é
um erro visível — o formulário de revisão vem **pré-preenchido**. Um analista com
fila de 400 achados confirma o que já está na tela.

### O que segurou

Tudo o que é estrutural:

| Propriedade | Resultado |
|---|---|
| Banda determinística alterada | **0 de 16** |
| Score de ordenação alterado | **0 de 16** |
| Evidência citada que não foi entregue | **0 de 16** |
| Aderência ao schema | **16 de 16** |

O modelo nunca chegou perto de mover uma decisão. A arquitetura funcionou
exatamente como a ADR-0010 §1 desenhou — **a IA sintetiza, não decide** — e é
por isso que um erro semântico de 100% não virou incidente.

**A camada semântica falhou por completo. A camada estrutural não cedeu em nada.**
Se a sugestão da IA alimentasse a decisão diretamente, este benchmark teria fechado
nove vulnerabilidades sob exploração ativa, expostas na internet, em ativos
críticos.

---

## 3. Diagnóstico

O prompt nunca dizia que `recommended_reason` é vocabulário de **fechamento**, nem
quando deixá-lo vazio. O modelo via um enum com `""` disponível e nenhuma pista de
que `""` era a resposta certa para um achado que deve ser corrigido, não encerrado.

Defeito real, e do tipo que só aparece com um modelo de verdade na frente.

---

## 4. As duas correções, e por que são duas

**Regra de prompt é conselho.** Ela depende de o modelo obedecer, que é exatamente
a suposição que a ADR-0007 proíbe para propriedade de segurança. Então:

1. **O prompt ganhou a informação que faltava** — uma frase.
2. **`contract.validate()` ganhou um portão estrutural:** uma razão de fechamento é
   descartada quando a banda determinística entregue ao modelo exige ação. O
   descarte é registrado em `uncertainty_reasons` — descarte silencioso esconderia
   justamente a métrica que diz que o modelo escolhido não serve.

O portão não depende de modelo nenhum, e está travado por cinco testes em
`tests/test_ai_privacy.py::TestSugestaoDeFechamento`.

---

## 5. Ablação — quanto vem do prompt, quanto vem do portão

Três variantes, mesmo corpus de 16, mesmo modelo, mesma seed de construção.
O portão está ativo nas três; o que varia é o prompt.

| Prompt | Aderência ao schema | Portão disparou (de 9 de ação) | Sugestão preservada em banda calma |
|---|---|---|---|
| **v1** — original, sem a frase | **16/16** (100%) | **9** (o modelo errou sempre) | 7 de 7 |
| **v2** — duas regras numeradas | **8/16** (50%) | 8 | 0 de 7 |
| **v3** — uma frase ← **em produção** | **16/16** (100%) | **3** (o modelo acerta 6 de 9) | 2 de 7 |

**Nenhuma variante produziu sugestão incoerente, porque o portão não deixa.** A
diferença é quanto trabalho sobra para ele.

### v2 foi medida e rejeitada

Duas regras numeradas derrubaram a aderência ao schema pela metade. As respostas
falhas não eram lixo: eram JSON válido com `summary` e `risk_explanation` **vazios**,
~70 tokens de saída. Num modelo de 3B, instrução nova compete com a produção de
conteúdo.

Isso é o `CLAUDE.md` §30 na prática — *"a change may be rejected even if model
quality improves when cost, latency, privacy, or reliability becomes materially
worse"*. A v2 melhorava a segurança da sugestão e destruía o produto.

### v3 é melhor que v1 por uma razão específica

As duas dão 16/16 e zero sugestão incoerente. A diferença está em **quantas vezes o
portão precisa agir**: 9 contra 3. Um portão que dispara sempre é a única coisa que
separa o produto do desastre; um portão que dispara às vezes é rede de segurança.
A segunda postura é a que sobrevive à troca de modelo.

Sinal secundário: com a v1 o modelo sugeriu `accepted_risk` para **todas** as 7
bandas calmas. Sugestão uniforme não carrega informação. Com a v3 foram 2 de 7 —
mais conservador, e mais útil.

---

## 6. Números operacionais

| | v1 | v2 | v3 |
|---|---|---|---|
| Latência mediana | 15,4 s | 10,7 s | 15,0 s |
| Latência p90 | 18,1 s | 16,9 s | 17,9 s |
| Lote de 16 | 238 s | 184 s | 243 s |
| Tokens (entrada / saída) | 17.749 / 4.111 | 20.549 / 2.722 | 18.325 / 4.151 |
| Custo | zero — roda na máquina | | |

**15 segundos por achado é utilizável para análise sob demanda e inviável para
lote.** Um analista clicando "analisar" num achado espera 15 s; a mesma operação
sobre 400 achados leva 1h40 e prende uma thread do pool a cada duas análises
(`Semaphore(2)`). A arquitetura já assume isso — análise é ação consentida por
achado, nunca varredura — e este número confirma que a suposição estava certa.

A latência da v2 é menor **porque as respostas eram vazias**. Latência sem
aderência não é vantagem, e é um bom lembrete de que medir uma coisa só engana.

---

## 7. O que continua não medido

- **Só um modelo.** Nada aqui se transfere para modelos maiores nem para a OpenAI.
  A hipótese natural — um modelo maior comete menos o erro do §2 — **não foi
  testada**, e o portão existe justamente para não depender dela.
- **Taxa de recusa: 0 em 48 chamadas.** Corpus de segurança com prosa sobre
  exploração ativa não disparou nenhuma recusa neste modelo. Um provider externo com
  filtro de conteúdo pode se comportar de outro jeito; a ADR-0015 §2 diz que isso
  pode decidir o fornecedor, e continua sem medida.
- **Qualidade do texto não foi avaliada por ninguém.** Os resumos são plausíveis e
  citam a evidência certa. Nenhum analista os leu com olhar crítico. "Plausível" é
  precisamente o que um modelo produz de graça.
- **16 achados.** Sem poder estatístico. As proporções (9/9, 3/9) são ilustrativas.
- **Custo por achado num provider pago:** não medido, porque nenhuma chamada paga
  foi feita.

---

## 8. Reproduzir

```bash
docker run -d --name ollama-bench -p 127.0.0.1:11434:11434 \
  -v ollama-models:/root/.ollama ollama/ollama
docker exec ollama-bench ollama pull qwen2.5:3b

python evaluation/ollama_bench.py --n 16 --prompt v3
python evaluation/ollama_bench.py --n 16 --prompt v1   # a ablação
```

A variante de prompt existe **apenas no instrumento de avaliação**. Em produção o
prompt é constante de módulo byte-estável (ADR-0015 §5); trocá-lo em runtime seria
exatamente o botão de ajuste que aquela regra proíbe.

**Nota de topologia.** O benchmark roda no host, não dentro do container da
aplicação. Não é conveniência: de dentro do container, `127.0.0.1` é o próprio
container, então a verificação de loopback impede — corretamente — que ele alcance
um Ollama que está em outro lugar. O modo local exige que a aplicação e o runtime
compartilhem a máquina, que é precisamente o alvo da Fase B (desktop).

---

## 9. Conclusão

**L13 está fechada.** Um LLM de verdade foi executado, 48 vezes, e o resultado
mudou o código.

O que o benchmark comprou, em ordem de valor:

1. **Uma prova de que a separação IA/decisão não é retórica.** Um modelo errou 100%
   das sugestões e não moveu uma única banda.
2. **Um defeito real encontrado e corrigido**, com portão estrutural que não depende
   de modelo.
3. **Uma correção medida e rejeitada** por custar metade das respostas — o tipo de
   decisão que só existe quando há número.
4. **Um número operacional** que confirma a escolha de arquitetura: 15 s por achado
   é análise sob demanda, nunca varredura.

O que ele **não** comprou: nenhuma escolha de fornecedor, nenhuma medida de
qualidade, nenhuma validação de produto. Continua valendo que o produto **não
depende de LLM para ser útil**, e o padrão continua sendo `null`/`none`.
