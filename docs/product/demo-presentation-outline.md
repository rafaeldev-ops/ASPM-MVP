# Roteiro de apresentação — demo 24/08

Conteúdo para slides + pontos de fala. ~10 slides, um deles é a demo ao vivo.
Sem enfeite: a força da apresentação é o rigor, não o hype — mantenha esse
tom em cada slide, principalmente na frente da Pride Security.

---

## 1. O problema (1 slide)

Times de segurança não têm falta de scanners. Cada scanner novo produz mais
achados, não mais decisão. O gargalo real: decidir o que é de verdade
relevante — e **lembrar** dessa decisão depois, quando o mundo muda.

> Fale um número concreto se tiver: "um time médio fecha X mil achados por
> ano como falso positivo ou risco aceito." Se não tiver, use a intuição do
> setor: a pilha de "falso positivo" não expira em nenhuma ferramenta.

## 2. A pergunta que ninguém responde hoje (1 slide)

> "Dos achados que fechamos como falso positivo ou risco aceito no ano
> passado, quantos hoje estão numa CVE que virou exploração ativa conhecida
> — e ninguém percebeu?"

Nenhuma ferramenta de scanner responde isso. É uma pergunta sobre o
**passado da organização**, não sobre o estado atual do código.

## 3. A tese (1 slide)

Decisões de segurança acumulam **dívida** — igual dívida técnica. Uma
decisão que era correta no dia em que foi tomada pode ficar errada meses
depois, silenciosamente, porque a evidência mudou. O produto detecta essa
dívida usando dado que a organização já tem.

## 4. Demo ao vivo (1 slide de transição + a demo em si)

Rode `python v1_backtest.py --demo` na tela. Sem instalar nada, sem subir
servidor. Narre enquanto roda:

- lê um export sintético de achados fechados
- consulta a lista oficial da CISA de vulnerabilidades exploradas ativamente
  (KEV) — uma chamada de rede, cacheada
- calcula, **por data**: quais CVEs entraram na KEV *depois* que o achado foi
  fechado (dívida de decisão de verdade) vs. quais *já estavam* na KEV no
  dia em que foi fechado (pior — fechado apesar de já ser conhecido)
- gera um relatório HTML local, nada sai da máquina

Abra o `decision-debt-report.html` gerado e mostre os dois números no topo.
Esse é o momento que precisa aterrissar — pare de falar por 5 segundos
depois de abrir o relatório, deixe a pessoa ler os números sozinha.

## 5. Por que isso é defensável, não só uma demo bonita (1 slide)

O diferencial não é a demo — é que **cada decisão de comparação foi
questionada antes de ser confiada**:

- O relatório separa "dívida de decisão" de "fechado apesar de já saber" —
  são histórias diferentes, e misturar os dois infla o número de um jeito
  que quem recebe o relatório notaria.
- EPSS (outro sinal de risco comum no mercado) foi **testado e rejeitado**
  como gatilho: uma troca de versão do modelo moveu 71.885 CVEs através de
  um limiar comum em dez dias, contra 306 em dez dias de mudança real —
  235× de inflação. Usar isso teria fabricado números falsos. A KEV não tem
  esse problema porque a data de entrada é um fato, não um score.
- A árvore de decisão de risco do projeto (documento de arquitetura) foi
  **executada**, não só lida — e isso achou 3 defeitos reais nela antes de
  qualquer linha de produto ser escrita.

> Essa é a frase-chave do slide: "uma especificação que nunca foi executada
> é um rascunho." O projeto trata os próprios documentos como hipóteses a
> testar, não como verdade.

## 6. Estado real do projeto — honestidade sobre o que existe (1 slide)

Duas colunas: **o que roda hoje** vs. **o que está desenhado, não construído**.

| Roda hoje | Desenhado, não construído |
|---|---|
| Backtest de dívida de decisão (a demo) | Ingestão multi-fonte, correlação |
| Árvore de risco determinística, testada | Motor de decisão com IA |
| 17 decisões de arquitetura documentadas | Banco de dados, API, UI |

Não esconda a coluna da direita — é isso que mostra que o próximo passo é
deliberado, não que "faltou tempo".

## 7. O que vem depois (1 slide)

Antes de construir a plataforma inteira (~76 semanas de engenheiro
estimadas), o passo é validar com dado real: pegar um export de achados
fechados de uma organização de verdade, rodar o mesmo script, e perguntar a
um analista de segurança se ele gostaria de ter sabido. **Sem isso, não faz
sentido construir o resto.**

## 8. O pedido explícito para a Pride Security (1 slide, se for pra Pride também)

Seja direto e específico — não peça "parceria" de forma vaga:

> "Um export dos achados que vocês fecharam nos últimos 12 meses (CSV ou
> JSON, de qualquer ferramenta) e 60 minutos para revisar o resultado
> comigo. Nada sai do computador de vocês — o script roda local."

Isso é uma pergunta que qualquer diretor de segurança consegue responder na
hora: sim, não, ou "deixa eu ver com o time".

## 9. Perguntas / discussão

Prepare a resposta curta para a pergunta óbvia: **"isso não é só um script
com CSV e uma API pública?"** — Sim, e é exatamente o ponto: o valor não
está na complexidade técnica agora, está em provar que a pergunta importa
antes de gastar meses construindo a resposta errada.

---

## Checklist antes do dia 24

- [ ] Rodar `python v1_backtest.py --demo` uma vez ANTES da apresentação, no
      computador que vai ser usado, para o cache da KEV já estar baixado
      (evita depender de rede na hora)
- [ ] Ter o `decision-debt-report.html` já gerado como backup, caso a demo
      ao vivo falhe por qualquer motivo de ambiente
- [ ] Decorar os dois números do topo do relatório de cor, para não precisar
      ler a tela
