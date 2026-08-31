# Roteiro da apresentação — 5 minutos, 4 integrantes

**Deck:** [`apresentacao-5min.html`](apresentacao-5min.html) · também em
[artifact](https://claude.ai/code/artifact/19dcf7db-873b-41ca-b8f2-efcdd82445ea)

**Como usar o deck ao vivo:** setas navegam, **N** abre as notas (o mesmo texto
que está aqui, slide a slide), **F** entra em tela cheia. Os slides não têm
número nem duração impressos — isso é informação de quem apresenta, e está nas
notas e na barra de progresso no rodapé da tela.

---

## Divisão

| Integrante | Slides | Tempo | Papel |
|---|---|---|---|
| **1** | 1, 2 | 1:00 | Abre. Estabelece o problema e a proposta |
| **2** | 3, 4 | 0:55 | Arquitetura: os cinco pilares e o fluxo |
| **3** | 5, 6 | 1:50 | **Demonstração ao vivo** e a dívida de decisão |
| **4** | 7, 8, 9, 10 | 1:25 | O teste da IA, honestidade sobre dados, fecho |

**Total: 5:10.** Apresentação sempre corre; a folga está no slide 4, que é de
passagem, e nos slides 8 e 9, que são curtos.

### Por que essa divisão

O Integrante 3 tem o dobro do tempo dos outros porque **a demonstração ao vivo é
o único momento em que a banca vê o produto funcionando** — e porque só quem
está com a aplicação aberta consegue emendar a demo com a linha do tempo da
dívida de decisão sem trocar de pessoa no meio.

O Integrante 4 tem quatro slides, mas três deles são curtos: o peso está no
slide 7, que é o argumento mais forte do trabalho.

---

## Antes de começar — checklist de 2 minutos

- [ ] Aplicação **já aberta** numa aba, no painel `/aspm`, com o dataset de
      demonstração carregado (12 ativos · 68 achados · 14 dívidas).
- [ ] Segunda aba já em `CVE-2021-27101` — **não navegar procurando a tela**
      durante a apresentação.
- [ ] Deck em tela cheia (**F**), na primeira tela.
- [ ] Notas abertas (**N**) só na tela do apresentador, se houver duas telas.
- [ ] Alguém marcando o tempo. Aos 3:30 o Integrante 3 tem que estar terminando.

---

## Integrante 1

### Slide 1 — Cinco scanners, uma fila · 0:25

> Toda equipe de segurança hoje tem scanner. Vários: código, dependência,
> segredo, contêiner. Cada um encontra coisa, e cada um entrega uma lista.
>
> **O resultado não é mais segurança. É mais fila.**
>
> São milhares de achados por ano, e cada um chega sem contexto. Não diz qual
> sistema afeta, se aquilo está exposto, nem se alguém já analisou o mesmo
> problema antes.

**Deixa:** pause depois de *"mais fila"*. É o único momento em que a banca ainda
não sabe do que se trata — vale um segundo de silêncio ali.

### Slide 2 — Não é mais um scanner · 0:35

> E aí vem a parte que ninguém acompanha: a maior parte desses achados é
> fechada. Falso positivo, risco aceito, mitigado. E estava certo, no dia em que
> foi decidido.
>
> O problema não é encontrar vulnerabilidade. É **decidir qual importa**, e
> continuar sabendo se aquela decisão ainda vale.
>
> E uma decisão de projeto que vale dizer agora: isto instala no notebook do
> analista, sem servidor e sem privilégio de administrador. Os dados de
> segurança ficam na máquina dele.
>
> **Transição:** para virar decisão, o achado precisa de contexto. É isso que os
> cinco componentes de uma ASPM fazem, e o nosso MVP implementa os cinco.

**Deixa:** termine na frase de transição e entregue. **Não desenvolva os cinco
componentes aqui** — eles são do Integrante 2.

---

## Integrante 2

### Slide 3 — Cinco perguntas do analista · 0:45

> São cinco perguntas, e cada componente responde uma.
>
> **O que a gente tem?** Asset Discovery: aplicações, serviços, dependências,
> com dono, ambiente e criticidade. Sem isso, todo achado parece igual.
>
> **O que está relacionado?** Correlação: o mesmo CVE em três serviços é um
> problema, não três. O sistema agrupa, e registra por que agrupou.
>
> **O que importa mais?** Priorização: severidade, criticidade do ativo,
> exposição, e se aquele CVE está na lista da CISA de exploração ativa
> conhecida.
>
> **O que fazer?** Remediação, com a fonte junto. Quando não existe fonte, o
> sistema diz que não sabe, em vez de inventar.
>
> **O risco mudou?** Monitoramento contínuo.

**Deixa:** cinco blocos curtos, um fôlego cada. Não desenvolva nenhum — quem
desenvolve é a demonstração. Se estiver atrasado, corte os exemplos e leia só as
cinco perguntas.

### Slide 4 — Um fluxo, não cinco telas · 0:10

> No MVP esses cinco não são telas separadas. São um fluxo só.
>
> E a prioridade sai de uma árvore determinística: vinte regras, setecentas e
> vinte combinações, auditável linha a linha. **Não é um modelo de linguagem
> decidindo.**
>
> **Transição:** dá para mostrar agora.

**Deixa:** slide de passagem, dez segundos. O Integrante 3 já deve estar com a
aba aberta. A frase *"não é um modelo de linguagem decidindo"* planta o slide 7
— não a corte.

---

## Integrante 3

### Slide 5 — Demonstração ao vivo · 1:15

Troque para a aplicação. **Abas já abertas.**

> Esse é o painel. Doze ativos, sessenta e oito achados, e esse número aqui,
> catorze, é o que a gente chama de **dívida de decisão**. Já volto nele.
>
> Vou abrir um achado: CVE-2021-27101, na zlib 1.2.11.
>
> O sistema classificou como **agir agora**, e não pede para acreditar. Ele
> lista o porquê: o ativo é crítico, está em produção, a versão em uso está
> dentro da faixa afetada, e o CVE consta no catálogo da CISA de exploração
> ativa. Essa última linha trava tudo: **achado em exploração ativa nunca pode
> ser silenciado.**
>
> Aqui embaixo, a evidência: fonte, autoridade, e a data do fato separada da
> data em que lemos. E a remediação: atualizar o pacote, com a origem junto.
>
> E, no fim, a análise de IA — com um selo dizendo se aquele texto saiu da
> máquina ou não. **Guardem esse selo.**

**Deixa:** o passo 5 é curto de propósito — ele é a montagem do slide do
Integrante 4. Não explique a IA aqui.

**Se a aplicação travar:** volte para o deck e siga pelo slide 6. A linha do
tempo conta a mesma história sem a tela. Não fique mexendo na aplicação.

### Slide 6 — Dívida de decisão · 0:35

> Agora o ponto. Esse achado **já tinha sido fechado**, como mitigado. Alguém
> olhou e concluiu que estava sob controle.
>
> Duzentos e dezenove dias depois, o CVE entrou no catálogo da CISA, com uso
> confirmado em ransomware.
>
> **A decisão não estava errada. Ela envelheceu. E o sistema percebeu.**
>
> **Transição:** esse é o diferencial que a gente propõe. E tem uma segunda
> coisa, que a gente descobriu testando.

**Deixa:** **PARE** depois de *"duzentos e dezenove dias"*. Deixe o número
pousar antes de continuar. É a pausa mais importante da apresentação.

---

## Integrante 4

### Slide 7 — Colocamos uma IA de verdade e medimos · 0:50

**O slide mais importante do trabalho.**

> Todo produto de segurança hoje diz que tem IA. A pergunta que ninguém responde
> é: **o que acontece quando ela erra?**
>
> A gente colocou um modelo de verdade rodando na máquina e mediu.
>
> Em **nove de nove** achados que a árvore mandava corrigir agora, o modelo
> recomendou encerrar como risco aceito. E escreveu, no mesmo texto, que eram
> críticos e urgentes. Ele se contradisse, com toda a confiança do mundo.
>
> *(pausa — vire para a coluna escura)*
>
> Agora olhem a outra coluna. Zero prioridades alteradas. Zero evidências
> inventadas. Zero decisões fechadas.
>
> **A IA errou cem por cento das recomendações e não conseguiu mexer em nada.**
> Porque na nossa arquitetura ela não decide: ela explica o que o motor
> determinístico já decidiu, e cita a evidência que recebeu. Se citar uma
> evidência que não existe, a resposta inteira é rejeitada.

**Deixa:** leia *"nove de nove"* devagar. **PARE** antes de virar para a coluna
escura — o contraste entre as duas colunas é o argumento inteiro, e ele só
funciona se houver silêncio entre elas.

### Slide 8 — Dado público real, e o fabricado · 0:20

> Sobre os dados: o MVP já roda sobre **dado público real**. O catálogo da CISA,
> cem mil achados reais de CodeQL, e a base de probabilidade de exploração do
> FIRST. São **duzentos e sete testes** automatizados.
>
> Já o histórico de decisões é **sintético**, e aparece marcado como tal em toda
> tela. Ele prova que o mecanismo funciona. **Não mede precisão em cliente.**

**Deixa:** honestidade sem pedir desculpa. **Nunca diga "precisão de cem por
cento"** — o número de precisão do MVP é contra rótulos de construção sintética,
e apresentá-lo como precisão de produto seria falso.

### Slide 9 — Próximo passo · 0:15

> É exatamente esse o próximo passo: **rodar sobre o histórico real de decisões
> de uma organização.**
>
> A gente não construiu mais um lugar para ver vulnerabilidade. Construiu a
> camada que **lembra** por que cada decisão foi tomada, e avisa quando ela
> deixa de valer.

**Deixa:** termine no fecho. **Não emende com "acho que é isso"** — respire e
vire o slide.

### Slide 10 — Obrigado · perguntas

> Era isso. Obrigado pela atenção de vocês.
>
> Ficamos à disposição para as perguntas.

**Deixa:** não corra. Deixe o slide no ar durante as perguntas — as três âncoras
são exatamente as respostas que provavelmente vão pedir.

---

## Perguntas prováveis, e quem responde

| Pergunta | Quem | Resposta curta |
|---|---|---|
| "Como vocês calculam a prioridade?" | 2 | Árvore determinística, 20 regras, 720 combinações, versionada. A IA não entra nisso |
| "Isso não é só um wrapper de LLM?" | 4 | O slide 7 é a resposta. A IA errou 9 de 9 e não moveu nada. O motor é determinístico |
| "E se a IA alucinar?" | 4 | Todo id de evidência é validado contra o que **foi entregue** ao modelo. Id desconhecido rejeita a resposta inteira |
| "Os dados vão para a OpenAI?" | 1 ou 4 | Só se o usuário escolher, e com confirmação a cada análise. O padrão é não sair da máquina |
| "Qual a precisão de vocês?" | 4 | **Não medimos precisão de produto.** O histórico é sintético; o número que temos mede o instrumento, não o mundo. É por isso que o próximo passo é dado real |
| "Testaram com quantos clientes?" | 4 | Nenhum ainda. É honestamente o gargalo, e é o pedido que a gente traz |
| "Roda em quê?" | 1 | Windows, instalação por usuário, sem admin. Também em Docker |
| "Quantos testes?" | 2 ou 4 | 207, sem framework externo |

**Regra para todos:** se não souber, diga *"não medimos isso"*. O trabalho
inteiro se apoia em separar o que foi medido do que foi suposto — inventar um
número na banca destrói exatamente esse argumento.

---

## O que nunca dizer

- ❌ *"Nossa precisão é de 100%"* — é contra rótulos sintéticos, não é precisão
  de produto.
- ❌ *"Testamos com clientes"* — zero parceiros até hoje.
- ❌ *"A IA prioriza os achados"* — ela não prioriza nada; contradiz o slide 7.
- ❌ Gastar mais de 30 segundos falando de limitações. Elas estão nos slides 8 e
  9, ditas uma vez, com clareza, e seguindo em frente.
