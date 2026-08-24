# Session Handoff — 2026-08-23

**Sessão anterior:** 2026-08-19 (implementação da aplicação web) e uma execução curta
de preparação de demo em 2026-08-23 22:45.
**Esta sessão:** inspeção completa do repositório + criação de
[`PROJECT_STATE.md`](PROJECT_STATE.md) e deste arquivo. **Nenhum código foi alterado.**
Dois arquivos existentes receberam edições de descoberta (não de conteúdo técnico):
`CLAUDE.md` ganhou um §0 apontando para estes dois arquivos, e o mapa do `README.md`
ganhou uma linha para eles.

> **Leia primeiro:** [`PROJECT_STATE.md`](PROJECT_STATE.md). Este arquivo só cobre a
> transição; o estado do projeto está lá e não é repetido aqui.

---

## O que estava sendo feito?

**[F] Preparação da apresentação de 2026-08-24** (roteiro em
`docs/product/demo-presentation-outline.md`, audiência: Pride Security).

A evidência disso é o timestamp dos artefatos, não uma lembrança de conversa:
`phase0/demo-export.csv` e `phase0/decision-debt-report.html` foram regenerados em
2026-08-23 22:45, e uma segunda análise demo foi gravada em `sdip.db` às 22:46. Esses são
exatamente os dois primeiros itens do checklist do roteiro ("rodar `--demo` antes, para o
cache da KEV já estar baixado" e "ter o HTML gerado como backup").

Nada disso foi commitado porque todos esses arquivos são gitignorados por decisão
anterior — são regeneráveis e contêm dado sintético.

## O que foi concluído nesta sessão?

1. **Inspeção completa e verificada** do repositório: git, estrutura, `app/`, `phase0/`,
   os 44 documentos de `docs/`, os 17 ADRs, o `sdip.db` local e o cache de `phase0/.cache/`.
2. **Execução real dos quatro gates executáveis** de `phase0/README.md` e de um smoke
   test HTTP da aplicação web. Resultados e comandos exatos em
   `PROJECT_STATE.md` § Current Test Status. **Todos passaram.**
3. **`docs/PROJECT_STATE.md` criado** — estado persistente, com marcação explícita de
   fato / hipótese / decisão em cada afirmação, incluindo um índice de **9 inconsistências
   entre documentação e implementação** e os **10 follow-ups em aberto** dos dois
   experimentos, que até agora só existiam no rodapé dos próprios documentos.
4. **`docs/SESSION_HANDOFF.md` criado** (este arquivo).
5. **`CLAUDE.md` ganhou um §0** ("Start here, every session") apontando para os dois
   arquivos acima e fixando a hierarquia de informação. Essa é a **única** alteração de
   regra permanente desta sessão, e ela existe porque sem ela o checkpoint é invisível:
   o `CLAUDE.md` é carregado automaticamente numa sessão nova, o `PROJECT_STATE.md` não.
   **Nenhuma outra regra do `CLAUDE.md` foi tocada.**
6. **`README.md`** ganhou uma linha no mapa do repositório apontando para os dois arquivos.

## O que não foi concluído?

- **[F] Nada foi corrigido.** Os oito itens de § Known Limitations e o bug B1 continuam
  como estavam. Isso foi deliberado: um checkpoint não é o momento de mudar código.
- **[F] Nenhum ADR foi criado**, apesar de existir uma decisão arquitetural sem registro
  (ver abaixo). Também deliberado — ver "Existe alguma decisão que o próximo Claude NÃO
  deve desfazer?".
- **[F] Nenhum commit foi feito.** Ver § Existem mudanças não commitadas.

## O que descobrimos?

Seis coisas que não estavam escritas em lugar nenhum do repositório antes deste checkpoint:

1. **[F] O prazo de V5 / T-1 venceu.** `competitive-teardown.md` fixa 2026-08-22 para as
   quatro perguntas Nucleus numa demo. Hoje é 2026-08-23 e não existe registro de que
   tenha acontecido. Esse é o primeiro critério pré-registrado do projeto a vencer, e o
   documento é explícito sobre a consequência: *"o pitch sai com uma alegação competitiva
   não verificada. Não deixe isso acontecer."*
2. **[F] O roteiro da demo demonstra o CLI, e a aplicação web não está nele.** Os commits
   provam a razão: o roteiro entrou às 03:03 e a aplicação às 04:38 do mesmo dia
   (2026-08-19). O roteiro nunca foi atualizado. **Isso é uma decisão em aberto para
   amanhã**, não um detalhe de documentação.
3. **[F] O cache da KEV nunca expira** — em ambos os instrumentos. O catálogo em disco é
   `2026.08.14` (baixado em 2026-08-16) e nada o renova. Uma segunda execução meses depois
   sub-reporta dívida de decisão em silêncio. Registrado como L1.
4. **[F] O V0 não existe no repositório.** O kit de recrutamento está completo, mas o
   tracker do §6 é um *schema* e não há nenhum arquivo preenchido. Se houve contato com
   algum parceiro, isso só existe na cabeça de alguém — e o Phase 0 inteiro depende disso.
5. **[F] O CLI e a aplicação web concordam numericamente** no mesmo export sintético
   (900 → 698 analisadas, 100 dívida, 88 "fechado apesar de"). A portabilidade da lógica
   entre os dois está verificada, não assumida.
6. **[F] A saída de `v4_kappa.py --demo` é sintética.** Ela imprime um veredito de aparência
   convincente ("EXPECTED RESULT. Decomposition becomes the core data model", κ_derived
   0.759) que é gerado pelo próprio script. **O V4 real nunca rodou.** É o número mais
   fácil de citar por engano em um slide, e está marcado como tal no `PROJECT_STATE.md`.

## O que deu errado?

**[F] Nada quebrou nesta sessão.** Dois incidentes menores de ferramenta, ambos
resolvidos e sem efeito no repositório:

- Um heredoc grande falhou no parser do shell; o arquivo foi escrito com a ferramenta de
  escrita direta.
- O servidor de smoke test não morreu ao fim do comando que o lançou em background e teve
  de ser encerrado por PID. **A porta 8137 está livre e o processo foi confirmado morto.**
  Se um `uvicorn` órfão aparecer, é disso.

## Qual foi a causa dos problemas?

Os dois itens acima são de ferramenta, não de projeto.

**A causa dos achados 1 e 4 acima é a mesma, e vale registrar:** o repositório tem uma
disciplina alta para *decisões* (17 ADRs, thresholds pré-registrados, experimentos que
refutam os próprios documentos) e **nenhum mecanismo para o estado de execução**. Prazos
vencem, itens ficam adiados, e não havia arquivo onde isso aparecesse. É exatamente a
lacuna que `PROJECT_STATE.md` passa a cobrir — e ele só continua útil se for atualizado
quando o estado mudar.

## Qual é o próximo passo EXATO?

**Hoje / amanhã de manhã, antes da apresentação de 2026-08-24:**

1. **Decidir o que demonstrar** — CLI ou aplicação web (achado 2 acima). Se for a
   aplicação web: editar `docs/product/demo-presentation-outline.md` §4 (que hoje diz
   *"sem subir servidor"*) e o checklist final, **antes** da apresentação.
2. **Se a máquina da apresentação não for esta**, rodar `python phase0/v1_backtest.py --demo`
   nela uma vez, com rede, para popular `phase0/.cache/kev.json`. O roteiro já pede isso,
   e L1 significa que o cache não se atualiza sozinho depois.
3. **Fazer o pedido do §8 do roteiro na sala:** export de 12 meses de achados fechados +
   60 minutos de revisão. Esse pedido é o item V0 e é o gargalo do projeto inteiro.

**Depois da apresentação, em ordem:**

4. **Criar `docs/product/partner-tracker.md`** com os campos de `design-partner-kit.md` §6
   e registrar o resultado da conversa — inclusive se a resposta for não. O kit diz que a
   negativa é o dado mais valioso e o mais silenciosamente descartado.
5. **Rodar V4 de verdade:** 3 anotadores × 50 achados × 2 formulários, seguindo
   `docs/evaluation/v4-annotation-kit.md`, produzir `annotations.csv` no formato longo do
   header de `phase0/v4_kappa.py`, e rodar `python phase0/v4_kappa.py annotations.csv`.
   Documentar como `docs/evaluation/exp-003-v4-agreement.md`. É o item mais barato do
   Phase 0, não depende de ninguém de fora, e decide a forma do contrato de decisão antes
   de qualquer schema ser escrito.
6. **Agendar a demo do Nucleus (T-1).** Não pesquisar de novo — `competitive-teardown.md`
   §191 diz que a documentação foi exaurida em duas rodadas e que só o acesso ao produto
   responde.

**Não começar R0-1.** O backlog exige o gate V1 antes, e V1 exige V0.

## Qual arquivo deve ser aberto primeiro?

1. [`docs/PROJECT_STATE.md`](PROJECT_STATE.md) — o estado.
2. [`docs/product/demo-presentation-outline.md`](product/demo-presentation-outline.md) —
   o compromisso com data mais próxima.
3. [`CLAUDE.md`](../CLAUDE.md) — as regras permanentes. **§45 e §46 em particular:
   o repositório está sob a regra de não escrever código de produto ainda.**

## Quais comandos devem ser executados para validar o estado?

Do diretório raiz do repositório. Todos foram executados em 2026-08-23 com os resultados
registrados em `PROJECT_STATE.md` § Current Test Status.

```bash
# 1. Git deve estar limpo em 021b981 (ou adiante, se houve commit depois)
git status && git log -3 --oneline

# 2. Os gates executáveis do Phase 0 — nenhum precisa de instalação
cd phase0
python v2_riskmodel.py --assert       # 3 PASS
python v2_riskmodel.py --selftest     # 4 PASS
python v4_corpus.py --check --offline # "All stratum assertions hold" (usa .cache/)
cd ..

# 3. A aplicação web sobe (precisa do requirements.txt instalado)
pip install -r requirements.txt
python -m uvicorn app.main:app --port 8000
# em outro terminal:
curl http://127.0.0.1:8000/health      # {"status":"ok"}
```

**Não existe `pytest`, `ruff`, `mypy` nem CI neste repositório.** Se um comando desses
aparecer numa instrução, ele não é deste projeto — ainda.

**Cuidado com um comando:** `python phase0/v4_kappa.py --demo` roda e imprime um veredito
completo. **É dado sintético.** Não o cite como resultado.

## Existem mudanças não commitadas?

**[F] Sim, quatro — e são exatamente os arquivos deste checkpoint:**

```
?? docs/PROJECT_STATE.md      (novo)
?? docs/SESSION_HANDOFF.md    (novo)
 M CLAUDE.md                  (+1 seção: §0 "Start here, every session")
 M README.md                  (+1 linha no mapa do repositório)
```

Nada mais. O working tree estava limpo em `021b981` antes desta sessão, e **nenhum
arquivo de código, nenhum ADR e nenhum documento de design foi tocado.**

**Ignorados, presentes no disco, e que não devem ser commitados** (`.gitignore` cobre
todos, por decisão anterior e com a razão escrita no próprio arquivo): `sdip.db`,
`phase0/.cache/`, `phase0/demo-export.csv`, `phase0/decision-debt-report.html`,
`.venv/`, `.claude/`, `__pycache__/`.

**O commit não foi feito.** O prompt de checkpoint pede que o estado seja apresentado
antes.

## Há algum risco de regressão?

**[F] Nenhum.** Nenhum código foi tocado, nenhuma dependência foi alterada, nenhum ADR e
nenhum documento de design foi editado. As duas edições em arquivos existentes
(`CLAUDE.md` §0, linha no mapa do `README.md`) são puramente aditivas e de descoberta —
não removem nem contradizem nenhuma regra, requisito ou decisão anterior.

**[F] Uma coisa mudou no disco e não é regressão:** `sdip.db` recebeu leituras durante o
smoke test (nenhuma escrita nova — a análise `id=2` é de 22:46, anterior a esta sessão).
O banco é local e gitignorado.

## Existe alguma decisão que o próximo Claude NÃO deve desfazer?

**Sim. Em ordem de dano se desfeita:**

1. **EPSS não é gatilho de re-litígio.** Rejeitado com número medido (EXP-001: 235× de
   inflação). Adicioná-lo é fácil, aumenta os números do relatório, e destrói a
   credibilidade do instrumento na primeira pessoa que checar. **Não adicione EPSS
   porque "melhoraria a demo".**
2. **A comparação é as-of-data-de-fechamento, nunca as-of-hoje**, e "dívida de decisão"
   e "fechado apesar de já estar na KEV" são reportados separados e nunca fundidos.
   As duas regras são o que torna o relatório honesto.
3. **`phase0/` é arquivo único, só stdlib, sem instalação.** Não é preferência estética:
   `design-partner-kit.md` §0 mostra que é a condição que torna o pedido do V0
   respondível por um diretor de segurança. Adicionar um `requirements.txt` a `phase0/`
   quebra a validação e o argumento de venda junto.
4. **`app/` não importa de `phase0/`** (regra escrita em `phase0/README.md`). A lógica foi
   portada de propósito. Refatorar para "eliminar duplicação" quebra a promessa de que
   `phase0/` roda sozinho na máquina de outra pessoa.
5. **Nada de código de produto antes do gate.** CLAUDE.md §46 e `mvp-backlog.md` §3.
   Começar R0-1 sem V0/V1 é literalmente o modo de falha que o projeto foi montado para
   evitar.
6. **Os 17 ADRs, especialmente 0001, 0003, 0011, 0012 e 0016.** Estão listados com a razão
   em `PROJECT_STATE.md` § Important Architectural Decisions.
7. **Os thresholds pré-registrados.** `phase-0-protocols.md` §8 é o único lugar onde um
   threshold pode mudar, com data, razão e aprovador — e o original nunca é apagado.
   Hoje o log está vazio. **Mantenha-o vazio a menos que exista uma razão registrada.**

---

## Uma decisão que ficou sem ADR — para o próximo Claude decidir com o humano

**[F] A aplicação web (`app/`) introduziu SQLite + SQLAlchemy + FastAPI e não tem ADR.**
A justificativa existe, mas só no docstring de `app/db.py` e no `README.md`.

**Não criei o ADR nesta sessão**, por dois motivos: a decisão foi tomada em outra sessão e
eu reconstruiria a justificativa em vez de registrá-la; e o prompt de checkpoint pede
explicitamente para não alterar arquitetura para criar o checkpoint.

**Recomendação:** se a aplicação web for continuar existindo depois da demo, ela merece um
ADR-0018 curto respondendo as seis perguntas de CLAUDE.md §37 — em particular *"o que ela
é em relação ao Ring 0"* e *"o que acontece com o caminho `app/` quando o monólito modular
de `repository-structure.md` começar"* (limitação L6). Se ela foi só um instrumento de
demonstração, isso deve ficar escrito em algum lugar também, senão a próxima pessoa vai
tratá-la como a fundação do Ring 0 — que é precisamente o que ela não é.
