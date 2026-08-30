"""
Versionamento de schema.

Hoje o banco nasce de `Base.metadata.create_all()`, que cria tabela nova mas
**nunca altera existente**. Isso funciona enquanto o banco e descartavel. Deixa
de funcionar no momento em que ele vira dado instalado na maquina de alguem, e a
primeira mudanca de coluna sem caminho de migracao e perda de dado ou uma nota
de versao dizendo "apague seu banco".

Migracoes sao **funcoes em modulo comum**, nao arquivos descobertos por
diretorio. A razao e especifica e olha para a frente: o Alembic resolve
`script_location` por caminho em disco, e num executavel congelado esse
diretorio cai sob a raiz de extracao. Funcao importada e so mais um import.

Saida registrada, para nao virar porta de mao unica: se surgir migracao com
ramificacao ou PostgreSQL, adota-se Alembic carimbando `alembic_version` a
partir de `schema_version`.

ORDEM IMPORTA. `init_db()` roda `create_all()` **antes** de `migrate()`, entao um
banco novo ja nasce na forma final e as migracoes rodam sobre ele. Por isso toda
migracao tem que ser **idempotente** -- checar antes de alterar, nunca assumir.
"""

from datetime import datetime, timezone

from sqlalchemy import text

SCHEMA_VERSION = 2


def _table_exists(conn, name):
    row = conn.execute(text(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=:n"
    ), {"n": name}).first()
    return row is not None


def _columns(conn, table):
    if not _table_exists(conn, table):
        return set()
    return {r[1] for r in conn.execute(text(f"PRAGMA table_info({table})"))}


def add_column_if_missing(conn, table, column, ddl_type):
    """`ALTER TABLE ... ADD COLUMN` idempotente.

    Existe como helper porque e a operacao que toda migracao futura vai querer, e
    porque esquecer a checagem quebra exatamente o caso que o mecanismo existe
    para proteger: um banco que ja passou pelo `create_all`.
    """
    if not _table_exists(conn, table):
        return False
    if column in _columns(conn, table):
        return False
    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl_type}"))
    return True


# --------------------------------------------------------------------------
# As migracoes
# --------------------------------------------------------------------------

def _m001_ai_layer(conn):
    """Carimba a versao 1.

    Nao altera nada: as tabelas da camada de IA (`settings`, `ai_analyses`) sao
    criadas pelo `create_all`, que lida bem com tabela nova. Esta migracao existe
    para estabelecer o mecanismo enquanto ele ainda e barato -- o momento de
    introduzir versionamento de schema e antes de precisar dele, nunca depois.
    """
    return {"note": "baseline da camada de IA; nenhuma alteracao estrutural"}


def _m002_decision_ai_link(conn):
    """Liga a decisao do analista a analise que a sugeriu.

    **A primeira migracao que altera tabela existente**, e por isso a primeira que
    justifica o mecanismo. Num banco novo o `create_all` ja criou as colunas e
    `add_column_if_missing` nao faz nada; num banco que ja existia, elas sao
    acrescentadas aqui.

    Sem FK declarada no `ALTER`: o SQLite nao adiciona restricao de chave
    estrangeira depois do fato, e fingir que adiciona seria pior que nao ter.
    A relacao esta no modelo, e a integridade de um banco local de um usuario nao
    justifica reconstruir a tabela.
    """
    changed = [
        add_column_if_missing(conn, "decisions", "ai_analysis_id", "INTEGER"),
        add_column_if_missing(conn, "decisions", "ai_suggested_reason", "VARCHAR(30)"),
    ]
    n = sum(1 for c in changed if c)
    return {"note": f"decisions: {n} coluna(s) de vinculo com analise de IA"}


MIGRATIONS = [
    (1, _m001_ai_layer),
    (2, _m002_decision_ai_link),
]


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------

def _ensure_table(conn):
    conn.execute(text(
        "CREATE TABLE IF NOT EXISTS schema_version ("
        " version INTEGER NOT NULL PRIMARY KEY,"
        " applied_at TEXT NOT NULL,"
        " note TEXT)"
    ))


def current_version(conn):
    _ensure_table(conn)
    row = conn.execute(text("SELECT MAX(version) FROM schema_version")).first()
    return int(row[0]) if row and row[0] is not None else 0


def migrate(engine):
    """Aplica o que falta. Idempotente: rodar de novo nao faz nada.

    Cada migracao roda na propria transacao, entao uma falha no meio da lista
    deixa o banco numa versao intermediaria conhecida em vez de num estado que
    ninguem sabe nomear.
    """
    applied = []
    with engine.begin() as conn:
        version = current_version(conn)

    for target, fn in MIGRATIONS:
        if target <= version:
            continue
        with engine.begin() as conn:
            result = fn(conn) or {}
            conn.execute(
                text("INSERT INTO schema_version (version, applied_at, note) "
                     "VALUES (:v, :a, :n)"),
                {"v": target,
                 "a": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 "n": str(result.get("note", ""))[:300]})
        applied.append(target)

    with engine.begin() as conn:
        final = current_version(conn)

    return {"from": version, "to": final, "applied": applied,
            "expected": SCHEMA_VERSION}
