"""
Configuracao da camada de IA.

Precedencia: **variavel de ambiente > banco > default.** Nao e arbitraria:
`tests/support.py` define `SDIP_AI_PROVIDER` antes de importar `app.*`, e
`tests/test_api.py` passa a variavel para o subprocesso uvicorn. Ambiente vencendo
mantem os dois deterministicos mesmo numa maquina cujo `sdip.db` tem OpenAI
configurada, e deixa o caminho Docker intacto.

Valor corrompido ou desconhecido degrada para o default em vez de derrubar -- a
mesma disciplina que a selecao de provider ja aplicava a um nome invalido.
"""

import hashlib
import json
import os
from dataclasses import asdict, dataclass, replace

from sqlalchemy import select

PREFIX = "ai."
VALID_TIERS = ("no_code",)  # unico tier no MVP (ADR-0011 §3)


@dataclass(frozen=True)
class AISettings:
    provider: str = "null"
    model: str = ""
    base_url: str = ""
    tier: str = "no_code"
    timeout_s: float = 60.0
    probe_timeout_s: float = 1.5
    max_output_tokens: int = 900
    # Preco e configuracao, nunca constante no codigo (ADR-0008 §3: instrumentar
    # custo por decisao desde o primeiro dia, sem fixar tabela de preco).
    cost_per_1k_in: float = 0.0
    cost_per_1k_out: float = 0.0

    def fingerprint(self):
        """Impressao digital da configuracao.

        E o que permite reconstruir o provider so quando algo muda de verdade --
        uma construcao por configuracao, nao por requisicao, mas sem exigir
        reinicio quando o usuario troca de provider na tela.
        """
        blob = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()[:16]

    def as_public(self):
        """Forma segura para tela e API. Nao ha segredo aqui por construcao -- a
        chave nunca esteve neste objeto."""
        d = asdict(self)
        d["fingerprint"] = self.fingerprint()
        return d


_FIELDS = {
    "provider": str, "model": str, "base_url": str, "tier": str,
    "timeout_s": float, "probe_timeout_s": float,
    "max_output_tokens": int, "cost_per_1k_in": float, "cost_per_1k_out": float,
}

_ENV = {"provider": "SDIP_AI_PROVIDER", "model": "SDIP_AI_MODEL",
        "base_url": "SDIP_AI_BASE_URL"}


def _coerce(name, raw, default):
    if raw is None:
        return default
    caster = _FIELDS[name]
    try:
        value = caster(raw)
    except (TypeError, ValueError):
        return default
    if name in ("timeout_s", "probe_timeout_s") and not (0.1 <= value <= 600):
        return default
    if name == "max_output_tokens" and not (1 <= value <= 32000):
        return default
    if name == "tier" and value not in VALID_TIERS:
        return default
    if name in ("cost_per_1k_in", "cost_per_1k_out") and value < 0:
        return default
    return value


def load(session=None, org_id=None):
    """Configuracao efetiva. Funciona sem sessao -- so ambiente e defaults."""
    from app.domain.models import DEFAULT_ORG, Setting
    org_id = org_id or DEFAULT_ORG
    base = AISettings()
    values = {}

    if session is not None:
        try:
            rows = session.scalars(select(Setting).where(
                Setting.org_id == org_id, Setting.key.like(PREFIX + "%"))).all()
        except Exception:
            rows = []
        for row in rows:
            name = row.key[len(PREFIX):]
            if name in _FIELDS:
                values[name] = _coerce(name, row.value, getattr(base, name))

    for name, var in _ENV.items():
        raw = (os.environ.get(var) or "").strip()
        if raw:
            values[name] = _coerce(name, raw, getattr(base, name))

    return replace(base, **values)


def save(session, updates, org_id=None, updated_by=None):
    """Grava as chaves informadas. Ignora nome desconhecido em silencio, para um
    formulario mais novo que o codigo nao derrubar a tela."""
    from app.domain.models import DEFAULT_ORG, Setting
    org_id = org_id or DEFAULT_ORG
    base = AISettings()
    written = []

    for name, raw in (updates or {}).items():
        if name not in _FIELDS:
            continue
        value = _coerce(name, raw, getattr(base, name))
        row = session.scalars(select(Setting).where(
            Setting.org_id == org_id, Setting.key == PREFIX + name)).first()
        if row is None:
            row = Setting(org_id=org_id, key=PREFIX + name)
            session.add(row)
        row.value_json = json.dumps(value)
        row.updated_by = updated_by
        written.append(name)

    session.flush()
    return written


def env_overrides():
    """Quais chaves o ambiente esta forcando. A tela precisa dizer isso, senao o
    usuario salva na configuracao e nao entende por que nada mudou."""
    return {name: var for name, var in _ENV.items()
            if (os.environ.get(var) or "").strip()}
