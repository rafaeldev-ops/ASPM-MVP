"""
Detector de segredo, para o portao de saida.

**A parte que decide se este portao sobrevive ao contato com usuario nao e a
lista de padroes: e o allowlist de forma, que roda primeiro.** Id de CVE, GHSA,
CWE, semver e hash SHA-256 sao dados que legitimamente enviamos como
proveniencia. Um detector que dispara neles vira ruido, ruido vira controle
desligado, e controle desligado e pior que controle nenhum.

Este detector e **defesa em profundidade, nao a fronteira**. A fronteira sao os
controles estruturais: `no_code` como unico tier e a exclusao de `raw_json`. A
ADR-0011 responde falso-negativo com canario em CI, que este repositorio ainda
nao tem -- e dizer isso e mais honesto que confiar num regex.

Somente biblioteca padrao.
"""

import math
import re

# Padroes de alta precisao. Cada um casa uma credencial de formato conhecido,
# nao "algo que parece secreto".
PATTERNS = (
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.")),
    ("connection_string",
     re.compile(r"\b(?:postgres|postgresql|mysql|mongodb|redis|amqp)://"
                r"[^:@/\s]+:[^@/\s]+@", re.I)),
    ("basic_auth_url", re.compile(r"\bhttps?://[^:@/\s]+:[^@/\s]+@", re.I)),
    ("assigned_secret",
     re.compile(r"\b(?:password|passwd|secret|api[_-]?key|token)\s*[=:]\s*"
                r"[\"']?[^\s\"',;]{8,}", re.I)),
)

# Formas legitimas. Verificadas ANTES da entropia.
_SHAPE_ALLOWLIST = (
    re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I),
    re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$", re.I),
    re.compile(r"^CWE-\d+$", re.I),
    re.compile(r"^v?\d+(\.\d+){1,3}([.-][A-Za-z0-9]+)*$"),   # semver
    re.compile(r"^[0-9a-f]{7,40}$", re.I),                    # sha de commit
    re.compile(r"^[0-9a-f]{64}$", re.I),                      # sha-256, proveniencia
    re.compile(r"^\d{4}-\d{2}-\d{2}"),                        # data ISO
    re.compile(r"^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"),  # e-mail
)

_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_-]{20,}")

ENTROPY_THRESHOLD = 4.0
HEX_ENTROPY_THRESHOLD = 3.0
HEX_MIN_LEN = 32


def shannon_entropy(s):
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _allowed_shape(token):
    return any(p.match(token) for p in _SHAPE_ALLOWLIST)


def scan(text):
    """Devolve `[(detector_id, inicio, fim)]`. Nunca inclui o valor casado."""
    if not text or not isinstance(text, str):
        return []
    hits = []
    for name, pattern in PATTERNS:
        for m in pattern.finditer(text):
            hits.append((name, m.start(), m.end()))

    covered = [(a, b) for _, a, b in hits]
    for m in _TOKEN_RE.finditer(text):
        token = m.group(0)
        if _allowed_shape(token):
            continue
        if any(a <= m.start() < b for a, b in covered):
            continue
        is_hex = bool(re.fullmatch(r"[0-9a-fA-F]+", token))
        if is_hex:
            if len(token) >= HEX_MIN_LEN and shannon_entropy(token) >= HEX_ENTROPY_THRESHOLD:
                hits.append(("high_entropy_hex", m.start(), m.end()))
        elif shannon_entropy(token) >= ENTROPY_THRESHOLD:
            hits.append(("high_entropy", m.start(), m.end()))

    hits.sort(key=lambda h: (h[1], h[2]))
    return hits


def redact_text(text):
    """Substitui por marcador tipado. Devolve `(texto, [detector_ids])`.

    O valor casado nunca sai daqui, nem para o registro -- so o nome do detector.
    """
    hits = scan(text)
    if not hits:
        return text, []

    out, cursor, found = [], 0, []
    last_end = -1
    for name, start, end in hits:
        if start < last_end:      # sobreposto; o primeiro ja cobriu
            continue
        out.append(text[cursor:start])
        out.append(f"[REDIGIDO:{name}]")
        cursor, last_end = end, end
        found.append(name)
    out.append(text[cursor:])
    return "".join(out), found


def has_secret(text):
    return bool(scan(text))
