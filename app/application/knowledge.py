"""
Conhecimento externo: CISA KEV e EPSS, com proveniencia e regra temporal.

Le os datasets ja ingeridos em `datasets/processed/` quando existem, e cai para
o cache do `phase0/` quando nao. Nada aqui faz chamada de rede no caminho de
request -- o carregamento e explicito e cacheado em memoria.

A regra que este modulo protege e a mesma de `evaluation/ring0/decision_debt.py`:

    Toda consulta de estado exige uma data. Nao existe metodo que responda
    "esta no KEV?" sem um `as_of`, e a data de entrada nao sai da funcao se for
    posterior ao `as_of`.

EPSS entra como SINAL CONTEXTUAL de ordenacao, nunca como gatilho. EXP-001 e
EXP-004 mediram por que: um deslocamento de 25% nos scores move ~22.900 CVEs
atraves do limiar 0,01, contra ~23 entradas de KEV por mes.
"""

import csv
import gzip
import json
import os
from datetime import date, datetime

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PROCESSED = os.path.join(REPO_ROOT, "datasets", "processed")
PHASE0_CACHE = os.path.join(REPO_ROOT, "phase0", ".cache")

# SDIP_CACHE_DIR e o mesmo diretorio que o instrumento de backtest usa. No
# container ele aponta para o volume, e `phase0/` nem existe na imagem -- sem
# isto o MVP subiria sem catalogo e o dataset de demonstracao falharia.
CACHE_DIR = os.environ.get("SDIP_CACHE_DIR") or PHASE0_CACHE

KEV_SNAPSHOT = os.path.join(PROCESSED, "kev_12m_snapshot.json")
KEV_FALLBACK = os.path.join(PHASE0_CACHE, "kev.json")
KEV_CACHE = os.path.join(CACHE_DIR, "kev.json")
EPSS_SNAPSHOT = os.path.join(PHASE0_CACHE, "epss-2026-08-14.csv.gz")
EPSS_CACHE = os.path.join(CACHE_DIR, "epss-2026-08-14.csv.gz")

KEV_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
KEV_FEED_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
                "known_exploited_vulnerabilities.json")


def _ensure_kev_cache():
    """Baixa o catalogo uma vez se nao houver nenhuma copia local.

    E a mesma unica chamada externa que o instrumento de backtest ja faz, para
    o mesmo arquivo. Falha em silencio: sem rede, o sistema segue sem catalogo
    e diz isso na tela, em vez de nao subir.
    """
    if any(os.path.exists(p) for p in (KEV_SNAPSHOT, KEV_FALLBACK, KEV_CACHE)):
        return
    try:
        import urllib.request
        os.makedirs(CACHE_DIR, exist_ok=True)
        with urllib.request.urlopen(KEV_FEED_URL, timeout=90) as r, \
                open(KEV_CACHE, "wb") as f:
            f.write(r.read())
    except Exception:
        pass


def as_date(d):
    if isinstance(d, datetime):
        return d.date()
    if isinstance(d, date):
        return d
    if d is None:
        return None
    return datetime.strptime(str(d)[:10], "%Y-%m-%d").date()


class TemporalLeakageError(Exception):
    """Alguem tentou usar informacao posterior a data consultada."""


class KevCatalog:
    """Catalogo KEV carregado, com consultas as-of."""

    def __init__(self, entries, version, window, is_complete=False):
        self.by_cve = entries
        self.version = version
        self.window_start, self.window_end = window
        # Catalogo completo (todas as entradas desde 2021-11-03) contra recorte
        # de janela. A diferenca decide o que a AUSENCIA de um CVE significa:
        # num catalogo completo ela e um fato ("nunca entrou no KEV"); num
        # recorte e ignorancia ("pode ter entrado antes da janela"). Tratar as
        # duas igual erra numa das duas direcoes, sempre.
        self.is_complete = is_complete

    @classmethod
    def load(cls):
        """Carrega o catalogo mais informativo disponivel.

        Quando existem os dois, o catalogo COMPLETO vence a janela de 12 meses.
        A janela e util para um experimento com escopo declarado; para o produto
        ela e uma perda: um CVE fora dela vira `UNKNOWN_OUTSIDE_WINDOW`, e o
        sistema passa a recusar responder sobre decisoes que o catalogo completo
        responderia. Preferir o maior nao e otimizacao -- e nao jogar fora
        evidencia que ja esta no disco.
        """
        _ensure_kev_cache()
        candidates = []
        if os.path.exists(KEV_SNAPSHOT):
            candidates.append(("snapshot", KEV_SNAPSHOT))
        for path in (KEV_FALLBACK, KEV_CACHE):
            if os.path.exists(path):
                candidates.append(("full", path))
        if not candidates:
            return cls({}, "unavailable", (None, None))
        best = max(candidates, key=lambda c: cls._count_of(c[0], c[1]))
        return cls._load_from(best[0], best[1])

    @staticmethod
    def _count_of(kind, path):
        try:
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
            return len(d["records"] if kind == "snapshot" else d["vulnerabilities"])
        except (OSError, ValueError, KeyError):
            return 0

    @classmethod
    def _load_from(cls, kind, path):
        if kind == "snapshot":
            with open(path, encoding="utf-8") as f:
                body = json.load(f)
            recs = body["records"]
            prov = body.get("_provenance", {})
            entries = {
                r["cve_id"]: {
                    "cve_id": r["cve_id"], "date_added": as_date(r["date_added"]),
                    "vendor": r["vendor_project"], "product": r["product"],
                    "name": r["vulnerability_name"], "cwes": r.get("cwes", []),
                    "known_ransomware": r["known_ransomware"],
                    "short_description": r.get("short_description", ""),
                    "notes": r.get("notes", ""), "due_date": r.get("due_date"),
                } for r in recs}
            version = prov.get("version", "unknown")
        else:
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
            entries = {
                v["cveID"]: {
                    "cve_id": v["cveID"], "date_added": as_date(v["dateAdded"]),
                    "vendor": v.get("vendorProject", ""), "product": v.get("product", ""),
                    "name": v.get("vulnerabilityName", ""),
                    "cwes": v.get("cwes", []) or [],
                    "known_ransomware": str(
                        v.get("knownRansomwareCampaignUse", "")).lower() == "known",
                    "short_description": v.get("shortDescription", ""),
                    "notes": v.get("notes", ""), "due_date": v.get("dueDate"),
                } for v in d["vulnerabilities"]}
            version = d.get("catalogVersion", "unknown")

        dates = [e["date_added"] for e in entries.values() if e["date_added"]]
        return cls(entries, version, (min(dates), max(dates)) if dates else (None, None),
                   is_complete=(kind == "full"))

    def date_added(self, cve_id):
        e = self.by_cve.get(str(cve_id or "").upper())
        return e["date_added"] if e else None

    def entry(self, cve_id):
        return self.by_cve.get(str(cve_id or "").upper())

    def state_as_of(self, cve_id, as_of):
        """IN_KEV | NOT_IN_KEV | UNKNOWN_OUTSIDE_WINDOW.

        A terceira existe porque o snapshot pode cobrir uma janela: um CVE
        ausente pode nunca ter entrado no KEV, ou ter entrado antes da janela.
        Responder NOT_IN_KEV nos dois casos afirmaria o que o dado nao sustenta.
        """
        as_of = as_date(as_of)
        added = self.date_added(cve_id)
        if added is None:
            # Catalogo completo: a ausencia e um fato. O KEV comecou em
            # 2021-11-03; um CVE que nunca aparece nele nunca entrou.
            # Recorte de janela: a ausencia e ignorancia, e dizer NOT_IN_KEV
            # seria afirmar o que o dado nao sustenta.
            return "NOT_IN_KEV" if self.is_complete else "UNKNOWN_OUTSIDE_WINDOW"
        if self.window_start and as_of < self.window_start and not self.is_complete:
            return "UNKNOWN_OUTSIDE_WINDOW"
        return "IN_KEV" if added <= as_of else "NOT_IN_KEV"

    def knowledge_as_of(self, cve_id, as_of):
        """O que se sabia naquele dia. Cego para o futuro, por construcao."""
        as_of = as_date(as_of)
        added = self.date_added(cve_id)
        known = added is not None and added <= as_of
        entry = self.entry(cve_id)
        return {
            "cve_id": str(cve_id or "").upper(),
            "as_of": as_of.isoformat() if as_of else None,
            "kev_state": self.state_as_of(cve_id, as_of),
            "kev_date_added_if_known": added.isoformat() if known else None,
            "known_ransomware_if_known": (
                bool(entry["known_ransomware"]) if (entry and known) else None),
            "source": "CISA KEV",
            "source_authority": "authoritative",
            "catalog_version": self.version,
        }

    def entered_after(self, cve_id, decision_date):
        added = self.date_added(cve_id)
        d = as_date(decision_date)
        return bool(added and d and added > d)


class EpssIndex:
    """EPSS como sinal contextual. Nunca gatilho.

    O carregamento e preguicoso: 359k linhas so entram em memoria se alguem
    pedir um score.
    """

    def __init__(self):
        self._scores = None
        self.model_version = None
        self.score_date = None

    def _ensure(self):
        if self._scores is not None:
            return
        self._scores = {}
        path = next((p for p in (EPSS_SNAPSHOT, EPSS_CACHE) if os.path.exists(p)), None)
        if path is None:
            return
        with gzip.open(path, "rt", encoding="utf-8") as f:
            header = f.readline().strip().lstrip("#")
            for part in header.split(","):
                if part.startswith("model_version:"):
                    self.model_version = part.split(":", 1)[1]
                elif part.startswith("score_date:"):
                    self.score_date = part.split(":", 1)[1]
            for row in csv.DictReader(f):
                try:
                    self._scores[row["cve"].upper()] = (
                        float(row["epss"]), float(row["percentile"]))
                except (TypeError, ValueError, KeyError):
                    continue

    def get(self, cve_id):
        """(score, percentile) ou (None, None). Nunca levanta."""
        if not cve_id:
            return None, None
        self._ensure()
        return self._scores.get(str(cve_id).upper(), (None, None))

    @property
    def available(self):
        self._ensure()
        return bool(self._scores)


_kev = None
_epss = None


def kev():
    global _kev
    if _kev is None:
        _kev = KevCatalog.load()
    return _kev


def epss():
    global _epss
    if _epss is None:
        _epss = EpssIndex()
    return _epss


def versions():
    """Versoes das fontes, para gravar no snapshot de importacao."""
    e = epss()
    return {
        "kev_catalog": kev().version,
        "kev_window": [str(kev().window_start), str(kev().window_end)],
        "epss_model": e.model_version if e.available else "unavailable",
        "epss_score_date": e.score_date if e.available else None,
    }
