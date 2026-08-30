"""
A interface de provider e a classe de egresso.

`is_external: bool` nao descreve o mundo novo. O Ollama e outro processo sobre um
socket: "o dado nao sai do processo" e falso, "nao sai da maquina" e verdadeiro,
"nao chega a terceiros" e verdadeiro. Um booleano nao carrega essa distincao, e
ela e exatamente a que o usuario esta comprando.

`is_external` sobrevive como propriedade derivada, para o contrato existente e
`tests/test_api.py:143` continuarem valendo -- e continuarem significando o que
dizem.
"""

import threading
from datetime import datetime, timezone
from enum import Enum

# Uma geracao de 60 s segura uma thread do pool do FastAPI. Fila num aplicativo
# de desktop e so uma falha mais lenta, entao acima do teto devolvemos `busy` na
# hora em vez de enfileirar.
_SLOTS = threading.Semaphore(2)


class EgressClass(str, Enum):
    NONE = "none"
    LOCALHOST = "localhost"
    THIRD_PARTY = "third_party"

    @property
    def rank(self):
        return {"none": 0, "localhost": 1, "third_party": 2}[self.value]

    @property
    def label(self):
        return {"none": "nenhum", "localhost": "local",
                "third_party": "terceiros"}[self.value]

    @property
    def explanation(self):
        return {
            "none": "Nenhuma chamada. A sintese e deterministica, feita neste processo.",
            "localhost": ("O modelo roda nesta maquina. O contexto vai por loopback "
                          "e nao atravessa a rede."),
            "third_party": ("O contexto do achado sai desta maquina e vai para o "
                            "fornecedor selecionado."),
        }[self.value]


# --------------------------------------------------------------------------
# Erros tipados
# --------------------------------------------------------------------------

class ProviderError(Exception):
    outcome = "malformed"


class ProviderUnavailable(ProviderError):
    """Runtime desligado, chave ausente, modelo inexistente."""
    outcome = "unavailable"


class ProviderTimeout(ProviderError):
    outcome = "timeout"


class ProviderRefusal(ProviderError):
    """HTTP 200 com recusa. E evento operacional recorrente num produto cujo
    corpus inteiro e descricao de vulnerabilidade (ADR-0015 §6)."""
    outcome = "refused"


class ProviderMalformed(ProviderError):
    outcome = "malformed"


class ProviderBusy(ProviderError):
    outcome = "busy"


# --------------------------------------------------------------------------
# Valores
# --------------------------------------------------------------------------

class ProviderStatus:
    """Resultado de sondagem. Construir isto nao faz I/O."""

    def __init__(self, available, detail="", models=(), checked_at=None):
        self.available = bool(available)
        self.detail = detail
        self.models = tuple(models)
        self.checked_at = checked_at or datetime.now(timezone.utc)

    def as_dict(self):
        return {"available": self.available, "detail": self.detail,
                "models": list(self.models), "checked_at": self.checked_at}


class ProviderResponse:
    """O que o adaptador devolve: cru, mais telemetria.

    Validar nao e trabalho do adaptador -- a ADR-0015 §1 define o escopo como
    transporte, retry, timeout e telemetria. Quem valida e `contract.py`.
    """

    def __init__(self, parsed=None, model=None, tokens_in=None, tokens_out=None,
                 latency_ms=0, attempts=1, stop_reason=None, http_status=None):
        self.parsed = parsed
        self.model = model
        self.tokens_in = tokens_in
        self.tokens_out = tokens_out
        self.latency_ms = latency_ms
        self.attempts = attempts
        self.stop_reason = stop_reason
        self.http_status = http_status


class AnalysisRequest:
    """O pedido. Só pode ser montado a partir de um contexto já redigido -- é
    esse tipo que faz o portão de privacidade valer."""

    def __init__(self, context, schema, settings):
        self.context = context
        self.schema = schema
        self.settings = settings


# --------------------------------------------------------------------------
# Base
# --------------------------------------------------------------------------

class AIProvider:
    name = "base"
    egress = EgressClass.NONE
    requires_api_key = False
    supports_structured_output = False

    def __init__(self, settings=None):
        from app.application.ai.settings import AISettings
        self.settings = settings or AISettings()

    @property
    def is_external(self):
        """Compatibilidade. `egress` e a verdade; isto e derivado dela."""
        return self.egress is EgressClass.THIRD_PARTY

    def status(self, timeout=None):
        """Sondagem. Nunca levanta, e **nunca envia dado de achado**."""
        return ProviderStatus(True, "Sintese deterministica, sempre disponivel.")

    # ----- FINAL. Nao sobrescrever. -----
    def analyze(self, request):
        """Portao de tipo, semaforo e relogio; depois delega para `_call`.

        Este metodo e o substituto estrutural do MyPy strict que a ADR-0011
        pressupoe e que este repositorio nao tem. Esquecer a checagem exige
        editar esta classe base -- e um teste de reflexao afirma que nenhum
        provider registrado define `analyze` no proprio `__dict__`.
        """
        # Import tardio de proposito: `redaction` importa `EgressClass` daqui, e
        # o ciclo se resolve adiando esta ponta para o momento da chamada.
        from app.application.ai.redaction import RedactedContext

        if not isinstance(request.context, RedactedContext):
            raise TypeError(
                "analyze() aceita apenas RedactedContext. Um FindingContext cru "
                "nunca pode chegar a um provider.")

        if request.context.egress is not self.egress:
            raise TypeError(
                f"contexto redigido para egresso {request.context.egress.value}, "
                f"mas o provider e {self.egress.value}")

        if not _SLOTS.acquire(blocking=False):
            raise ProviderBusy("Ha analises em andamento. Tente de novo em instantes.")
        try:
            return self._call(request)
        finally:
            _SLOTS.release()

    def _call(self, request):
        raise NotImplementedError

    # ----- compatibilidade com o caminho de renderizacao -----
    def summarize_risk(self, context):
        """Sintese deterministica dos cinco campos historicos.

        Continua existindo, e continua sendo o que a tela de achado usa em toda
        renderizacao. Nao faz I/O em nenhum provider: e a implementacao da base,
        e nenhum adaptador a sobrescreve.
        """
        from app.application.ai.contract import deterministic_summary
        return deterministic_summary(context)
