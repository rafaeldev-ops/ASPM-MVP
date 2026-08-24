# Aplicacao web de demonstracao do SDIP.
#
# Isto NAO e a plataforma. E o instrumento local descrito em
# docs/PROJECT_STATE.md -- sem tenancy, sem autenticacao, sem LLM. Roda numa
# maquina, para uma pessoa, e faz UMA chamada externa: o catalogo CISA KEV.
#
# Base 3.12-slim: CLAUDE.md secao 21 fixa Python 3.12+ como a stack do projeto.
FROM python:3.12-slim

# Least privilege (CLAUDE.md secao 18). UID alto e fixo para o volume nomeado
# manter dono estavel entre rebuilds.
RUN useradd --create-home --uid 10001 sdip

WORKDIR /app

# Dependencias antes do codigo: a camada de pip so reconstroi quando
# requirements.txt muda, nao a cada edicao de template.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# /data guarda o banco (historico de execucoes) e o cache da KEV.
# Sem um volume montado ai, o container comeca vazio a cada execucao.
ENV SDIP_DB_PATH=/data/sdip.db \
    SDIP_CACHE_DIR=/data/kev-cache \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN mkdir -p /data /data/kev-cache && chown -R sdip:sdip /data

USER sdip

EXPOSE 8000

# curl nao existe na imagem slim; o healthcheck usa a stdlib que ja esta aqui.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status == 200 else 1)"]

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
