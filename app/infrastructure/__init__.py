"""
Infraestrutura: o que fala com o mundo fora do processo.

Nada aqui importa de `app.domain` ou `app.application`. A dependencia corre numa
direcao so, e isso e o que permite testar transporte e credencial isolados, sem
banco e sem aplicacao.
"""
