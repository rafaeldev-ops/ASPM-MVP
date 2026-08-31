# -*- mode: python ; coding: utf-8 -*-
"""
Empacotamento do Pride Security Desktop.

onedir, NAO onefile
-------------------
`--onefile` extrai tudo para um temporario a cada execucao: ~5 s de partida, e
um antivirus corporativo trata "executavel que se descompacta em %TEMP%" como
comportamento suspeito -- exatamente o publico que este produto tem. `onedir`
inicia rapido, e o instalador esconde a pasta do usuario de qualquer jeito.

Os tres imports que o PyInstaller nao ve sozinho
------------------------------------------------
1. **uvicorn**: escolhe loop e protocolo por string em runtime
   (`uvicorn.loops.asyncio`, `uvicorn.protocols.http.h11_impl`). Nenhum aparece
   como `import` no codigo, entao a analise estatica nao os encontra.
2. **app.domain.models**: importado em `main.py` por efeito colateral, para
   registrar as tabelas no metadata do SQLAlchemy.
3. **as migracoes**: `app/db_migrations.py` e importado normalmente -- e foi por
   isso que ele existe em vez de Alembic, que descobre revisao por caminho em
   disco e quebraria aqui.

Templates e static entram como DADOS, nao como modulo: `app/paths.py` os
resolve via `sys._MEIPASS`.
"""

import os

from PyInstaller.utils.hooks import collect_submodules

RAIZ = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(SPEC)), ".."))

ocultos = [
    "app.domain.models",
    "app.db_migrations",
    "app.application.ai.providers.null",
    "app.application.ai.providers.ollama",
    "app.application.ai.providers.openai",
]
ocultos += collect_submodules("uvicorn")

dados = [
    (os.path.join(RAIZ, "app", "templates"), os.path.join("app", "templates")),
    (os.path.join(RAIZ, "app", "static"), os.path.join("app", "static")),
]

# Um cache de KEV embutido faz a primeira execucao funcionar sem rede. Opcional:
# se nao existir, a aplicacao baixa na primeira vez.
kev = os.path.join(RAIZ, "phase0", ".cache", "kev.json")
if os.path.exists(kev):
    dados.append((kev, os.path.join("phase0", ".cache")))

a = Analysis(
    [os.path.join(RAIZ, "launcher.py")],
    pathex=[RAIZ],
    binaries=[],
    datas=dados,
    hiddenimports=ocultos,
    hookspath=[],
    runtime_hooks=[],
    # Nada de tkinter, matplotlib e afins: reduz o pacote e, mais importante,
    # reduz o que um antivirus tem para reclamar.
    excludes=["tkinter", "matplotlib", "numpy", "PIL", "pytest", "setuptools"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="PrideSecurity",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,          # UPX dispara heuristica de antivirus; nao vale os MB
    console=False,      # sem janela preta; ver o tratamento de stdout no launcher
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="PrideSecurity",
)
