"""
Constroi o executavel e, se o Inno Setup existir, o instalador.

Existe como script e nao como linha no README porque build feito a mao erra
calado: esquecer de rodar a suite antes, empacotar com o `dist/` velho, ou
construir a partir de uma arvore suja. As tres coisas produzem um `.exe` que
parece certo.

    python packaging/build.py             # suite, .exe e instalador
    python packaging/build.py --sem-teste # so quando a suite ja rodou agora

PyInstaller e Inno Setup NAO sao dependencias do produto -- so de quem empacota.
O `requirements.txt` continua com os mesmos 5 pins, e a aplicacao roda sem
nenhum dos dois.
"""

import argparse
import os
import shutil
import subprocess
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC = os.path.join(RAIZ, "packaging", "pride-security.spec")
ISS = os.path.join(RAIZ, "packaging", "pride-security.iss")
DIST = os.path.join(RAIZ, "dist")

ISCC_CANDIDATOS = [
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "Inno Setup 6", "ISCC.exe"),
    r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    r"C:\Program Files\Inno Setup 6\ISCC.exe",
]


def passo(titulo):
    print(f"\n{'=' * 62}\n{titulo}\n{'=' * 62}")


def rodar(cmd, **kw):
    print("$", " ".join(str(c) for c in cmd))
    r = subprocess.run(cmd, cwd=RAIZ, **kw)
    if r.returncode != 0:
        sys.exit(f"\nFALHOU: {cmd[0]} devolveu {r.returncode}")
    return r


def achar_iscc():
    for c in ISCC_CANDIDATOS:
        if c and os.path.exists(c):
            return c
    return shutil.which("iscc")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sem-teste", action="store_true",
                    help="pula a suite; use so se ela acabou de passar")
    ap.add_argument("--sem-instalador", action="store_true")
    args = ap.parse_args()

    if not args.sem_teste:
        passo("1. Suite")
        # Antes de empacotar, nao depois: um .exe construido sobre suite
        # vermelha e um defeito distribuido.
        rodar([sys.executable, "tests/run.py", "-q"])

    passo("2. Executavel (PyInstaller, onedir)")
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        sys.exit("PyInstaller nao instalado:  pip install pyinstaller\n"
                 "(nao e dependencia do produto, so de quem empacota)")

    # `dist/PrideSecurity` inteiro, para nao sobrar arquivo de uma versao velha
    # dentro do pacote -- o modo de falha que produz um .exe com codigo antigo.
    alvo = os.path.join(DIST, "PrideSecurity")
    if os.path.isdir(alvo):
        shutil.rmtree(alvo, ignore_errors=True)

    rodar([sys.executable, "-m", "PyInstaller", SPEC, "--noconfirm",
           "--distpath", DIST])

    exe = os.path.join(alvo, "PrideSecurity.exe")
    if not os.path.exists(exe):
        sys.exit("o executavel nao apareceu em dist/")
    print(f"\n  {exe}  ({os.path.getsize(exe) / 1048576:.1f} MB)")

    if args.sem_instalador:
        return 0

    passo("3. Instalador (Inno Setup)")
    iscc = achar_iscc()
    if not iscc:
        print("Inno Setup nao encontrado. O .exe em dist/PrideSecurity ja funciona;")
        print("para gerar o instalador:  winget install JRSoftware.InnoSetup")
        return 0

    rodar([iscc, ISS])
    saida = os.path.join(DIST, "installer")
    if os.path.isdir(saida):
        for nome in sorted(os.listdir(saida)):
            caminho = os.path.join(saida, nome)
            print(f"\n  {caminho}  ({os.path.getsize(caminho) / 1048576:.1f} MB)")

    print("\nO instalador NAO esta assinado: o SmartScreen vai avisar em toda")
    print("instalacao, e a reputacao zera a cada versao. Nao ha contorno")
    print("tecnico -- so certificado de assinatura de codigo.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
