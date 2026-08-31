"""
Pride Security Desktop — o ponto de entrada do executavel.

O que um aplicativo precisa e um servidor nao
---------------------------------------------
`python -m uvicorn app.main:app` e um comando; um aplicativo instalado precisa
resolver quatro coisas que ninguem digita:

1. **Achar porta livre.** Porta fixa colide com qualquer outra coisa na 8000, e
   o usuario nao tem como saber o que aconteceu. Pedimos 8000 e caimos para uma
   porta livre se ela estiver ocupada.
2. **Escutar so em loopback.** `0.0.0.0` publicaria dado de seguranca sem
   autenticacao para a rede local. Nao ha opcao para mudar isso: a ausencia de
   autenticacao e um fato do produto (L4), entao a interface nao pode ficar
   exposta.
3. **Abrir o navegador**, depois que o servidor responde -- nao antes, senao o
   usuario ve erro de conexao no primeiro segundo.
4. **Nao abrir console.** Empacotado com `--windowed`, `sys.stdout` e `None`, e
   qualquer `print` de biblioteca vira `AttributeError`. Por isso os fluxos sao
   substituidos logo no inicio, antes de importar qualquer coisa.

Instancia unica
---------------
Clicar duas vezes no icone nao pode subir dois servidores sobre o mesmo SQLite.
Um arquivo de trava em `%LOCALAPPDATA%` guarda a porta viva: a segunda instancia
so abre o navegador na porta da primeira e sai.

Diagnostico
-----------
Sem console, um erro no boot seria um icone que pisca e some. Toda excecao vai
para `%LOCALAPPDATA%\\PrideSecurity\\logs\\launcher.log` e vira uma caixa de
mensagem do Windows dizendo onde olhar.
"""

import os
import socket
import sys
import threading
import time
import traceback
import webbrowser

# ANTES de qualquer import que possa escrever. Sob `--windowed` os tres fluxos
# padrao sao None, e uma linha de log de biblioteca derruba o processo.
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")
if sys.stdin is None:
    sys.stdin = open(os.devnull, "r")

HOST = "127.0.0.1"
PORTA_PREFERIDA = 8000
NOME = "Pride Security"


def _paths():
    from app import paths
    return paths


def porta_livre(preferida=PORTA_PREFERIDA):
    """A preferida, se der; senao uma qualquer que o sistema escolha."""
    for porta in (preferida, 0):
        try:
            with socket.socket() as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((HOST, porta))
                return s.getsockname()[1]
        except OSError:
            continue
    raise RuntimeError("nenhuma porta disponivel em 127.0.0.1")


def _arquivo_de_trava():
    return _paths().dados("running.port")


def instancia_viva():
    """Ha outra instancia respondendo? Devolve a porta dela, ou None.

    Testa de verdade em vez de confiar no arquivo: trava orfa depois de um
    desligamento sujo e o caso comum, e um aplicativo que se recusa a abrir
    porque nao limpou um arquivo e pior que um aplicativo aberto duas vezes.
    """
    try:
        with open(_arquivo_de_trava(), encoding="utf-8") as f:
            porta = int(f.read().strip())
    except (OSError, ValueError):
        return None
    try:
        with socket.create_connection((HOST, porta), timeout=1.5):
            return porta
    except OSError:
        return None


def marcar_instancia(porta):
    try:
        with open(_arquivo_de_trava(), "w", encoding="utf-8") as f:
            f.write(str(porta))
    except OSError:
        pass


def limpar_instancia():
    try:
        os.unlink(_arquivo_de_trava())
    except OSError:
        pass


def esperar_e_abrir(porta, timeout=40.0):
    """Abre o navegador so depois que o servidor aceita conexao."""
    url = f"http://{HOST}:{porta}/aspm"
    limite = time.time() + timeout
    while time.time() < limite:
        try:
            with socket.create_connection((HOST, porta), timeout=1):
                break
        except OSError:
            time.sleep(0.2)
    else:
        return
    try:
        webbrowser.open(url)
    except Exception:
        pass


def _registrar_falha(exc):
    """Log em arquivo mais caixa de mensagem. Sem console, e a unica pista."""
    try:
        destino = _paths().dados("logs", "launcher.log")
    except Exception:
        destino = os.path.join(os.path.expanduser("~"), "pride-security-erro.log")
    try:
        with open(destino, "a", encoding="utf-8") as f:
            f.write(f"\n=== {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
            f.write("".join(traceback.format_exception(exc)))
    except OSError:
        pass

    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(
                None,
                f"{NOME} nao conseguiu iniciar.\n\n{type(exc).__name__}: {exc}\n\n"
                f"Detalhes em:\n{destino}",
                NOME, 0x10)
        except Exception:
            pass
    return destino


def main():
    porta_existente = instancia_viva()
    if porta_existente:
        # Ja esta rodando: so traz a janela de volta.
        try:
            webbrowser.open(f"http://{HOST}:{porta_existente}/aspm")
        except Exception:
            pass
        return 0

    porta = porta_livre()
    marcar_instancia(porta)

    threading.Thread(target=esperar_e_abrir, args=(porta,), daemon=True).start()

    import uvicorn

    from app.main import app  # noqa: F401  (importa aqui para o log pegar falha de boot)

    try:
        uvicorn.run(
            "app.main:app",
            host=HOST, port=porta,
            log_level="warning",
            # `reload` e `workers` ficam de fora de proposito: os dois criam
            # subprocessos, e subprocesso dentro de executavel congelado
            # reexecuta o proprio .exe, abrindo instancias em cascata.
            access_log=False,
        )
    finally:
        limpar_instancia()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException as exc:  # inclusive KeyboardInterrupt no modo console
        limpar_instancia()
        _registrar_falha(exc)
        sys.exit(1)
