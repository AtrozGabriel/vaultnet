"""Entrada de senhas com feedback visual, sem exibir o conteúdo digitado."""

import getpass
import os
import sys
import warnings


def _ler_mascarado(ler, escrever):
    caracteres = []
    while True:
        caractere = ler()
        if not caractere:
            raise EOFError("Entrada encerrada.")
        if caractere in ("\r", "\n"):
            escrever("\n")
            return "".join(caracteres)
        if caractere == "\x03":
            raise KeyboardInterrupt
        if caractere in ("\b", "\x7f"):
            if caracteres:
                caracteres.pop()
                escrever("\b \b")
        elif caractere == "\x15":
            escrever("\b \b" * len(caracteres))
            caracteres.clear()
        elif caractere.isprintable():
            caracteres.append(caractere)
            escrever("*")


def ler_senha(mensagem):
    """Recusa redirecionamentos e qualquer fallback que exponha a senha."""
    if not sys.stdin.isatty():
        raise ValueError("Digite a senha em um terminal interativo, como o PowerShell.")
    if sys.version_info >= (3, 14):
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            try:
                return getpass.getpass(mensagem, echo_char="*")
            except getpass.GetPassWarning:
                raise ValueError(
                    "Este terminal não permite proteger a senha. Abra o PowerShell diretamente."
                ) from None
    if os.name == "nt":
        import msvcrt

        def ler():
            caractere = msvcrt.getwch()
            if caractere in ("\x00", "\xe0"):
                msvcrt.getwch()
                return "\x00"
            return caractere

        def escrever(texto):
            for caractere in texto:
                msvcrt.putwch(caractere)

        escrever(mensagem)
        return _ler_mascarado(ler, escrever)

    import termios

    descritor = sys.stdin.fileno()
    anterior = termios.tcgetattr(descritor)
    configuracao = termios.tcgetattr(descritor)
    configuracao[3] &= ~(termios.ECHO | termios.ECHONL | termios.ICANON)
    configuracao[6][termios.VMIN] = 1
    configuracao[6][termios.VTIME] = 0

    def escrever(texto):
        sys.stderr.write(texto)
        sys.stderr.flush()

    try:
        termios.tcsetattr(descritor, termios.TCSADRAIN, configuracao)
        escrever(mensagem)
        return _ler_mascarado(lambda: sys.stdin.read(1), escrever)
    finally:
        termios.tcsetattr(descritor, termios.TCSADRAIN, anterior)
