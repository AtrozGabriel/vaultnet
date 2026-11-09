"""Inicialização HTTP pelo BAT; preparação offline sem credenciais em comandos."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
import webbrowser
from contextlib import closing, contextmanager
from pathlib import Path

PROJETO = Path(__file__).resolve().parent
SONDAR_PYTHON = (
    "import json,struct,sys,sysconfig; "
    "print(json.dumps({'versao':list(sys.version_info[:2]), "
    "'bits':struct.calcsize('P')*8,'plataforma':sysconfig.get_platform()}))"
)


class SistemaJaAberto(RuntimeError):
    pass


@contextmanager
def instancia_unica(projeto):
    dados = projeto / "dados"
    dados.mkdir(mode=0o700, exist_ok=True)
    with (dados / ".inicializacao.lock").open("a+b") as arquivo:
        if arquivo.seek(0, 2) == 0:
            arquivo.write(b"\0")
            arquivo.flush()
        arquivo.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(arquivo.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                # Permite testar o controle de concorrência no ambiente de QA.
                import fcntl

                fcntl.flock(arquivo, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as erro:
            raise SistemaJaAberto(
                "Já existe uma janela preparando ou executando o sistema. Use essa janela."
            ) from erro
        try:
            yield
        finally:
            arquivo.seek(0)
            if os.name == "nt":
                msvcrt.locking(arquivo.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(arquivo, fcntl.LOCK_UN)


def python_ambiente(projeto):
    return (
        projeto / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    )


def sondar_python(executavel):
    try:
        resultado = subprocess.run(
            [str(executavel), "-I", "-c", SONDAR_PYTHON],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
        )
        info = json.loads(resultado.stdout)
        if (
            info.get("versao") not in ([3, 12], [3, 14])
            or info.get("bits") != 64
            or (os.name == "nt" and info.get("plataforma") != "win-amd64")
        ):
            return None
        return info
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def requisitos_lock(lock):
    blocos = {}
    nome = None
    for linha in lock.read_text(encoding="utf-8").splitlines(keepends=True):
        inicio = re.match(r"^([\w.-]+)==([^\s;\\]+)", linha)
        if inicio:
            nome, versao = inicio.groups()
            if nome in blocos:
                raise ValueError("Dependência duplicada em requirements.lock.")
            blocos[nome] = {"versao": versao, "bloco": linha}
        elif linha.lstrip().startswith("--hash=") and nome:
            blocos[nome]["bloco"] += linha
    if not blocos or any(
        not re.search(r"--hash=sha256:[0-9a-f]{64}", item["bloco"])
        for item in blocos.values()
    ):
        raise ValueError("requirements.lock deve conter versões e hashes válidos.")
    if os.name != "nt":
        blocos.pop("colorama", None)
    return blocos


def inspecionar_pacotes(executavel, requisitos):
    codigo = """
import importlib.metadata as m, json, sys
def versao(nome):
    try:
        return m.version(nome)
    except m.PackageNotFoundError:
        return None
esperados = json.loads(sys.argv[1])
print(json.dumps({
    'pendentes': [n for n,v in esperados.items() if versao(n) != v],
    'pip': versao('pip') is not None,
}))
"""
    esperados = {nome: item["versao"] for nome, item in requisitos.items()}
    resultado = subprocess.run(
        [str(executavel), "-I", "-c", codigo, json.dumps(esperados)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
        shell=False,
    )
    return json.loads(resultado.stdout)


def pacotes_corretos(executavel, lock):
    return not inspecionar_pacotes(executavel, requisitos_lock(lock))["pendentes"]


def preparar_ambiente(projeto, base_python=None):
    lock = projeto / "requirements.lock"
    if not lock.is_file() or not (projeto / "manage.py").is_file():
        raise RuntimeError("Pacote incompleto. Extraia o ZIP inteiro antes de iniciar.")
    base_python = Path(base_python or sys.executable)
    ambiente = projeto / ".venv"
    if ambiente.is_symlink():
        raise RuntimeError(
            "O ambiente virtual não pode ser um link. Extraia o projeto em uma pasta normal."
        )
    executavel = python_ambiente(projeto)
    info = sondar_python(executavel) if executavel.is_file() else None
    if not info:
        if not sondar_python(base_python):
            raise RuntimeError("Use Python 3.14 ou 3.12 de 64 bits para Windows x64.")
        if ambiente.exists():
            if Path(sys.prefix).resolve() == ambiente.resolve():
                raise RuntimeError(
                    "Feche este terminal e recrie o ambiente com uma instalação válida do Python."
                )
            anterior = projeto / f".venv-anterior-{time.time_ns()}"
            ambiente.rename(anterior)
            print(
                "O ambiente anterior foi preservado; preparando um novo...", flush=True
            )
        print("Criando o ambiente Python. Aguarde...", flush=True)
        subprocess.run(
            [str(base_python), "-I", "-m", "venv", str(ambiente)],
            check=True,
            shell=False,
        )
        info = sondar_python(executavel)
        if not info:
            raise RuntimeError("Não foi possível criar um ambiente Python compatível.")
    versao = "".join(str(x) for x in info["versao"])
    plataforma = "windows" if os.name == "nt" else "linux"
    wheels = projeto / "wheels" / f"{plataforma}-py{versao}-x64"
    requisitos = requisitos_lock(lock)
    print("Verificando as dependências instaladas...", flush=True)
    estado = inspecionar_pacotes(executavel, requisitos)
    marca = ambiente / "vaultnet-preparado.json"
    esperado = {"lock_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(), **info}
    try:
        pronto = json.loads(marca.read_text()) == esperado
    except (OSError, ValueError):
        pronto = False
    if not estado["pip"]:
        print("Preparando o pip ausente...", flush=True)
        subprocess.run(
            [str(executavel), "-I", "-m", "ensurepip"],
            check=True,
            shell=False,
        )
    if estado["pendentes"]:
        if not wheels.is_dir():
            raise RuntimeError(
                "As dependências offline estão ausentes. Extraia o ZIP completo."
            )
        print(
            "Instalando somente dependências ausentes ou com versão incompatível: "
            + ", ".join(estado["pendentes"]),
            flush=True,
        )
        with tempfile.TemporaryDirectory(prefix="vaultnet-dependencias-") as temporaria:
            parcial = Path(temporaria) / "pendentes.lock"
            parcial.write_text(
                "".join(requisitos[nome]["bloco"] for nome in estado["pendentes"]),
                encoding="utf-8",
            )
            subprocess.run(
                [
                    str(executavel),
                    "-I",
                    "-m",
                    "pip",
                    "--isolated",
                    "install",
                    "--no-index",
                    "--find-links",
                    str(wheels),
                    "--only-binary=:all:",
                    "--require-hashes",
                    "--no-deps",
                    "-r",
                    str(parcial),
                ],
                check=True,
                shell=False,
            )
        if not pacotes_corretos(executavel, lock):
            raise RuntimeError("As dependências não foram instaladas corretamente.")
    else:
        print("Todas as dependências já estão presentes. Instalação dispensada.")
    subprocess.run(
        [str(executavel), "-I", "-m", "pip", "--isolated", "check"],
        check=True,
        shell=False,
    )
    if not pronto:
        marca.write_text(json.dumps(esperado), encoding="utf-8")
    print("Ambiente pronto.", flush=True)
    return executavel


def oferecer_cadastro_administrador(app):
    with closing(sqlite3.connect(app.database_path)) as db:
        tem_administrador = db.execute(
            "SELECT 1 FROM usuarios WHERE perfil='administrador' LIMIT 1"
        ).fetchone()
    artigo = "outra" if tem_administrador else "uma"
    while True:
        resposta = (
            input(f"Deseja criar {artigo} conta de administrador? (y/n): ")
            .strip()
            .lower()
        )
        if resposta == "n":
            return False
        if resposta == "y":
            break
        print("Digite y para criar ou n para abrir o sistema.", flush=True)

    from app import criar_usuario, validar_nome_usuario, validar_usuario
    from terminal import ler_senha

    while True:
        nome = input("Nome de usuário: ").strip()
        try:
            validar_nome_usuario(nome)
        except ValueError as erro:
            print(str(erro), flush=True)
            continue
        with closing(sqlite3.connect(app.database_path)) as db:
            existe = db.execute(
                "SELECT 1 FROM usuarios WHERE nome=?", (nome,)
            ).fetchone()
        if existe:
            print("Esse nome de usuário já existe. Escolha outro.", flush=True)
            continue
        while True:
            senha = ler_senha("Senha (9 a 128 caracteres): ")
            confirmacao = ler_senha("Repita a senha: ")
            if senha != confirmacao:
                print("As senhas não coincidem. Tente novamente.", flush=True)
                continue
            try:
                validar_usuario(nome, senha, "administrador")
            except ValueError as erro:
                print(str(erro), flush=True)
                continue
            break
        try:
            criar_usuario(app, nome, senha, "administrador")
        except sqlite3.IntegrityError:
            # Outro comando local pode ter cadastrado esse nome durante a entrada.
            with closing(sqlite3.connect(app.database_path)) as db:
                existe = db.execute(
                    "SELECT 1 FROM usuarios WHERE nome=?", (nome,)
                ).fetchone()
            if not existe:
                raise
            print("Esse nome de usuário já existe. Escolha outro.", flush=True)
            continue
        print(
            f"Conta {nome} criada. O autenticador será configurado no primeiro login.",
            flush=True,
        )
        return True


def abrir_http(endereco):
    print(
        "Abrindo o navegador. Entre com seu usuário, senha e segundo fator.", flush=True
    )
    try:
        if not webbrowser.open(endereco + "/login", new=2):
            print("Abra este endereço no navegador: " + endereco + "/login", flush=True)
    except OSError:
        print("Abra este endereço no navegador: " + endereco + "/login", flush=True)


def executar_sistema(projeto, cloudflare=False):
    # O BAT usa -I; importações locais são autorizadas somente nesta pasta.
    sys.path.insert(0, str(projeto))
    from app import create_app
    from servidor import servir_http

    app = create_app({"DATA_DIR": str(projeto / "dados")})
    oferecer_cadastro_administrador(app)
    if cloudflare:
        def ao_iniciar(endereco):
            print("\nENDERECO FIXO: https://www.vaultnet.site/login", flush=True)
            print("O servico Cloudflared do Windows precisa estar em execucao.", flush=True)
            from acesso_rede import carregar
            import sqlite3
            with sqlite3.connect(app.database_path) as db:
                modo = carregar(db)["modo"]
            abrir_http("https://www.vaultnet.site" if modo == "internet" else endereco)

        servir_http(
            app, host="127.0.0.1", ao_iniciar=ao_iniciar, proxy_cloudflare=True
        )
    else:
        servir_http(app, ao_iniciar=abrir_http)


def main():
    parser = argparse.ArgumentParser(
        description="Inicialização automática pelo INICIAR.bat"
    )
    etapas = parser.add_mutually_exclusive_group(required=True)
    etapas.add_argument("--preparar", action="store_true")
    etapas.add_argument("--executar", action="store_true")
    parser.add_argument("--cloudflare", action="store_true")
    args = parser.parse_args()
    if os.name != "nt":
        print("INICIAR.bat é destinado ao Windows. No Linux, siga o README.")
        return 1
    try:
        with instancia_unica(PROJETO):
            if args.preparar:
                preparar_ambiente(PROJETO)
            else:
                executar_sistema(PROJETO, cloudflare=True) if args.cloudflare else executar_sistema(PROJETO)
        return 0
    except SistemaJaAberto as erro:
        print(str(erro), flush=True)
        return 3
    except (KeyboardInterrupt, EOFError):
        print("\nOperação encerrada.", flush=True)
        return 4 if args.preparar else 0
    except (
        OSError,
        RuntimeError,
        ValueError,
        sqlite3.Error,
        subprocess.SubprocessError,
    ) as erro:
        print("Não foi possível concluir: " + str(erro), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
