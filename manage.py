"""Comandos administrativos executados no próprio servidor."""

import argparse
import unicodedata
import ipaddress
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path

from antivirus import ErroAntivirus, analisar_arquivo
from app import HASHER, PERFIS, create_app, criar_usuario, validar_nome_usuario
from servidor import servir_http, validar_host
from terminal import ler_senha


def main():
    parser = argparse.ArgumentParser(
        description="VaultNet · Arquivos e login com dois fatores"
    )
    parser.add_argument(
        "--dados",
        default=str(Path(__file__).parent / "dados"),
        help="Diretório do banco e da chave",
    )
    comandos = parser.add_subparsers(dest="comando", required=True)
    criar = comandos.add_parser("criar-usuario")
    criar.add_argument("nome", nargs="?", help="Se omitido, o terminal solicita o nome")
    criar.add_argument("--perfil", choices=PERFIS, default="atendente")
    executar = comandos.add_parser("executar")
    executar.add_argument("--porta", type=int, default=8080)
    executar.add_argument(
        "--rede-local",
        action="store_true",
        help="Escutar na LAN; sem --subrede permite qualquer IP",
    )
    executar.add_argument(
        "--subrede", action="append", help="CIDR autorizado, ex.: 192.168.1.0/24"
    )
    executar.add_argument(
        "--host-login",
        default="login.interno",
        help="Nome DNS ou IPv4 usado pelos clientes na LAN",
    )
    executar.add_argument(
        "--antivirus",
        help="Caminho do clamscan ou MpCmdRun.exe; no Windows o Defender é localizado automaticamente",
    )
    executar.add_argument(
        "--scanner",
        choices=("auto", "defender", "clamav", "nenhum"),
        default="auto",
        help="auto detecta Microsoft Defender no Windows; nenhum mantém os envios bloqueados",
    )
    executar.add_argument(
        "--demo-sem-antivirus",
        action="store_true",
        help="Permitir envios somente na demonstração em loopback",
    )
    executar.add_argument(
        "--cota-mb",
        type=int,
        default=1024,
        help="Cota total de documentos cifrados, incluindo a lixeira",
    )
    resetar = comandos.add_parser("redefinir-2fa")
    resetar.add_argument("nome")
    desativar = comandos.add_parser("desativar-usuario")
    desativar.add_argument("nome")
    senha_comando = comandos.add_parser("redefinir-senha")
    senha_comando.add_argument("nome")
    renomear = comandos.add_parser("renomear-usuario")
    renomear.add_argument(
        "nome", help="Nome atual da conta; o novo nome será solicitado"
    )
    verificar = comandos.add_parser(
        "verificar-antivirus",
        help="Testar o scanner local com um arquivo de texto inofensivo",
    )
    verificar.add_argument(
        "--scanner", choices=("auto", "defender", "clamav"), default="auto"
    )
    verificar.add_argument("--antivirus", help="Caminho do clamscan ou MpCmdRun.exe")
    args = parser.parse_args()
    config = {"DATA_DIR": args.dados}
    if args.comando == "verificar-antivirus":
        config.update(SCANNER_TYPE=args.scanner, SCANNER_PATH=args.antivirus)
    if args.comando == "executar":
        if args.rede_local and args.demo_sem_antivirus:
            parser.error("O modo sem antivírus não pode ser usado na rede local.")
        if args.cota_mb < 10:
            parser.error("A cota precisa ser de pelo menos 10 MB.")
        if not 1 <= args.porta <= 65535:
            parser.error("Porta inválida.")
        if args.subrede and not args.rede_local:
            parser.error("Use --rede-local junto com --subrede.")
        try:
            args.host_login = (
                validar_host(args.host_login) if args.rede_local else "127.0.0.1"
            )
        except ValueError as erro:
            parser.error(str(erro))
        config["TRUSTED_HOSTS"] = None
        if args.demo_sem_antivirus:
            config["ALLOWED_NETWORKS"] = ["127.0.0.0/8", "::1/128"]
        config.update(
            SCANNER_PATH=args.antivirus,
            SCANNER_TYPE=args.scanner,
            ALLOW_UNSCANNED_UPLOADS=args.demo_sem_antivirus,
            STORAGE_QUOTA=args.cota_mb * 1024 * 1024,
        )
    if args.comando == "executar" and args.rede_local:
        try:
            for rede in args.subrede or []:
                ipaddress.ip_network(rede, strict=False)
        except ValueError as erro:
            parser.error(str(erro))
        config.update(
            ALLOWED_NETWORKS=(
                ["127.0.0.0/8", "::1/128", *args.subrede]
                if args.subrede else ["0.0.0.0/0", "::/0"]
            ),
        )
    try:
        app = create_app(config)
        if args.comando == "executar":
            nomes_scanner = {
                "defender": "Microsoft Defender",
                "clamav": "ClamAV",
                "nenhum": "nenhum; envios bloqueados",
            }
            print(
                "Antivírus: "
                + (
                    "demonstração sem análise"
                    if args.demo_sem_antivirus
                    else nomes_scanner[app.config["SCANNER_ENGINE"]]
                )
            )
        if args.comando == "verificar-antivirus":
            if not app.config["SCANNER_PATH"]:
                raise ValueError(
                    "Nenhum antivírus foi localizado. Configure o Defender no Windows ou informe o clamscan."
                )
            dados_teste = b"VaultNet: arquivo de texto inofensivo para testar o antivirus local.\n"
            with tempfile.TemporaryDirectory(
                prefix="verificacao-antivirus-", dir=app.config["DATA_DIR"]
            ) as temporario:
                caminho = Path(temporario) / "teste.txt"
                caminho.write_bytes(dados_teste)
                engine = analisar_arquivo(caminho, dados_teste, app.config)
            print(
                f"Verificação concluída: {engine}. O scanner aprovou o arquivo de teste."
            )
        elif args.comando == "criar-usuario":
            nome = unicodedata.normalize("NFC", (args.nome or input("Nome de usuário: ")).strip())
            validar_nome_usuario(nome)
            print(f"Criando a conta {nome}.")
            senha = ler_senha("Senha (9 a 128 caracteres): ")
            if senha != ler_senha("Repita a senha: "):
                parser.error("As senhas não coincidem.")
            criar_usuario(app, nome, senha, args.perfil)
            print(
                f"Usuário {nome} criado. Configure o autenticador no primeiro acesso, com acompanhamento do responsável."
            )
        elif args.comando in {
            "redefinir-2fa",
            "desativar-usuario",
            "redefinir-senha",
            "renomear-usuario",
        }:
            nome = unicodedata.normalize("NFC", args.nome.strip()).casefold()
            if (
                input(
                    "Confirme a identidade do titular e digite novamente o nome do usuário: "
                )
                .strip()
                .casefold()
                != nome
            ):
                parser.error("Confirmação incorreta.")
            senha_hash = None
            novo_nome = None
            if args.comando == "redefinir-senha":
                nova_senha = ler_senha("Nova senha (9 a 128 caracteres): ")
                if not 9 <= len(nova_senha) <= 128 or nova_senha != ler_senha(
                    "Repita a nova senha: "
                ):
                    parser.error("Use de 9 a 128 caracteres e repita a mesma senha.")
                senha_hash = HASHER.hash(nova_senha)
            elif args.comando == "renomear-usuario":
                novo_nome = unicodedata.normalize("NFC", input("Novo nome de usuário: ").strip())
                validar_nome_usuario(novo_nome)
            with closing(sqlite3.connect(app.database_path)) as db, db:
                db.execute("PRAGMA foreign_keys=ON")
                db.create_function("texto_busca", 1, lambda texto: unicodedata.normalize("NFC", texto).casefold(), deterministic=True)
                db.execute("BEGIN IMMEDIATE")
                usuario = db.execute(
                    "SELECT id,perfil,ativo FROM usuarios WHERE texto_busca(nome)=texto_busca(?)", (nome,)
                ).fetchone()
                if not usuario:
                    parser.error("Usuário não encontrado.")
                uid = usuario[0]
                if (
                    args.comando == "desativar-usuario"
                    and usuario[1] == "administrador"
                    and usuario[2]
                    and db.execute(
                        "SELECT count(*) FROM usuarios WHERE ativo=1 AND perfil='administrador'"
                    ).fetchone()[0]
                    <= 1
                ):
                    parser.error(
                        "Mantenha pelo menos um administrador ativo. Crie outro antes de desativar esta conta."
                    )
                db.execute("DELETE FROM sessoes WHERE usuario_id=?", (uid,))
                if args.comando == "redefinir-2fa":
                    db.execute("DELETE FROM recuperacao WHERE usuario_id=?", (uid,))
                    db.execute(
                        "UPDATE usuarios SET segredo_2fa=NULL,ultimo_passo=-1,falhas=0,bloqueado_ate=0 WHERE id=?",
                        (uid,),
                    )
                elif args.comando == "desativar-usuario":
                    db.execute("UPDATE usuarios SET ativo=0 WHERE id=?", (uid,))
                elif args.comando == "renomear-usuario":
                    if db.execute("SELECT 1 FROM usuarios WHERE texto_busca(nome)=texto_busca(?) AND id<>?", (novo_nome, uid)).fetchone():
                        parser.error("Este nome de usuário já está em uso.")
                    db.execute(
                        "UPDATE usuarios SET nome=? WHERE id=?", (novo_nome, uid)
                    )
                else:
                    db.execute(
                        "UPDATE usuarios SET senha_hash=?,falhas=0,bloqueado_ate=0 WHERE id=?",
                        (senha_hash, uid),
                    )
                db.execute(
                    "INSERT INTO auditoria(momento,usuario_id,evento,ip) VALUES(?,?,?,?)",
                    (
                        app.config["CLOCK"](),
                        uid,
                        args.comando + "_console",
                        "console-local",
                    ),
                )
            print("Operação concluída; as sessões anteriores foram invalidadas.")
        else:
            servir_http(
                app,
                porta=args.porta,
                host="0.0.0.0" if args.rede_local else "127.0.0.1",  # nosec B104: acesso pela rede solicitado explicitamente.
                host_login=args.host_login,
            )
    except (
        ValueError,
        RuntimeError,
        OSError,
        sqlite3.IntegrityError,
        ErroAntivirus,
    ) as erro:
        parser.error(
            "Nome já cadastrado."
            if isinstance(erro, sqlite3.IntegrityError)
            else str(erro)
        )
    except (KeyboardInterrupt, EOFError):
        print("\nOperação encerrada.")


if __name__ == "__main__":
    main()
