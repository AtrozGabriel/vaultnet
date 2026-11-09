"""Autenticação local com senha, TOTP e sessões no servidor."""

from __future__ import annotations

import hashlib
import io
import ipaddress
import os
import re
import secrets
import sqlite3
import struct
import zlib
import time
import unicodedata
from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import pyotp
import qrcode
import qrcode.image.svg
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerificationError
from cryptography.fernet import Fernet, InvalidToken
from flask import (
    Flask,
    Response,
    abort,
    g,
    redirect,
    render_template,
    request,
    url_for,
)
from werkzeug.exceptions import RequestEntityTooLarge, SecurityError

PERFIS = {
    "atendente": {"ler", "enviar"},
    "supervisor": {"ler", "enviar", "editar"},
    "administrador": {"ler", "enviar", "editar", "excluir", "administrar"},
}
HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1, type=Type.ID)
COOKIE = "vaultnet_http"
ERRO_LOGIN = (
    "Não foi possível entrar. Confira os dados ou aguarde antes de tentar novamente."
)
ERRO_OTP = "Código inválido, já utilizado ou tentativa temporariamente bloqueada."
SCHEMA = """
CREATE TABLE IF NOT EXISTS usuarios (
 id INTEGER PRIMARY KEY, nome TEXT NOT NULL UNIQUE,
 senha_hash TEXT NOT NULL, perfil TEXT NOT NULL
 CHECK(perfil IN ('atendente','supervisor','administrador')),
 ativo INTEGER NOT NULL DEFAULT 1, segredo_2fa TEXT,
 ultimo_passo INTEGER NOT NULL DEFAULT -1,
 falhas INTEGER NOT NULL DEFAULT 0, bloqueado_ate REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessoes (
 token_hash TEXT PRIMARY KEY, usuario_id INTEGER REFERENCES usuarios(id),
 etapa TEXT NOT NULL CHECK(etapa IN ('anonima','configuracao','pendente','autenticada')),
 csrf TEXT NOT NULL, criado REAL NOT NULL, expira REAL NOT NULL,
 ultimo_acesso REAL NOT NULL, mfa_em REAL,
 segredo_inicial TEXT, codigos_iniciais TEXT
);
CREATE TABLE IF NOT EXISTS recuperacao (
 usuario_id INTEGER NOT NULL REFERENCES usuarios(id),
 codigo_hash TEXT NOT NULL, PRIMARY KEY(usuario_id,codigo_hash)
);
CREATE TABLE IF NOT EXISTS auditoria (
 id INTEGER PRIMARY KEY, momento REAL NOT NULL,
 usuario_id INTEGER REFERENCES usuarios(id), evento TEXT NOT NULL, ip TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS limite_ip (
 ip TEXT PRIMARY KEY, inicio REAL NOT NULL, quantidade INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS limite_paginas (
 ip TEXT PRIMARY KEY, inicio REAL NOT NULL, quantidade INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS configuracoes (
 chave TEXT PRIMARY KEY, valor TEXT NOT NULL
);
"""


def digest(texto):
    return hashlib.sha256(texto.encode("utf-8")).hexdigest()


def agora():
    return g.app_clock()


def banco():
    if "db" not in g:
        g.db = sqlite3.connect(g.database_path, timeout=10, isolation_level=None)
        g.db.row_factory = sqlite3.Row
        g.db.create_function(
            "texto_busca",
            1,
            lambda texto: unicodedata.normalize("NFC", texto).casefold(),
            deterministic=True,
        )
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@contextmanager
def transacao():
    db = banco()
    db.execute("BEGIN IMMEDIATE")
    try:
        yield db
    except BaseException:
        db.rollback()
        raise
    else:
        db.commit()


def registrar(evento, usuario_id=None):
    banco().execute(
        "INSERT INTO auditoria(momento,usuario_id,evento,ip) VALUES(?,?,?,?)",
        (agora(), usuario_id, evento, request.remote_addr or "desconhecido"),
    )


def criar_sessao(etapa, usuario_id=None, segredo=None, codigos=None):
    """A rotação também invalida a sessão anterior no banco."""
    if g.sessao:
        banco().execute(
            "DELETE FROM sessoes WHERE token_hash=?", (g.sessao["token_hash"],)
        )
    token = secrets.token_urlsafe(32)
    prazo = 8 * 3600 if etapa == "autenticada" else (900 if etapa == "anonima" else 300)
    banco().execute(
        """INSERT INTO sessoes(token_hash,usuario_id,etapa,csrf,criado,expira,
        ultimo_acesso,mfa_em,segredo_inicial,codigos_iniciais) VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (
            digest(token),
            usuario_id,
            etapa,
            secrets.token_urlsafe(32),
            agora(),
            agora() + prazo,
            agora(),
            agora() if etapa == "autenticada" else None,
            segredo,
            codigos,
        ),
    )
    g.sessao = (
        banco()
        .execute("SELECT * FROM sessoes WHERE token_hash=?", (digest(token),))
        .fetchone()
    )
    g.novo_token = token


def exigir_csrf():
    recebido = request.form.get("csrf", "")
    if (
        not g.sessao
        or len(recebido) > 100
        or not secrets.compare_digest(recebido.encode(), g.sessao["csrf"].encode())
    ):
        abort(400, description="A página expirou. Atualize a página e tente novamente.")


def pagina(tipo, **dados):
    return render_template("pagina.html", tipo=tipo, **dados)


def revalidar(etapas=("autenticada",), permissao=None):
    """Releia o acesso dentro da transação: revogação e mudança de perfil têm efeito imediato."""
    sessao = (
        banco()
        .execute(
            "SELECT * FROM sessoes WHERE token_hash=?",
            (g.sessao["token_hash"] if g.sessao else "",),
        )
        .fetchone()
    )
    usuario = (
        banco()
        .execute("SELECT * FROM usuarios WHERE id=?", (sessao["usuario_id"],))
        .fetchone()
        if sessao
        else None
    )
    if (
        not sessao
        or sessao["etapa"] not in etapas
        or sessao["expira"] <= agora()
        or sessao["ultimo_acesso"] + 900 <= agora()
        or not usuario
        or not usuario["ativo"]
        or (
            sessao["etapa"] in {"pendente", "autenticada"}
            and not usuario["segredo_2fa"]
        )
    ):
        abort(401, description="Seu acesso expirou. Entre novamente.")
    g.sessao, g.usuario = sessao, usuario
    if permissao and permissao not in PERFIS[usuario["perfil"]]:
        abort(403, description="Seu perfil não permite esta operação.")
    return usuario


def exigir_confirmacao_recente():
    if not g.sessao["mfa_em"] or g.sessao["mfa_em"] + 300 < agora():
        abort(
            403,
            description="Confirme sua senha e o segundo fator na página Confirmar acesso antes desta operação.",
        )


def verificar_senha(usuario, senha):
    try:
        return len(senha) <= 128 and HASHER.verify(usuario["senha_hash"], senha)
    except VerificationError:
        return False


def protegido(permissao=None):
    def decorar(fn):
        @wraps(fn)
        def executar(*args, **kwargs):
            if not g.sessao or g.sessao["etapa"] != "autenticada" or not g.usuario:
                return redirect(url_for("login"))
            if permissao and permissao not in PERFIS[g.usuario["perfil"]]:
                registrar("permissao_negada", g.usuario["id"])
                abort(403, description="Seu perfil não tem acesso a esta área.")
            return fn(*args, **kwargs)

        return executar

    return decorar


def falha(usuario):
    if not usuario:
        registrar("login_recusado")
        return
    quantidade = usuario["falhas"] + 1
    bloqueio = agora() + 300 if quantidade >= 5 else usuario["bloqueado_ate"]
    banco().execute(
        "UPDATE usuarios SET falhas=?,bloqueado_ate=? WHERE id=?",
        (0 if quantidade >= 5 else quantidade, bloqueio, usuario["id"]),
    )
    registrar(
        "bloqueio_temporario" if quantidade >= 5 else "login_recusado", usuario["id"]
    )


def passo_totp(segredo, codigo, ultimo=-1):
    if not re.fullmatch(r"[0-9]{6}", codigo):
        return None
    atual = int(agora()) // 30
    totp = pyotp.TOTP(segredo, interval=30, digits=6)
    for passo in (atual, atual - 1, atual + 1):
        if passo > ultimo and secrets.compare_digest(totp.at(passo * 30), codigo):
            return passo
    return None


def create_app(config=None):
    app = Flask(__name__)
    app.config.update(
        DATA_DIR=str(Path(__file__).parent / "dados"),
        ALLOWED_NETWORKS=["0.0.0.0/0", "::/0"],
        TRUSTED_HOSTS=None,
        PREFERRED_URL_SCHEME="http",
        MAX_CONTENT_LENGTH=16 * 1024,
        # O parser lê blocos de 64 KiB e pode guardar o fim de um bloco para
        # reconhecer a próxima fronteira. O teto precisa comportar ambos.
        MAX_FORM_MEMORY_SIZE=128 * 1024,
        MAX_FORM_PARTS=12,
        MAX_FILE_SIZE=10 * 1024 * 1024,
        STORAGE_QUOTA=1024 * 1024 * 1024,
        SCANNER_PATH=None,
        SCANNER_TYPE="auto",
        SCANNER_ENGINE="clamav",
        DEFENDER_POWERSHELL=None,
        ALLOW_UNSCANNED_UPLOADS=False,
        DISPLAY_OFFSET_HOURS=-3,
        CLOCK=time.time,
    )
    if config:
        app.config.update(config)
    pasta = Path(app.config["DATA_DIR"]).expanduser().resolve()
    if app.static_folder and pasta.is_relative_to(Path(app.static_folder).resolve()):
        raise ValueError(
            "A pasta de dados não pode ficar dentro de static, onde os arquivos são públicos. "
            "Use uma pasta privada, como dados."
        )
    app.config["DATA_DIR"] = str(pasta)
    pasta.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(pasta, 0o700)
    chave = pasta / "chave_2fa.key"
    if not chave.exists():
        if (pasta / "login.sqlite3").exists():
            raise RuntimeError(
                "A chave do segundo fator está ausente. Restaure o backup da chave antes de iniciar."
            )
        try:
            with os.fdopen(
                os.open(chave, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
            ) as arquivo:
                arquivo.write(Fernet.generate_key())
        except FileExistsError:
            pass
    os.chmod(chave, 0o600)
    app.fernet = Fernet(chave.read_bytes())
    app.database_path = str(pasta / "login.sqlite3")
    with closing(sqlite3.connect(app.database_path)) as db, db:
        db.executescript(SCHEMA)
        db.executescript("""
            CREATE TABLE IF NOT EXISTS solicitacoes_nome (
                id INTEGER PRIMARY KEY, usuario_id INTEGER NOT NULL REFERENCES usuarios(id),
                nome_anterior TEXT NOT NULL, nome_novo TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pendente' CHECK(status IN ('pendente','aprovada','rejeitada')),
                criado REAL NOT NULL, decidido REAL, administrador_id INTEGER REFERENCES usuarios(id)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS nome_pendente_por_usuario
                ON solicitacoes_nome(usuario_id) WHERE status='pendente';
        """)
        if "setor" not in {row[1] for row in db.execute("PRAGMA table_info(usuarios)")}:
            db.execute("ALTER TABLE usuarios ADD COLUMN setor TEXT NOT NULL DEFAULT ''")
        if "foto" not in {row[1] for row in db.execute("PRAGMA table_info(usuarios)")}:
            db.execute("ALTER TABLE usuarios ADD COLUMN foto BLOB")
        db.execute("PRAGMA journal_mode=WAL")
        # Ao migrar uma cópia antiga do banco, contas e fatores são preservados,
        # mas sessões anteriores não atravessam a mudança de protocolo.
        db.execute("BEGIN IMMEDIATE")
        protocolo = db.execute(
            "SELECT valor FROM configuracoes WHERE chave='protocolo'"
        ).fetchone()
        if not protocolo or protocolo[0] != "http":
            db.execute("DELETE FROM sessoes")
            db.execute(
                "INSERT OR REPLACE INTO configuracoes(chave,valor) VALUES('protocolo','http')"
            )
    os.chmod(app.database_path, 0o600)
    app.dummy_hash = HASHER.hash(secrets.token_urlsafe(24))
    redes = [
        ipaddress.ip_network(x, strict=False) for x in app.config["ALLOWED_NETWORKS"]
    ]
    rede_externa_ao_loopback = any(
        not rede.network_address.is_loopback or not rede.broadcast_address.is_loopback
        for rede in redes
    )
    if app.config["ALLOW_UNSCANNED_UPLOADS"] and rede_externa_ao_loopback:
        raise ValueError(
            "O modo de envio sem antivírus é permitido somente na demonstração em loopback."
        )
    app.config["COOKIE_NAME"] = COOKIE

    @app.before_request
    def preparar():
        g.app_clock = app.config["CLOCK"]
        g.database_path = app.database_path
        g.sessao = None
        g.usuario = None
        g.novo_token = None
        if request.endpoint == "arquivos.enviar":
            request.max_content_length = app.config["MAX_FILE_SIZE"] + 65536
        if request.endpoint == "foto_perfil":
            request.max_content_length = 400 * 1024
        endereco = request.remote_addr or ""
        try:
            permitido = any(ipaddress.ip_address(endereco) in rede for rede in redes)
        except ValueError:
            permitido = False
        if not permitido:
            registrar("rede_recusada")
            from bloqueio_rede import pagina_bloqueio
            return pagina_bloqueio()
        from acesso_rede import carregar, permitido as acesso_permitido
        politica = carregar(banco())
        if not acesso_permitido(politica, request.environ.get("vaultnet.canal", "desconhecido"), endereco,
                                 request.environ.get("vaultnet.ip_publico")):
            from bloqueio_rede import pagina_bloqueio
            return pagina_bloqueio()
        token = request.cookies.get(app.config["COOKIE_NAME"], "")
        if 20 <= len(token) <= 100:
            sessao = (
                banco()
                .execute("SELECT * FROM sessoes WHERE token_hash=?", (digest(token),))
                .fetchone()
            )
            if sessao:
                expirada = (
                    sessao["expira"] <= agora()
                    or sessao["ultimo_acesso"] + 900 <= agora()
                )
                usuario = (
                    banco()
                    .execute(
                        "SELECT * FROM usuarios WHERE id=?", (sessao["usuario_id"],)
                    )
                    .fetchone()
                )
                invalida = sessao["usuario_id"] is not None and (
                    not usuario
                    or not usuario["ativo"]
                    or (
                        sessao["etapa"] in {"pendente", "autenticada"}
                        and not usuario["segredo_2fa"]
                    )
                )
                if expirada or invalida:
                    banco().execute(
                        "DELETE FROM sessoes WHERE token_hash=?",
                        (sessao["token_hash"],),
                    )
                else:
                    g.sessao, g.usuario = sessao, usuario
                    banco().execute(
                        "UPDATE sessoes SET ultimo_acesso=? WHERE token_hash=?",
                        (agora(), sessao["token_hash"]),
                    )
        if request.method == "POST":
            if request.headers.get("Sec-Fetch-Site") == "cross-site":
                abort(403, description="Origem da solicitação não autorizada.")
            origem = request.headers.get("Origin")
            if origem and origem != request.host_url.rstrip("/"):
                abort(403, description="Origem da solicitação não autorizada.")
            if request.endpoint == "arquivos.enviar" and (
                not g.sessao or g.sessao["etapa"] != "autenticada"
            ):
                # Recuse antes de interpretar e criar temporários do multipart.
                return redirect(url_for("login"))
            exigir_csrf()
        if request.endpoint == "login" and request.method == "GET" and not g.sessao:
            with transacao() as db:
                linha = db.execute(
                    "SELECT * FROM limite_paginas WHERE ip=?", (endereco,)
                ).fetchone()
                if not linha or linha["inicio"] + 60 <= agora():
                    db.execute(
                        "DELETE FROM limite_paginas WHERE inicio<?", (agora() - 3600,)
                    )
                    db.execute(
                        "INSERT OR REPLACE INTO limite_paginas VALUES(?,?,1)",
                        (endereco, agora()),
                    )
                elif linha["quantidade"] >= 120:
                    abort(429, description="Muitos acessos. Aguarde um minuto.")
                else:
                    db.execute(
                        "UPDATE limite_paginas SET quantidade=quantidade+1 WHERE ip=?",
                        (endereco,),
                    )
        if request.method == "POST" and request.endpoint in {
            "login",
            "segundo_fator",
            "configurar_2fa",
            "confirmar_acesso",
            "alterar_senha",
            "novo_usuario",
            "atualizar_usuario",
        }:
            with transacao() as db:
                linha = db.execute(
                    "SELECT * FROM limite_ip WHERE ip=?", (endereco,)
                ).fetchone()
                if not linha or linha["inicio"] + 60 <= agora():
                    db.execute(
                        "DELETE FROM limite_ip WHERE inicio<?", (agora() - 3600,)
                    )
                    db.execute(
                        "INSERT OR REPLACE INTO limite_ip VALUES(?,?,1)",
                        (endereco, agora()),
                    )
                elif linha["quantidade"] >= 30:
                    abort(429, description="Muitas tentativas. Aguarde um minuto.")
                else:
                    db.execute(
                        "UPDATE limite_ip SET quantidade=quantidade+1 WHERE ip=?",
                        (endereco,),
                    )

    @app.after_request
    def cabecalhos(resposta):
        resposta.headers["Cache-Control"] = "no-store"
        resposta.headers["X-Content-Type-Options"] = "nosniff"
        resposta.headers["X-Frame-Options"] = "DENY"
        resposta.headers["Referrer-Policy"] = "same-origin"
        resposta.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob:; worker-src 'self'; font-src 'self'; "
            "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'"
        )
        if g.get("network_nonce"):
            resposta.headers["Content-Security-Policy"] = (
                "default-src 'none'; style-src 'nonce-" + g.network_nonce + "'; "
                "base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
            )
        resposta.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )
        if g.get("novo_token"):
            resposta.set_cookie(
                app.config["COOKIE_NAME"],
                g.novo_token,
                secure=False,
                httponly=True,
                samesite="Lax",
                path="/",
            )
        return resposta

    @app.teardown_appcontext
    def fechar(_erro):
        if "db" in g:
            g.db.close()

    @app.errorhandler(400)
    @app.errorhandler(401)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(405)
    @app.errorhandler(413)
    @app.errorhandler(429)
    @app.errorhandler(503)
    def erro_conhecido(erro):
        if isinstance(erro, SecurityError):
            return Response(
                "Endereço de acesso não autorizado.", status=400, mimetype="text/plain"
            )
        mensagem = erro.description
        if erro.code == 413 and mensagem == RequestEntityTooLarge.description:
            mensagem = (
                "O envio excedeu um dos limites do sistema. "
                "Confira o tamanho do arquivo e os campos do formulário."
            )
        resposta = pagina("erro", mensagem=mensagem, status=erro.code)
        return resposta, erro.code

    @app.errorhandler(500)
    def erro_interno(_erro):
        return pagina(
            "erro", mensagem="Não foi possível concluir a operação.", status=500
        ), 500

    @app.route("/")
    def inicio():
        return redirect(
            url_for(
                "painel" if g.sessao and g.sessao["etapa"] == "autenticada" else "login"
            )
        )

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if g.sessao and g.sessao["etapa"] != "anonima":
            destino = {
                "autenticada": "painel",
                "configuracao": "configurar_2fa",
                "pendente": "segundo_fator",
            }
            return redirect(url_for(destino[g.sessao["etapa"]]))
        if request.method == "GET":
            if not g.sessao:
                banco().execute(
                    "DELETE FROM sessoes WHERE expira<=? OR ultimo_acesso<?",
                    (agora(), agora() - 900),
                )
                criar_sessao("anonima")
            return pagina("login")
        exigir_csrf()
        nome = unicodedata.normalize("NFC", request.form.get("nome", "").strip())
        senha = request.form.get("senha", "")
        with transacao() as db:
            usuario = db.execute(
                "SELECT * FROM usuarios WHERE texto_busca(nome)=texto_busca(?)", (nome,)
            ).fetchone()
            try:
                valida = (
                    HASHER.verify(
                        usuario["senha_hash"] if usuario else app.dummy_hash,
                        senha[:128],
                    )
                    and len(senha) <= 128
                )
            except VerificationError:
                valida = False
            if (
                not valida
                or not usuario
                or not usuario["ativo"]
                or usuario["bloqueado_ate"] > agora()
            ):
                if not usuario or usuario["bloqueado_ate"] <= agora():
                    falha(usuario)
                return pagina("login", erro=ERRO_LOGIN), 401
            if HASHER.check_needs_rehash(usuario["senha_hash"]):
                db.execute(
                    "UPDATE usuarios SET senha_hash=? WHERE id=?",
                    (HASHER.hash(senha), usuario["id"]),
                )
            segredo = (
                app.fernet.encrypt(pyotp.random_base32().encode()).decode()
                if not usuario["segredo_2fa"]
                else None
            )
            criar_sessao(
                "configuracao" if segredo else "pendente",
                usuario["id"],
                segredo=segredo,
            )
            registrar("senha_validada", usuario["id"])
        return redirect(url_for("configurar_2fa" if segredo else "segundo_fator"))

    @app.route("/configurar-2fa", methods=["GET", "POST"])
    def configurar_2fa():
        if not g.sessao or g.sessao["etapa"] != "configuracao":
            return redirect(url_for("login"))
        segredo = app.fernet.decrypt(g.sessao["segredo_inicial"].encode()).decode()
        if request.method == "GET":
            return pagina("configuracao", segredo=segredo)
        exigir_csrf()
        with transacao() as db:
            usuario = revalidar(("configuracao",))
            passo = passo_totp(segredo, request.form.get("codigo", "").strip())
            if usuario["bloqueado_ate"] > agora():
                return pagina("configuracao", segredo=segredo, erro=ERRO_OTP), 401
            if passo is None:
                falha(usuario)
                return pagina("configuracao", segredo=segredo, erro=ERRO_OTP), 401
            if usuario["segredo_2fa"]:
                abort(
                    400,
                    description="O segundo fator já foi configurado. Entre novamente.",
                )
            codigos = [secrets.token_hex(16) for _ in range(10)]
            db.execute(
                "UPDATE usuarios SET segredo_2fa=?,ultimo_passo=?,falhas=0,bloqueado_ate=0 WHERE id=?",
                (g.sessao["segredo_inicial"], passo, usuario["id"]),
            )
            db.executemany(
                "INSERT INTO recuperacao VALUES(?,?)",
                [(usuario["id"], digest(c)) for c in codigos],
            )
            criar_sessao(
                "autenticada",
                usuario["id"],
                codigos=app.fernet.encrypt("\n".join(codigos).encode()).decode(),
            )
            registrar("segundo_fator_configurado", usuario["id"])
            registrar("login_concluido", usuario["id"])
        return redirect(url_for("codigos_recuperacao"))

    @app.route("/qr-2fa.svg")
    def qr_2fa():
        if not g.sessao or g.sessao["etapa"] != "configuracao":
            abort(403, description="Entre para configurar o autenticador.")
        segredo = app.fernet.decrypt(g.sessao["segredo_inicial"].encode()).decode()
        uri = pyotp.TOTP(segredo).provisioning_uri(
            name=g.usuario["nome"], issuer_name="VaultNet"
        )
        qr = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
        saida = io.BytesIO()
        qr.save(saida)
        return Response(saida.getvalue(), mimetype="image/svg+xml")

    @app.route("/segundo-fator", methods=["GET", "POST"])
    def segundo_fator():
        if not g.sessao or g.sessao["etapa"] != "pendente":
            return redirect(url_for("login"))
        if request.method == "GET":
            return pagina("segundo_fator")
        exigir_csrf()
        codigo = (
            request.form.get("codigo", "")
            .strip()
            .lower()
            .replace("-", "")
            .replace(" ", "")
        )
        with transacao() as db:
            usuario = revalidar(("pendente",))
            if usuario["bloqueado_ate"] > agora():
                return pagina("segundo_fator", erro=ERRO_OTP), 401
            recuperacao = bool(re.fullmatch(r"[0-9a-f]{32}", codigo))
            if recuperacao:
                valida = (
                    db.execute(
                        "DELETE FROM recuperacao WHERE usuario_id=? AND codigo_hash=?",
                        (usuario["id"], digest(codigo)),
                    ).rowcount
                    == 1
                )
                passo = None
            else:
                segredo = app.fernet.decrypt(usuario["segredo_2fa"].encode()).decode()
                passo = passo_totp(segredo, codigo, usuario["ultimo_passo"])
                valida = passo is not None
            if not valida:
                falha(usuario)
                return pagina("segundo_fator", erro=ERRO_OTP), 401
            db.execute(
                "UPDATE usuarios SET falhas=0,bloqueado_ate=0 WHERE id=?",
                (usuario["id"],),
            )
            if passo is not None:
                db.execute(
                    "UPDATE usuarios SET ultimo_passo=? WHERE id=?",
                    (passo, usuario["id"]),
                )
            criar_sessao("autenticada", usuario["id"])
            registrar(
                "recuperacao_utilizada" if recuperacao else "login_concluido",
                usuario["id"],
            )
        return redirect(url_for("painel"))

    @app.route("/codigos-recuperacao")
    @protegido()
    def codigos_recuperacao():
        with transacao() as db:
            revalidar()
            atual = db.execute(
                "SELECT codigos_iniciais FROM sessoes WHERE token_hash=?",
                (g.sessao["token_hash"],),
            ).fetchone()
            if (
                not atual
                or not atual["codigos_iniciais"]
                or g.sessao["criado"] + 300 <= agora()
            ):
                db.execute(
                    "UPDATE sessoes SET codigos_iniciais=NULL WHERE token_hash=?",
                    (g.sessao["token_hash"],),
                )
                return redirect(url_for("painel"))
            codigos = (
                app.fernet.decrypt(atual["codigos_iniciais"].encode())
                .decode()
                .splitlines()
            )
        return pagina("recuperacao", codigos=codigos)

    @app.post("/codigos-recuperacao/confirmar")
    @protegido()
    def confirmar_codigos():
        with transacao() as db:
            revalidar()
            db.execute(
                "UPDATE sessoes SET codigos_iniciais=NULL WHERE token_hash=?",
                (g.sessao["token_hash"],),
            )
        return redirect(url_for("painel"))

    @app.route("/painel")
    @protegido()
    def painel():
        from arquivos import listar, resumo

        eventos = (
            banco()
            .execute(
                "SELECT momento,evento FROM auditoria WHERE usuario_id=? ORDER BY id DESC LIMIT 6",
                (g.usuario["id"],),
            )
            .fetchall()
        )
        return pagina(
            "painel", arquivos=listar(limite=5), resumo=resumo(), eventos=eventos
        )

    @app.route("/api/permissoes")
    @protegido()
    def api_permissoes():
        return {
            "usuario": g.usuario["nome"],
            "perfil": g.usuario["perfil"],
            "permissoes": sorted(PERFIS[g.usuario["perfil"]]),
        }

    @app.route("/administracao")
    @protegido("administrar")
    def administracao():
        usuarios = (
            banco()
            .execute(
                "SELECT id,nome,perfil,setor,ativo,segredo_2fa IS NOT NULL AS mfa FROM usuarios ORDER BY nome"
            )
            .fetchall()
        )
        pedidos_nome = banco().execute(
            "SELECT s.*,u.nome AS usuario_atual,u.ativo FROM solicitacoes_nome s "
            "JOIN usuarios u ON u.id=s.usuario_id WHERE s.status='pendente' ORDER BY s.id LIMIT 100"
        ).fetchall()
        total_pedidos = banco().execute("SELECT count(*) FROM solicitacoes_nome WHERE status='pendente'").fetchone()[0]
        return pagina("administracao", usuarios=usuarios, pedidos_nome=pedidos_nome, total_pedidos=total_pedidos)

    @app.get("/registros")
    @protegido("administrar")
    def registros():
        recebido = request.args.get("pagina", "1")
        if not re.fullmatch(r"[0-9]{1,3}", recebido) or not 1 <= int(recebido) <= 100:
            abort(400, description="Informe uma página entre 1 e 100.")
        total = min(2000, banco().execute("SELECT count(*) FROM auditoria").fetchone()[0])
        paginas = max(1, (total + 19) // 20)
        numero = min(int(recebido), paginas)
        offset = (numero - 1) * 20
        eventos = banco().execute(
            "SELECT a.momento,u.nome,a.evento,a.ip FROM auditoria a "
            "LEFT JOIN usuarios u ON u.id=a.usuario_id ORDER BY a.id DESC LIMIT 20 OFFSET ?", (offset,)
        ).fetchall()
        paginacao = dict(total=total, pagina=numero, paginas=paginas,
            inicio=offset+1 if total else 0, fim=offset+len(eventos),
            anterior=url_for("registros", pagina=numero-1) if numero>1 else None,
            proxima=url_for("registros", pagina=numero+1) if numero<paginas else None)
        return pagina("registros", eventos=eventos, paginacao=paginacao)

    @app.route("/administracao/rede", methods=["GET", "POST"])
    @protegido("administrar")
    def acesso_rede():
        from acesso_rede import carregar, salvar, validar
        mensagem = None
        if request.method == "POST":
            try:
                politica = validar(request.form.get("modo", ""), request.form.get("redes", ""), request.form.get("ips_publicos", ""))
            except ValueError as erro:
                abort(400, description=str(erro))
            with transacao():
                usuario = revalidar(permissao="administrar")
                if usuario["bloqueado_ate"] > agora() or not verificar_senha(usuario, request.form.get("senha_atual", "")):
                    if usuario["bloqueado_ate"] <= agora():
                        falha(usuario)
                    return pagina("erro", mensagem="Não foi possível confirmar a operação.", status=403), 403
                salvar(banco(), politica)
                registrar("acesso_rede_alterado:" + politica["modo"], usuario["id"])
            mensagem = "Configuração aplicada. As próximas requisições já seguem o novo modo de acesso."
        return pagina("acesso_rede", politica=carregar(banco()), mensagem=mensagem,
                      canal_atual=request.environ.get("vaultnet.canal", "desconhecido"), ip_atual=request.remote_addr,
                      ip_publico=request.environ.get("vaultnet.ip_publico"))

    @app.post("/usuarios/criar")
    @protegido("administrar")
    def novo_usuario():
        nome = unicodedata.normalize("NFC", request.form.get("nome", "").strip())
        senha = request.form.get("senha", "")
        perfil = request.form.get("perfil", "")
        setor = request.form.get("setor", "").strip()
        if len(setor) > 60 or any(ord(c) < 32 for c in setor):
            abort(400, description="Informe um setor com até 60 caracteres.")
        try:
            validar_usuario(nome, senha, perfil)
        except ValueError as erro:
            abort(400, description=str(erro))
        with transacao() as db:
            revalidar(permissao="administrar")
            exigir_confirmacao_recente()
            if g.usuario["bloqueado_ate"] > agora() or not verificar_senha(
                g.usuario, request.form.get("senha_atual", "")
            ):
                if g.usuario["bloqueado_ate"] <= agora():
                    falha(g.usuario)
                return pagina(
                    "erro",
                    mensagem="Não foi possível confirmar a operação.",
                    status=403,
                ), 403
            if db.execute("SELECT 1 FROM usuarios WHERE texto_busca(nome)=texto_busca(?)", (nome,)).fetchone():
                abort(400, description="Este nome de usuário já está cadastrado.")
            novo = db.execute(
                "INSERT INTO usuarios(nome,senha_hash,perfil,setor) VALUES(?,?,?,?)",
                (nome, HASHER.hash(senha), perfil, setor),
            )
            registrar("usuario_criado_web:" + str(novo.lastrowid), g.usuario["id"])
        return redirect(url_for("administracao"))

    @app.post("/usuarios/<int:uid>/atualizar")
    @protegido("administrar")
    def atualizar_usuario(uid):
        perfil = request.form.get("perfil", "")
        setor = request.form.get("setor", "").strip()
        if len(setor) > 60 or any(ord(c) < 32 for c in setor):
            abort(400, description="Informe um setor com até 60 caracteres.")
        ativo = 1 if request.form.get("ativo") == "1" else 0
        if perfil not in PERFIS:
            abort(400, description="Perfil inválido.")
        with transacao() as db:
            revalidar(permissao="administrar")
            exigir_confirmacao_recente()
            if g.usuario["bloqueado_ate"] > agora() or not verificar_senha(
                g.usuario, request.form.get("senha_atual", "")
            ):
                if g.usuario["bloqueado_ate"] <= agora():
                    falha(g.usuario)
                return pagina(
                    "erro",
                    mensagem="Não foi possível confirmar a operação.",
                    status=403,
                ), 403
            alvo = db.execute("SELECT * FROM usuarios WHERE id=?", (uid,)).fetchone()
            if not alvo:
                abort(404, description="Conta não encontrada.")
            if (
                alvo["ativo"]
                and alvo["perfil"] == "administrador"
                and (not ativo or perfil != "administrador")
                and db.execute(
                    "SELECT count(*) FROM usuarios WHERE ativo=1 AND perfil='administrador'"
                ).fetchone()[0]
                <= 1
            ):
                abort(400, description="Mantenha pelo menos um administrador ativo.")
            db.execute(
                "UPDATE usuarios SET perfil=?,ativo=?,setor=? WHERE id=?",
                (perfil, ativo, setor if "setor" in request.form else alvo["setor"], uid)
            )
            db.execute("DELETE FROM sessoes WHERE usuario_id=?", (uid,))
            registrar("usuario_atualizado:" + str(uid), g.usuario["id"])
        return redirect(url_for("login" if uid == g.usuario["id"] else "administracao"))

    @app.post("/perfil/nome")
    @protegido()
    def alterar_nome():
        nome = unicodedata.normalize("NFC", request.form.get("nome_novo", "").strip())
        try:
            validar_nome_usuario(nome)
        except ValueError as erro:
            abort(400, description=str(erro))
        with transacao() as db:
            usuario = revalidar()
            if nome == usuario["nome"]:
                abort(400, description="Escolha um nome diferente do atual.")
            if db.execute("SELECT 1 FROM usuarios WHERE texto_busca(nome)=texto_busca(?) AND id<>?", (nome, usuario["id"])).fetchone():
                abort(400, description="Este nome de usuário já está em uso.")
            if usuario["perfil"] == "administrador":
                exigir_confirmacao_recente()
                db.execute("UPDATE usuarios SET nome=? WHERE id=?", (nome, usuario["id"]))
                db.execute("UPDATE solicitacoes_nome SET status='rejeitada',decidido=?,administrador_id=? "
                           "WHERE usuario_id=? AND status='pendente'", (agora(), usuario["id"], usuario["id"]))
                registrar("nome_alterado:" + str(usuario["id"]), usuario["id"])
                resultado = "alterado"
            else:
                if db.execute("SELECT 1 FROM solicitacoes_nome WHERE usuario_id=? AND status='pendente'", (usuario["id"],)).fetchone():
                    abort(400, description="Você já tem uma solicitação de nome aguardando aprovação.")
                db.execute("INSERT INTO solicitacoes_nome(usuario_id,nome_anterior,nome_novo,criado) VALUES(?,?,?,?)",
                           (usuario["id"], usuario["nome"], nome, agora()))
                registrar("nome_solicitado:" + str(usuario["id"]), usuario["id"])
                resultado = "solicitado"
        return redirect(url_for("perfil", nome=resultado))

    @app.post("/usuarios/nomes/<int:pedido_id>/<decisao>")
    @protegido("administrar")
    def decidir_nome(pedido_id, decisao):
        if decisao not in {"aprovar", "rejeitar"}:
            abort(404)
        with transacao() as db:
            revalidar(permissao="administrar")
            exigir_confirmacao_recente()
            pedido = db.execute("SELECT * FROM solicitacoes_nome WHERE id=?", (pedido_id,)).fetchone()
            if not pedido or pedido["status"] != "pendente":
                abort(409, description="Esta solicitação não está mais pendente. Atualize a página.")
            if decisao == "aprovar":
                alvo = db.execute("SELECT * FROM usuarios WHERE id=?", (pedido["usuario_id"],)).fetchone()
                if not alvo or not alvo["ativo"] or alvo["nome"] != pedido["nome_anterior"]:
                    abort(409, description="A conta foi alterada ou desativada. Rejeite a solicitação e solicite uma nova.")
                try:
                    validar_nome_usuario(pedido["nome_novo"])
                except ValueError:
                    abort(409, description="O nome solicitado não segue a regra atual de até 20 letras e números. Rejeite o pedido para permitir uma nova solicitação.")
                if db.execute("SELECT 1 FROM usuarios WHERE texto_busca(nome)=texto_busca(?) AND id<>?", (pedido["nome_novo"], alvo["id"])).fetchone():
                    abort(409, description="O nome solicitado já está em uso. Rejeite esta solicitação.")
                db.execute("UPDATE usuarios SET nome=? WHERE id=?", (pedido["nome_novo"], alvo["id"]))
            status = "aprovada" if decisao == "aprovar" else "rejeitada"
            db.execute("UPDATE solicitacoes_nome SET status=?,decidido=?,administrador_id=? WHERE id=?",
                       (status, agora(), g.usuario["id"], pedido_id))
            registrar("nome_" + status + ":" + str(pedido["usuario_id"]), g.usuario["id"])
        return redirect(url_for("administracao", nome=status))

    @app.route("/perfil/foto", methods=["GET", "POST"])
    @protegido()
    def foto_perfil():
        if request.method == "GET":
            foto = g.usuario["foto"]
            if not foto:
                abort(404)
            try:
                imagem = app.fernet.decrypt(foto)
            except InvalidToken:
                abort(503, description="Não foi possível abrir a foto.")
            return Response(imagem, mimetype="image/png")
        if set(request.files) != {"foto"} or len(request.files.getlist("foto")) != 1:
            abort(400, description="Selecione e ajuste uma imagem antes de salvar.")
        dados = request.files["foto"].read(300 * 1024 + 1)
        try:
            dados = validar_foto_png(dados)
        except ValueError as erro:
            abort(400, description=str(erro))
        with transacao() as db:
            revalidar()
            db.execute("UPDATE usuarios SET foto=? WHERE id=?", (app.fernet.encrypt(dados), g.usuario["id"]))
            registrar("foto_atualizada", g.usuario["id"])
        return redirect(url_for("perfil", foto_atualizada=1))

    @app.get("/perfil")
    @protegido()
    def perfil():
        sessoes = (
            banco()
            .execute(
                "SELECT criado,ultimo_acesso,expira,token_hash=? AS atual FROM sessoes WHERE usuario_id=? AND etapa='autenticada' AND expira>? AND ultimo_acesso>? ORDER BY criado DESC",
                (g.sessao["token_hash"], g.usuario["id"], agora(), agora() - 900),
            )
            .fetchall()
        )
        codigos = (
            banco()
            .execute(
                "SELECT count(*) FROM recuperacao WHERE usuario_id=?",
                (g.usuario["id"],),
            )
            .fetchone()[0]
        )
        pedido_nome = banco().execute(
            "SELECT * FROM solicitacoes_nome WHERE usuario_id=? ORDER BY id DESC LIMIT 1", (g.usuario["id"],)
        ).fetchone()
        return pagina("perfil", sessoes=sessoes, restantes=codigos, pedido_nome=pedido_nome)

    @app.get("/seguranca")
    @protegido()
    def seguranca():
        return pagina("seguranca", redes=app.config["ALLOWED_NETWORKS"])

    @app.route("/confirmar-acesso", methods=["GET", "POST"])
    @protegido()
    def confirmar_acesso():
        if request.method == "GET":
            return pagina("reautenticacao")
        with transacao() as db:
            usuario = revalidar()
            codigo = request.form.get("codigo", "").strip()
            segredo = app.fernet.decrypt(usuario["segredo_2fa"].encode()).decode()
            passo = passo_totp(segredo, codigo, usuario["ultimo_passo"])
            if (
                usuario["bloqueado_ate"] > agora()
                or not verificar_senha(usuario, request.form.get("senha", ""))
                or passo is None
            ):
                if usuario["bloqueado_ate"] <= agora():
                    falha(usuario)
                return pagina("reautenticacao", erro=ERRO_LOGIN), 401
            db.execute(
                "UPDATE usuarios SET ultimo_passo=?,falhas=0,bloqueado_ate=0 WHERE id=?",
                (passo, usuario["id"]),
            )
            criar_sessao("autenticada", usuario["id"])
            registrar("acesso_reconfirmado", usuario["id"])
        return redirect(url_for("perfil", confirmado=1))

    @app.post("/perfil/senha")
    @protegido()
    def alterar_senha():
        senha = request.form.get("senha_nova", "")
        if not 9 <= len(senha) <= 128 or senha != request.form.get("confirmacao", ""):
            abort(400, description="Use de 9 a 128 caracteres e repita a mesma senha.")
        with transacao() as db:
            usuario = revalidar()
            exigir_confirmacao_recente()
            if usuario["bloqueado_ate"] > agora() or not verificar_senha(
                usuario, request.form.get("senha_atual", "")
            ):
                if usuario["bloqueado_ate"] <= agora():
                    falha(usuario)
                return pagina(
                    "erro",
                    mensagem="Não foi possível confirmar a operação.",
                    status=403,
                ), 403
            db.execute(
                "UPDATE usuarios SET senha_hash=?,falhas=0,bloqueado_ate=0 WHERE id=?",
                (HASHER.hash(senha), usuario["id"]),
            )
            db.execute("DELETE FROM sessoes WHERE usuario_id=?", (usuario["id"],))
            criar_sessao("autenticada", usuario["id"])
            registrar("senha_alterada", usuario["id"])
        return redirect(url_for("perfil", senha_alterada=1))

    @app.post("/perfil/encerrar-outras-sessoes")
    @protegido()
    def encerrar_outras_sessoes():
        with transacao() as db:
            revalidar()
            db.execute(
                "DELETE FROM sessoes WHERE usuario_id=? AND token_hash<>?",
                (g.usuario["id"], g.sessao["token_hash"]),
            )
            registrar("outras_sessoes_revogadas", g.usuario["id"])
        return redirect(url_for("perfil"))

    @app.route("/sair", methods=["POST"])
    def sair():
        exigir_csrf()
        if g.usuario:
            registrar("sessao_encerrada", g.usuario["id"])
        banco().execute(
            "DELETE FROM sessoes WHERE token_hash=?", (g.sessao["token_hash"],)
        )
        resposta = redirect(url_for("login"))
        resposta.delete_cookie(
            app.config["COOKIE_NAME"],
            path="/",
            secure=False,
            httponly=True,
            samesite="Lax",
        )
        return resposta

    @app.context_processor
    def contexto_visual():
        from arquivos import uso_armazenamento

        autenticado = bool(
            g.get("usuario") and g.get("sessao") and g.sessao["etapa"] == "autenticada"
        )
        return {
            "sessao": g.get("sessao"),
            "usuario": g.get("usuario"),
            "permissoes": PERFIS[g.usuario["perfil"]] if autenticado else set(),
            "armazenamento": uso_armazenamento() if autenticado else None,
            "envio_disponivel": bool(
                app.config["SCANNER_PATH"] or app.config["ALLOW_UNSCANNED_UPLOADS"]
            ),
            "envio_demo": app.config["ALLOW_UNSCANNED_UPLOADS"],
            "perfis": PERFIS,
            "confirmacao_recente": bool(
                g.get("sessao")
                and g.sessao["mfa_em"]
                and g.sessao["mfa_em"] + 300 >= agora()
            ),
        }

    @app.template_filter("horario")
    def horario(valor):
        fuso = timezone(timedelta(hours=app.config["DISPLAY_OFFSET_HOURS"]))
        return datetime.fromtimestamp(valor, fuso).strftime("%d/%m/%Y %H:%M:%S")

    @app.template_filter("evento")
    def evento(valor):
        nomes = {
            "senha_validada": "Senha verificada",
            "login_concluido": "Login concluído",
            "segundo_fator_configurado": "Autenticador configurado",
            "sessao_encerrada": "Sessão encerrada",
            "login_recusado": "Tentativa de acesso recusada",
            "bloqueio_temporario": "Conta bloqueada temporariamente",
            "recuperacao_utilizada": "Código de recuperação utilizado",
            "senha_alterada": "Senha alterada",
            "foto_atualizada": "Foto de perfil atualizada",
            "nome_solicitado": "Alteração de nome solicitada",
            "nome_alterado": "Nome de usuário alterado",
            "nome_aprovada": "Alteração de nome aprovada",
            "nome_rejeitada": "Alteração de nome rejeitada",
            "acesso_reconfirmado": "Acesso reconfirmado",
            "outras_sessoes_revogadas": "Outras sessões encerradas",
            "usuario_criado_web": "Conta criada",
            "usuario_criado_console": "Conta criada no servidor",
            "usuario_atualizado": "Conta atualizada",
            "arquivo_enviado": "Documento enviado",
            "arquivo_baixado": "Documento baixado",
            "arquivo_visualizado": "Documento visualizado",
            "arquivo_editado": "Informações do documento alteradas",
            "arquivo_na_lixeira": "Documento movido para a lixeira",
            "arquivo_restaurado": "Documento restaurado",
            "arquivo_removido": "Documento excluído definitivamente",
            "permissao_negada": "Permissão recusada",
            "rede_recusada": "Origem recusada",
            "acesso_rede_alterado": "Política de acesso à rede alterada",
            "acesso_rede_recuperado": "Acesso recuperado no servidor",
            "arquivo_rejeitado_antivirus": "Envio rejeitado pelo antivírus",
        }
        partes = valor.split(":", 2)
        rotulo = nomes.get(partes[0], valor.replace("_", " ").capitalize())
        if partes[0] == "arquivo_enviado":
            nome_arquivo = partes[2] if len(partes) == 3 else None
            if nome_arquivo is None and len(partes) > 1:
                linha = banco().execute("SELECT nome FROM arquivos WHERE id=?", (partes[1],)).fetchone()
                nome_arquivo = linha[0] if linha else None
            if nome_arquivo:
                return rotulo + " — " + nome_arquivo
        return rotulo

    from arquivos import configurar

    configurar(app)

    return app


def validar_nome_usuario(nome):
    if not 3 <= len(nome) <= 20 or not nome.strip() or not all(c.isalpha() or c.isdecimal() or c == " " for c in nome):
        raise ValueError("Use de 3 a 20 caracteres: somente letras maiúsculas, minúsculas, números e espaços, sem símbolos.")


def validar_usuario(nome, senha, perfil):
    validar_nome_usuario(nome)
    if not 9 <= len(senha) <= 128:
        raise ValueError("A senha deve ter de 9 a 128 caracteres.")
    if perfil not in PERFIS:
        raise ValueError("Perfil inválido.")


def criar_usuario(app, nome, senha, perfil):
    nome = unicodedata.normalize("NFC", nome.strip())
    validar_usuario(nome, senha, perfil)
    with closing(sqlite3.connect(app.database_path)) as db, db:
        db.execute("PRAGMA foreign_keys=ON")
        db.create_function("texto_busca", 1, lambda texto: unicodedata.normalize("NFC", texto).casefold(), deterministic=True)
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT 1 FROM usuarios WHERE texto_busca(nome)=texto_busca(?)", (nome,)).fetchone():
            raise ValueError("Este nome de usuário já está em uso.")
        cursor = db.execute(
            "INSERT INTO usuarios(nome,senha_hash,perfil) VALUES(?,?,?)",
            (nome, HASHER.hash(senha), perfil),
        )
        db.execute(
            "INSERT INTO auditoria(momento,usuario_id,evento,ip) VALUES(?,?,?,?)",
            (
                app.config["CLOCK"](),
                cursor.lastrowid,
                "usuario_criado_console",
                "console-local",
            ),
        )
    return cursor.lastrowid


def validar_foto_png(dados):
    """Aceita somente o PNG 256x256 gerado pelo recorte e remove metadados."""
    erro = "A foto precisa ser uma imagem PNG de 256 × 256. Ajuste a foto e tente novamente."
    if len(dados) > 300 * 1024 or not dados.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError(erro)
    pos, ihdr, partes, final = 8, None, [], False
    while pos + 12 <= len(dados):
        tamanho = int.from_bytes(dados[pos:pos+4], "big")
        tipo = dados[pos+4:pos+8]
        fim = pos + 12 + tamanho
        if fim > len(dados): raise ValueError(erro)
        conteudo = dados[pos+8:pos+8+tamanho]
        crc = int.from_bytes(dados[pos+8+tamanho:fim], "big")
        if zlib.crc32(tipo + conteudo) & 0xffffffff != crc: raise ValueError(erro)
        if ihdr is None and tipo != b"IHDR": raise ValueError(erro)
        if tipo == b"IHDR":
            if ihdr is not None or len(conteudo) != 13: raise ValueError(erro)
            w,h,prof,cor,comp,filtro,inter = struct.unpack(">IIBBBBB", conteudo)
            if (w,h,prof,comp,filtro,inter) != (256,256,8,0,0,0) or cor not in (2,6): raise ValueError(erro)
            ihdr = conteudo
        elif tipo == b"IDAT": partes.append(conteudo)
        elif tipo == b"IEND":
            if tamanho or fim != len(dados): raise ValueError(erro)
            final = True; break
        elif tipo[0] & 32 == 0: raise ValueError(erro)
        pos = fim
    if not ihdr or not partes or not final: raise ValueError(erro)
    esperado = 256 * (1 + 256 * (4 if ihdr[9] == 6 else 3))
    try:
        decoder = zlib.decompressobj()
        pixels = decoder.decompress(b"".join(partes), esperado+1)
        if len(pixels) != esperado or not decoder.eof or decoder.unused_data: raise ValueError(erro)
        linha = esperado // 256
        if any(pixels[i] > 4 for i in range(0,esperado,linha)): raise ValueError(erro)
    except zlib.error as e: raise ValueError(erro) from e
    def chunk(tipo, payload):
        return struct.pack(">I",len(payload))+tipo+payload+struct.pack(">I",zlib.crc32(tipo+payload)&0xffffffff)
    return b"\x89PNG\r\n\x1a\n"+chunk(b"IHDR",ihdr)+chunk(b"IDAT",b"".join(partes))+chunk(b"IEND",b"")
