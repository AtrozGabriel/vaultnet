"""Arquivos privados no disco; toda consulta e operação aplica a autorização."""

from __future__ import annotations

import csv
import hashlib
import io
import os
import re
import secrets
import sqlite3
import tempfile
import threading
import unicodedata
import zipfile
import zlib
from contextlib import closing
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from flask import (
    Blueprint,
    abort,
    current_app,
    g,
    redirect,
    request,
    send_file,
    url_for,
)

from antivirus import (
    SCANNERS_VERIFICADOS,
    ErroAntivirus,
    analisar_arquivo,
    configurar_scanner,
)
from app import (
    PERFIS,
    agora,
    banco,
    exigir_confirmacao_recente,
    pagina,
    protegido,
    registrar,
    revalidar,
    transacao,
)

TIPOS = {"pdf", "txt", "csv", "png", "jpg", "jpeg", "docx", "xlsx", "pptx"}
CATEGORIAS = (
    "Geral",
    "Administrativo",
    "Financeiro",
    "Jurídico",
    "Projetos",
    "Recursos humanos",
)
SCHEMA = """
CREATE TABLE IF NOT EXISTS arquivos (
 id TEXT PRIMARY KEY, nome TEXT NOT NULL, extensao TEXT NOT NULL,
 tamanho INTEGER NOT NULL CHECK(tamanho>0), tamanho_disco INTEGER NOT NULL,
 sha256 TEXT NOT NULL, dono_id INTEGER NOT NULL REFERENCES usuarios(id),
 criado REAL NOT NULL, atualizado REAL NOT NULL, categoria TEXT NOT NULL,
 descricao TEXT NOT NULL DEFAULT '', visibilidade TEXT NOT NULL
 CHECK(visibilidade IN ('privado','equipe')), scanner TEXT NOT NULL,
 excluido_em REAL, excluido_por INTEGER REFERENCES usuarios(id)
);
CREATE TABLE IF NOT EXISTS arquivo_destinos (
 arquivo_id TEXT PRIMARY KEY REFERENCES arquivos(id) ON DELETE CASCADE,
 tipo TEXT NOT NULL CHECK(tipo IN ('usuario','perfil','setor')),
 valor TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS arquivos_dono ON arquivos(dono_id);
CREATE INDEX IF NOT EXISTS arquivos_criado ON arquivos(criado);
"""


def validar_nome(nome):
    nome = unicodedata.normalize("NFC", nome.strip())
    if (
        not 1 <= len(nome) <= 120
        or nome.startswith((".", "-"))
        or ".." in nome
        or any(c in nome for c in '/\\:<>"|?*')
        or any(unicodedata.category(c).startswith("C") for c in nome)
        or nome.endswith((" ", "."))
    ):
        raise ValueError(
            "Use um nome de até 120 caracteres, sem caminhos ou caracteres especiais de sistema."
        )
    extensao = Path(nome).suffix.lower().lstrip(".")
    if re.fullmatch(
        r"(?:con|prn|aux|nul|com[1-9¹²³]|lpt[1-9¹²³])",
        nome.split(".", 1)[0].rstrip(" "),
        re.IGNORECASE,
    ):
        raise ValueError(
            "Este nome é reservado pelo Windows. Renomeie o arquivo antes de enviar."
        )
    if extensao not in TIPOS:
        raise ValueError(
            "Tipo não permitido. Envie PDF, TXT, CSV, PNG, JPG, DOCX, XLSX ou PPTX."
        )
    return nome, extensao


def validar_conteudo(dados, extensao):
    """Verificação adicional ao scanner; não interpreta ou executa documentos."""
    if not dados:
        raise ValueError("O arquivo está vazio.")
    if extensao == "pdf" and not (
        dados.startswith(b"%PDF-") and b"%%EOF" in dados[-4096:]
    ):
        raise ValueError("O conteúdo não corresponde a um PDF.")
    if extensao == "png" and not dados.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("O conteúdo não corresponde a uma imagem PNG.")
    if extensao in {"jpg", "jpeg"} and not (
        dados.startswith(b"\xff\xd8\xff") and dados.endswith(b"\xff\xd9")
    ):
        raise ValueError("O conteúdo não corresponde a uma imagem JPEG.")
    if extensao in {"txt", "csv"}:
        try:
            texto = dados.decode("utf-8-sig")
        except UnicodeDecodeError as erro:
            raise ValueError("Arquivos de texto devem usar UTF-8.") from erro
        if "\x00" in texto or any(ord(c) < 32 and c not in "\n\r\t" for c in texto):
            raise ValueError(
                "O arquivo contém dados binários ou controles não permitidos."
            )
        if extensao == "csv":
            # Planilhas podem detectar diferentes separadores ao abrir um CSV.
            try:
                for separador in (",", ";", "\t"):
                    for linha in csv.reader(io.StringIO(texto), delimiter=separador):
                        for celula in linha:
                            valor = celula.lstrip().lstrip("\ufeff").lstrip()
                            if valor.startswith(
                                ("=", "+", "@", "＝", "＋", "＠", "－")
                            ) or (
                                valor.startswith("-")
                                and not re.fullmatch(r"-\d+(?:[.,]\d+)?", valor)
                            ):
                                raise ValueError(
                                    "O CSV contém células interpretáveis como fórmulas. Use valores simples."
                                )
            except csv.Error as erro:
                raise ValueError("Não foi possível validar este CSV.") from erro
    if extensao in {"docx", "xlsx", "pptx"}:
        pasta = {"docx": "word/", "xlsx": "xl/", "pptx": "ppt/"}[extensao]
        try:
            with zipfile.ZipFile(io.BytesIO(dados)) as documento:
                itens = documento.infolist()
                nomes = [item.filename for item in itens]
                if len({nome.casefold() for nome in nomes}) != len(nomes):
                    raise ValueError("O documento contém nomes internos duplicados.")
                if (
                    len(itens) > 1000
                    or sum(item.file_size for item in itens) > 30 * 1024 * 1024
                ):
                    raise ValueError(
                        "O documento excede o limite de conteúdo descompactado."
                    )
                if "[Content_Types].xml" not in nomes or not any(
                    n.startswith(pasta) for n in nomes
                ):
                    raise ValueError("O conteúdo não corresponde ao tipo de documento.")
                for item in itens:
                    n = item.filename.lower()
                    if (
                        n.startswith(("/", "\\"))
                        or ".." in n.split("/")
                        or "\\" in n
                        or item.flag_bits & 1
                        or item.compress_type
                        not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                        or "vbaproject" in n
                        or n.endswith((".exe", ".dll", ".js", ".vbs", ".ps1", ".bat"))
                        or (
                            item.file_size > 1024 * 1024
                            and item.file_size > max(1, item.compress_size) * 100
                        )
                    ):
                        raise ValueError(
                            "O documento contém macros, conteúdo cifrado ou estrutura não permitida."
                        )
                # Leia em blocos para verificar cabeçalhos locais, CRC e o limite real,
                # sem extrair conteúdo nem confiar somente no índice do ZIP.
                total = 0
                for item in itens:
                    with documento.open(item) as parte:
                        while bloco := parte.read(64 * 1024):
                            total += len(bloco)
                            if total > 30 * 1024 * 1024:
                                raise ValueError(
                                    "O documento excede o limite de conteúdo descompactado."
                                )
        except (zipfile.BadZipFile, RuntimeError, EOFError, zlib.error) as erro:
            raise ValueError("Não foi possível validar este documento.") from erro


def verificar_antivirus(dados):
    scanner = current_app.config["SCANNER_PATH"]
    if not scanner:
        if current_app.config["ALLOW_UNSCANNED_UPLOADS"]:
            return "demo-sem-antivirus"
        abort(
            503,
            description="O envio está indisponível até o responsável configurar o antivírus local.",
        )
    # O caminho do programa vem da configuração do servidor, nunca da requisição.
    pasta = Path(current_app.config["DATA_DIR"]) / "temporarios"
    pasta.mkdir(mode=0o700, exist_ok=True)
    os.chmod(pasta, 0o700)
    caminho = None
    try:
        with tempfile.NamedTemporaryFile(dir=pasta, delete=False) as arquivo:
            caminho = Path(arquivo.name)
            arquivo.write(dados)
        return analisar_arquivo(caminho, dados, current_app.config)
    except ErroAntivirus as erro:
        if erro.rejeitado:
            registrar("arquivo_rejeitado_antivirus", g.usuario["id"])
        abort(400 if erro.rejeitado else 503, description=str(erro))
    except OSError:
        abort(
            503,
            description="O antivírus está indisponível. Nenhum arquivo foi liberado.",
        )
    finally:
        if caminho:
            caminho.unlink(missing_ok=True)


ACESSO_SQL = """(?=1 OR f.dono_id=? OR f.visibilidade='equipe' OR EXISTS (
    SELECT 1 FROM arquivo_destinos d WHERE d.arquivo_id=f.id AND (
        (d.tipo='usuario' AND d.valor=?) OR
        (d.tipo='perfil' AND d.valor=?) OR
        (d.tipo='setor' AND d.valor<>'' AND d.valor=?)
    )))"""


def escopo():
    return (int(g.usuario["perfil"] == "administrador"), g.usuario["id"],
            str(g.usuario["id"]), g.usuario["perfil"], g.usuario["setor"])


def dados_destinos():
    return {
        "destinatarios": banco().execute(
            "SELECT id,nome,perfil,setor FROM usuarios WHERE ativo=1 ORDER BY nome"
        ).fetchall(),
        "setores": [r[0] for r in banco().execute(
            "SELECT DISTINCT setor FROM usuarios WHERE ativo=1 AND setor<>'' ORDER BY setor"
        )],
    }


def escolha_destino(padrao="equipe"):
    valor = request.form.get("visibilidade", padrao)
    if valor == "usuario":
        valor = "usuario:" + request.form.get("destinatario_id", "")
    return valor


def validar_destino(valor):
    if valor in {"privado", "equipe"}:
        return valor, None
    tipo, separador, alvo = valor.partition(":")
    valido = False
    if separador and tipo == "usuario" and re.fullmatch(r"[1-9][0-9]{0,17}", alvo):
        valido = banco().execute("SELECT 1 FROM usuarios WHERE id=? AND ativo=1", (int(alvo),)).fetchone()
    elif separador and tipo == "perfil":
        valido = alvo in PERFIS
    elif separador and tipo == "setor" and alvo:
        valido = banco().execute("SELECT 1 FROM usuarios WHERE setor=? AND ativo=1", (alvo,)).fetchone()
    if not valido:
        abort(400, description="Selecione um destinatário, nível ou setor válido.")
    return "privado", (tipo, alvo)


def salvar_destino(db, file_id, destino):
    db.execute("DELETE FROM arquivo_destinos WHERE arquivo_id=?", (file_id,))
    if destino:
        db.execute("INSERT INTO arquivo_destinos(arquivo_id,tipo,valor) VALUES(?,?,?)",
                   (file_id, *destino))


def acesso_valor(arquivo):
    destino = banco().execute("SELECT tipo,valor FROM arquivo_destinos WHERE arquivo_id=?", (arquivo["id"],)).fetchone()
    return destino["tipo"] + ":" + destino["valor"] if destino else arquivo["visibilidade"]


def acesso_nome(arquivo):
    valor = acesso_valor(arquivo)
    if valor == "equipe": return "Toda a equipe"
    if valor == "privado": return "Somente remetente e administradores"
    tipo, alvo = valor.split(":", 1)
    if tipo == "usuario":
        conta = banco().execute("SELECT nome FROM usuarios WHERE id=?", (int(alvo),)).fetchone()
        return "Usuário: " + (conta[0] if conta else "conta indisponível")
    return ("Nível: " if tipo == "perfil" else "Setor: ") + alvo


def filtros_listagem(compartilhados=False):
    consulta = request.args.get("q", "").strip()[:80]
    tipo_recebido = request.args.get("tipo", "")
    categoria_recebida = request.args.get("categoria", "")
    tipo = tipo_recebido if tipo_recebido in TIPOS else ""
    categoria = categoria_recebida if categoria_recebida in CATEGORIAS else ""
    uid = g.usuario["id"]
    visao = request.endpoint
    meus = int(visao == "arquivos.lista")
    recebidos = int(compartilhados)
    publico = request.args.get("publico", "") if compartilhados else ""
    if publico not in {"", "usuario", "setor", "perfil", "equipe"}:
        abort(400, description="Filtro de compartilhamento inválido.")
    filtros = {"q": consulta, "tipo": tipo, "categoria": categoria}
    if publico:
        filtros["publico"] = publico
    condicao = "WHERE f.excluido_em IS NULL AND " + ACESSO_SQL + """
        AND (?='' OR instr(texto_busca(f.nome),texto_busca(?))>0 OR instr(texto_busca(u.nome),texto_busca(?))>0)
        AND (?='' OR f.extensao=?) AND (?='' OR f.categoria=?)
        AND (?=0 OR f.dono_id=?) AND (?=0 OR f.visibilidade='equipe' OR EXISTS (SELECT 1 FROM arquivo_destinos d WHERE d.arquivo_id=f.id))"""
    # Recebidos exige destinatário real: o privilégio de administrador não amplia esta tela.
    condicao += """ AND (?=0 OR (f.dono_id<>? AND (
        f.visibilidade='equipe' OR EXISTS (
        SELECT 1 FROM arquivo_destinos d WHERE d.arquivo_id=f.id AND (
        (d.tipo='usuario' AND d.valor=?) OR (d.tipo='perfil' AND d.valor=?) OR
        (d.tipo='setor' AND d.valor<>'' AND d.valor=?))))))"""
    condicao += """ AND (?='' OR (?='equipe' AND f.visibilidade='equipe') OR EXISTS (
        SELECT 1 FROM arquivo_destinos d WHERE d.arquivo_id=f.id AND d.tipo=? AND (
        (d.tipo='usuario' AND d.valor=?) OR (d.tipo='perfil' AND d.valor=?) OR
        (d.tipo='setor' AND d.valor<>'' AND d.valor=?))))"""
    valores = (
        *escopo(),
        consulta,
        consulta,
        consulta,
        tipo,
        tipo,
        categoria,
        categoria,
        meus,
        uid,
        int(compartilhados),
        recebidos, uid, str(uid), g.usuario["perfil"], g.usuario["setor"],
        publico, publico, publico, str(uid), g.usuario["perfil"], g.usuario["setor"],
    )
    return condicao, valores, filtros


def listar(limite=100, compartilhados=False, deslocamento=0):
    condicao, valores, _ = filtros_listagem(compartilhados)
    return (
        banco()
        .execute(
            # condicao contém apenas SQL constante de filtros_listagem;
            # todas as entradas do usuário são parâmetros separados.
            "SELECT f.*,u.nome AS dono FROM arquivos f JOIN usuarios u ON u.id=f.dono_id "  # nosec B608
            + condicao
            + " ORDER BY f.criado DESC,f.id DESC LIMIT ? OFFSET ?",
            (*valores, min(limite, 1000), deslocamento),
        )
        .fetchall()
    )


def dados_pagina(compartilhados=False, lixeira=False, limite=100):
    recebido = request.args.get("pagina", "1")
    if not re.fullmatch(r"[0-9]{1,9}", recebido) or int(recebido) < 1:
        abort(400, description="Página inválida. Use um número a partir de 1.")
    if lixeira:
        condicao, valores, filtros = "WHERE f.excluido_em IS NOT NULL", (), {}
    else:
        condicao, valores, filtros = filtros_listagem(compartilhados)
    total = (
        banco()
        .execute(
            # Os dois valores possíveis de condicao são SQL constante.
            "SELECT count(*) FROM arquivos f JOIN usuarios u ON u.id=f.dono_id "  # nosec B608
            + condicao,
            valores,
        )
        .fetchone()[0]
    )
    paginas = max(1, (total + limite - 1) // limite)
    numero = min(int(recebido), paginas)
    deslocamento = (numero - 1) * limite
    if lixeira:
        itens = (
            banco()
            .execute(
                # A condição da lixeira é fixa; o deslocamento é um parâmetro.
                "SELECT f.*,u.nome AS dono FROM arquivos f JOIN usuarios u ON u.id=f.dono_id "  # nosec B608
                + condicao
                + " ORDER BY f.excluido_em DESC,f.id DESC LIMIT ? OFFSET ?",
                (limite, deslocamento),
            )
            .fetchall()
        )
    else:
        itens = listar(limite=limite, compartilhados=compartilhados, deslocamento=deslocamento)
    return {
        "arquivos": itens,
        "paginacao": {
            "total": total,
            "limite": limite,
            "pagina": numero,
            "paginas": paginas,
            "inicio": deslocamento + 1 if total else 0,
            "fim": deslocamento + len(itens),
            "anterior": url_for(request.endpoint, **filtros, pagina=numero - 1)
            if numero > 1
            else None,
            "proxima": url_for(request.endpoint, **filtros, pagina=numero + 1)
            if numero < paginas
            else None,
        },
    }


def obter(file_id, lixeira=False):
    if not re.fullmatch(r"[0-9a-f]{32}", file_id):
        abort(404, description="Arquivo não encontrado.")
    linha = banco().execute(
        "SELECT f.*,u.nome AS dono FROM arquivos f JOIN usuarios u ON u.id=f.dono_id "
        "WHERE f.id=? AND " + ACESSO_SQL,
        (file_id, *escopo()),
    ).fetchone()
    if not linha or (linha["excluido_em"] is not None and not lixeira):
        abort(404, description="Arquivo não encontrado.")
    return linha


def caminho_arquivo(file_id):
    if not re.fullmatch(r"[0-9a-f]{32}", file_id):
        abort(404)
    return Path(current_app.config["DATA_DIR"]) / "documentos" / (file_id + ".vault")


def uso_armazenamento():
    usado = (
        banco()
        .execute("SELECT coalesce(sum(tamanho_disco),0) FROM arquivos")
        .fetchone()[0]
    )
    quota = current_app.config["STORAGE_QUOTA"]
    return {
        "usado": usado,
        "quota": quota,
        "percentual": min(100, round(usado * 100 / quota, 1)),
    }


def resumo():
    linha = (
        banco()
        .execute(
            """SELECT count(*) AS total,coalesce(sum(tamanho),0) AS tamanho,
        sum(scanner IN ('clamav','defender')) AS verificados FROM arquivos f WHERE excluido_em IS NULL
        AND """ + ACESSO_SQL,
            escopo(),
        )
        .fetchone()
    )
    return dict(linha)


def configurar(app):
    with closing(sqlite3.connect(app.database_path)) as db, db:
        db.executescript(SCHEMA)
        quantidade = db.execute("SELECT count(*) FROM arquivos").fetchone()[0]
    chave = Path(app.config["DATA_DIR"]) / "chave_arquivos.key"
    if not chave.exists():
        if quantidade:
            raise RuntimeError(
                "A chave dos arquivos está ausente. Restaure o backup antes de iniciar."
            )
        try:
            with os.fdopen(
                os.open(chave, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
            ) as arquivo:
                arquivo.write(Fernet.generate_key())
        except FileExistsError:
            pass
    os.chmod(chave, 0o600)
    app.document_fernet = Fernet(chave.read_bytes())
    documentos = Path(app.config["DATA_DIR"]) / "documentos"
    documentos.mkdir(mode=0o700, exist_ok=True)
    os.chmod(documentos, 0o700)
    configurar_scanner(app.config)
    app.upload_slots = threading.BoundedSemaphore(2)
    bp = Blueprint("arquivos", __name__)

    @bp.get("/arquivos")
    @protegido("ler")
    def lista():
        return pagina(
            "arquivos",
            **dados_pagina(limite=12),
            categorias=CATEGORIAS,
            tipos=sorted(TIPOS),
            compartilhados=False,
        )

    @bp.get("/compartilhados")
    @protegido("ler")
    def compartilhados():
        return pagina(
            "arquivos",
            **dados_pagina(compartilhados=True, limite=12),
            categorias=CATEGORIAS,
            tipos=sorted(TIPOS),
            compartilhados=True,
        )

    @bp.get("/administracao/arquivos")
    @protegido("administrar")
    def todos():
        return pagina(
            "arquivos", **dados_pagina(), categorias=CATEGORIAS,
            tipos=sorted(TIPOS), compartilhados=False, todos_arquivos=True,
        )

    @bp.route("/enviar", methods=["GET", "POST"])
    @protegido("enviar")
    def enviar():
        if request.method == "GET":
            return pagina(
                "enviar", categorias=CATEGORIAS, limite=app.config["MAX_FILE_SIZE"],
                historico_envios=banco().execute(
                    "SELECT a.momento,a.evento,f.id AS arquivo_id,f.nome AS arquivo_nome,f.excluido_em "
                    "FROM auditoria a LEFT JOIN arquivos f ON f.id=substr(a.evento,17,32) "
                    "WHERE a.usuario_id=? AND substr(a.evento,1,16)='arquivo_enviado:' "
                    "ORDER BY a.id DESC LIMIT 20", (g.usuario["id"],)
                ).fetchall(), **dados_destinos()
            )
        if not (app.config["SCANNER_PATH"] or app.config["ALLOW_UNSCANNED_UPLOADS"]):
            abort(
                503,
                description="O envio está indisponível até a configuração do antivírus local.",
            )
        if not app.upload_slots.acquire(blocking=False):
            abort(
                429,
                description="Há outros envios em andamento. Aguarde e tente novamente.",
            )
        caminho = None
        concluido = False
        try:
            with transacao():
                revalidar(permissao="enviar")
            if len(request.files.getlist("arquivo")) != 1 or set(request.files) != {
                "arquivo"
            }:
                abort(400, description="Selecione um arquivo por envio.")
            upload = request.files["arquivo"]
            categoria = request.form.get("categoria", "Geral")
            visibilidade, destino = validar_destino(escolha_destino())
            descricao = request.form.get("descricao", "").strip()
            if (
                categoria not in CATEGORIAS
                or visibilidade not in {"privado", "equipe"}
                or len(descricao) > 500
            ):
                abort(400, description="Categoria, acesso ou descrição inválidos.")
            try:
                nome, extensao = validar_nome(upload.filename or "")
                dados = upload.stream.read(app.config["MAX_FILE_SIZE"] + 1)
                if len(dados) > app.config["MAX_FILE_SIZE"]:
                    abort(413, description="O limite é de 10 MB por arquivo.")
                validar_conteudo(dados, extensao)
            except ValueError as erro:
                abort(400, description=str(erro))
            scanner_usado = verificar_antivirus(dados)
            cifrado = app.document_fernet.encrypt(dados)
            file_id = secrets.token_hex(16)
            with transacao() as db:
                revalidar(permissao="enviar")
                if (
                    uso_armazenamento()["usado"] + len(cifrado)
                    > app.config["STORAGE_QUOTA"]
                ):
                    abort(
                        413,
                        description="O armazenamento está cheio. Contate o responsável.",
                    )
                caminho = caminho_arquivo(file_id)
                with os.fdopen(
                    os.open(caminho, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
                ) as arquivo:
                    arquivo.write(cifrado)
                    arquivo.flush()
                    os.fsync(arquivo.fileno())
                db.execute(
                    "INSERT INTO arquivos(id,nome,extensao,tamanho,tamanho_disco,sha256,dono_id,criado,atualizado,categoria,descricao,visibilidade,scanner) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        file_id,
                        nome,
                        extensao,
                        len(dados),
                        len(cifrado),
                        hashlib.sha256(dados).hexdigest(),
                        g.usuario["id"],
                        agora(),
                        agora(),
                        categoria,
                        descricao,
                        visibilidade,
                        scanner_usado,
                    ),
                )
                # Revalida o destino na transação final, após a análise do arquivo.
                vis_final, destino_final = validar_destino(escolha_destino())
                salvar_destino(db, file_id, destino_final)
                registrar("arquivo_enviado:" + file_id + ":" + nome, g.usuario["id"])
            concluido = True
            return redirect(url_for("arquivos.detalhe", file_id=file_id, enviado=1))
        finally:
            if caminho and not concluido:
                caminho.unlink(missing_ok=True)
            app.upload_slots.release()

    @bp.get("/arquivos/<file_id>")
    @protegido("ler")
    def detalhe(file_id):
        return pagina("detalhe", arquivo=obter(file_id), categorias=CATEGORIAS, **dados_destinos())

    @app.template_global()
    def pode_baixar():
        return g.usuario["perfil"] != "atendente"

    @bp.get("/arquivos/<file_id>/baixar")
    @protegido("ler")
    def baixar(file_id):
        return entregar_arquivo(file_id)

    @bp.get("/arquivos/<file_id>/previa")
    @protegido("ler")
    def previa(file_id):
        return entregar_arquivo(file_id, previa=True)

    @bp.get("/arquivos/<file_id>/miniatura")
    @protegido("ler")
    def miniatura(file_id):
        return entregar_arquivo(file_id, previa=True, miniatura=True)

    def entregar_arquivo(file_id, previa=False, miniatura=False):
        with transacao():
            revalidar(permissao="ler")
            if not previa and not pode_baixar():
                abort(403, description="Seu perfil não permite baixar arquivos.")
            arquivo = obter(file_id)
            if (
                arquivo["scanner"] not in SCANNERS_VERIFICADOS
                and not app.config["ALLOW_UNSCANNED_UPLOADS"]
            ):
                abort(
                    403,
                    description=(
                        "Este documento foi enviado sem antivírus na demonstração. "
                        "Envie-o novamente com o antivírus configurado para "
                        "disponibilizá-lo no modo padrão."
                    ),
                )
            if miniatura and (
                arquivo["extensao"] not in {"pdf", "png", "jpg", "jpeg"}
                or arquivo["tamanho"] > 8 * 1024 * 1024
            ):
                abort(415)
            try:
                # Leitura limitada também protege contra um disco adulterado ou arquivo substituído.
                with caminho_arquivo(file_id).open("rb") as origem:
                    cifrado = origem.read(app.config["MAX_FILE_SIZE"] * 2 + 1024)
                dados = app.document_fernet.decrypt(cifrado)
                if (
                    len(dados) != arquivo["tamanho"]
                    or hashlib.sha256(dados).hexdigest() != arquivo["sha256"]
                ):
                    raise InvalidToken
            except (OSError, InvalidToken):
                abort(
                    503,
                    description="Não foi possível verificar a integridade do arquivo. Contate o responsável.",
                )
            tipos_previa = {
                "pdf": "application/pdf", "png": "image/png",
                "jpg": "image/jpeg", "jpeg": "image/jpeg",
                "txt": "text/plain", "csv": "text/plain",
            }
            if previa and arquivo["extensao"] not in tipos_previa:
                abort(415, description="Prévia indisponível para este formato. Baixe o arquivo para abrir.")
            if not miniatura:
                registrar(("arquivo_visualizado:" if previa else "arquivo_baixado:") + file_id, g.usuario["id"])
        return send_file(
            io.BytesIO(dados),
            mimetype=tipos_previa[arquivo["extensao"]] if previa else "application/octet-stream",
            as_attachment=not previa,
            download_name=arquivo["nome"],
            conditional=False,
            etag=False,
        )

    @bp.post("/arquivos/<file_id>/editar")
    @protegido("editar")
    def editar(file_id):
        with transacao() as db:
            revalidar(permissao="editar")
            arquivo = obter(file_id)
            try:
                nome, extensao = validar_nome(request.form.get("nome", ""))
            except ValueError as erro:
                abort(400, description=str(erro))
            categoria = request.form.get("categoria", "")
            descricao = request.form.get("descricao", "").strip()
            escolha = escolha_destino("")
            visibilidade, destino = validar_destino(escolha)
            if (
                extensao != arquivo["extensao"]
                or categoria not in CATEGORIAS
                or len(descricao) > 500
                or visibilidade not in {"privado", "equipe"}
            ):
                abort(
                    400,
                    description="Confira o nome, a categoria e a descrição. Preserve a extensão.",
                )
            if (
                g.usuario["perfil"] != "administrador"
                and arquivo["dono_id"] != g.usuario["id"]
                and escolha != acesso_valor(arquivo)
            ):
                abort(
                    403,
                    description="Somente o proprietário ou o administrador pode alterar o acesso.",
                )
            db.execute(
                "UPDATE arquivos SET nome=?,categoria=?,descricao=?,visibilidade=?,atualizado=? WHERE id=?",
                (nome, categoria, descricao, visibilidade, agora(), file_id),
            )
            salvar_destino(db, file_id, destino)
            registrar("arquivo_editado:" + file_id, g.usuario["id"])
        return redirect(url_for("arquivos.detalhe", file_id=file_id))

    @bp.post("/arquivos/<file_id>/excluir")
    @protegido("excluir")
    def excluir(file_id):
        with transacao() as db:
            revalidar(permissao="excluir")
            obter(file_id)
            db.execute(
                "UPDATE arquivos SET excluido_em=?,excluido_por=? WHERE id=?",
                (agora(), g.usuario["id"], file_id),
            )
            registrar("arquivo_na_lixeira:" + file_id, g.usuario["id"])
        return redirect(url_for("arquivos.lixeira"))

    @bp.get("/lixeira")
    @protegido("excluir")
    def lixeira():
        return pagina("lixeira", **dados_pagina(lixeira=True))

    @bp.post("/arquivos/<file_id>/restaurar")
    @protegido("excluir")
    def restaurar(file_id):
        with transacao() as db:
            revalidar(permissao="excluir")
            obter(file_id, lixeira=True)
            db.execute(
                "UPDATE arquivos SET excluido_em=NULL,excluido_por=NULL WHERE id=?",
                (file_id,),
            )
            registrar("arquivo_restaurado:" + file_id, g.usuario["id"])
        return redirect(url_for("arquivos.lixeira"))

    @bp.post("/arquivos/<file_id>/remover")
    @protegido("excluir")
    def remover(file_id):
        with transacao() as db:
            revalidar(permissao="excluir")
            exigir_confirmacao_recente()
            arquivo = obter(file_id, lixeira=True)
            if (
                arquivo["excluido_em"] is None
                or request.form.get("confirmacao") != "EXCLUIR"
            ):
                abort(
                    400,
                    description="Mova para a lixeira e digite EXCLUIR para confirmar.",
                )
            caminho_arquivo(file_id).unlink(missing_ok=True)
            db.execute("DELETE FROM arquivo_destinos WHERE arquivo_id=?", (file_id,))
            db.execute("DELETE FROM arquivos WHERE id=?", (file_id,))
            registrar("arquivo_removido:" + file_id, g.usuario["id"])
        return redirect(url_for("arquivos.lixeira"))

    @bp.get("/armazenamento")
    @protegido("ler")
    def armazenamento():
        categorias = (
            banco()
            .execute(
                """SELECT categoria,count(*) AS quantidade,sum(tamanho) AS tamanho
            FROM arquivos f WHERE excluido_em IS NULL AND """ + ACESSO_SQL + " GROUP BY categoria ORDER BY tamanho DESC",
                escopo(),
            )
            .fetchall()
        )
        return pagina("armazenamento", categorias=categorias, resumo=resumo())

    @app.template_global("distribuicao_armazenamento")
    def distribuicao_armazenamento():
        tipos = banco().execute(
            """SELECT extensao, COUNT(*) AS quantidade, SUM(tamanho) AS tamanho
               FROM arquivos f WHERE excluido_em IS NULL AND """
            + ACESSO_SQL
            + " GROUP BY extensao ORDER BY tamanho DESC, extensao",
            escopo(),
        ).fetchall()
        total = sum(item["tamanho"] for item in tipos)
        cores = ("#2563eb", "#008577", "#a14bc0", "#db7621", "#db4566",
                 "#5b6cbc", "#7b8d21", "#00a1c4", "#965b3f")
        fatias = []
        inicio = 0
        for i, item in enumerate(tipos):
            percentual = 100 * item["tamanho"] / total if total else 0
            fatias.append(dict(item) | {
                "percentual": percentual, "inicio": inicio,
                "cor": cores[i % len(cores)],
            })
            inicio += percentual
        return fatias

    @app.template_filter("tamanho")
    def tamanho(valor):
        valor = float(valor or 0)
        for unidade in ("B", "KB", "MB", "GB", "TB"):
            if valor < 1024 or unidade == "TB":
                return (
                    f"{int(valor)} {unidade}"
                    if unidade == "B"
                    else f"{valor:.1f} {unidade}"
                ).replace(".", ",")
            valor /= 1024

    app.add_template_filter(acesso_nome, "acesso_nome")
    app.add_template_filter(acesso_valor, "acesso_valor")
    app.register_blueprint(bp)
