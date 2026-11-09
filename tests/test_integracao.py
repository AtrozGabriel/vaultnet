"""Testes de integração e tentativas de contornar autenticação e autorização."""

import concurrent.futures
import io
import json
import os
import re
import sqlite3
import subprocess
import tempfile
import unittest
import zipfile
from contextlib import closing, contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pyotp

from app import COOKIE, create_app, criar_usuario, digest
from test_antivirus import ESTADO_PRONTO


def docx_tamanho(tamanho):
    """Documento OpenXML válido, sem compressão, com linhas perto das fronteiras."""

    def montar(texto):
        arquivo = io.BytesIO()
        with zipfile.ZipFile(arquivo, "w", compression=zipfile.ZIP_STORED) as z:
            z.writestr(
                "[Content_Types].xml",
                '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                '<Default Extension="xml" ContentType="application/xml"/>'
                '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
                "</Types>",
            )
            z.writestr(
                "_rels/.rels",
                '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
                "</Relationships>",
            )
            z.writestr(
                "word/document.xml",
                b'<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                b'<w:body><w:p><w:r><w:t xml:space="preserve">'
                + texto
                + b"</w:t></w:r></w:p></w:body></w:document>",
            )
        return arquivo.getvalue()

    conteudo = tamanho - len(montar(b""))
    if conteudo < 0:
        raise ValueError("Tamanho insuficiente para o DOCX do teste.")
    linha = b"Documento de teste com linhas internas para verificar o upload.\r\n"
    return montar((linha * (conteudo // len(linha) + 1))[:conteudo])


class IntegracaoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tempo = [1_700_000_000.0]
        self.app = create_app(
            {
                "TESTING": True,
                "DATA_DIR": self.tmp.name,
                "CLOCK": lambda: self.tempo[0],
                "ALLOW_UNSCANNED_UPLOADS": True,
            }
        )
        self.client = self.app.test_client()
        self.senha = "Q7!m2#L9?"
        self.uid = criar_usuario(self.app, "amy", self.senha, "atendente")
        self.segredo = None

    def tearDown(self):
        self.tmp.cleanup()

    @contextmanager
    def db(self):
        with closing(sqlite3.connect(self.app.database_path)) as db, db:
            db.row_factory = sqlite3.Row
            yield db

    def csrf(self, resposta):
        m = re.search(rb'name="csrf"\s+value="([^"]+)"', resposta.data)
        self.assertIsNotNone(m, resposta.status_code)
        return m.group(1).decode()

    def entrar(self, client=None, nome="amy"):
        client = client or self.client
        tela = client.get("/login")
        r = client.post(
            "/login", data={"csrf": self.csrf(tela), "nome": nome, "senha": self.senha}
        )
        self.assertEqual(r.location, "/configurar-2fa")
        with self.db() as db:
            row = db.execute(
                "SELECT segredo_inicial FROM sessoes WHERE token_hash=?",
                (digest(client.get_cookie(COOKIE).value),),
            ).fetchone()
        segredo = self.app.fernet.decrypt(row[0].encode()).decode()
        r = client.post(
            "/configurar-2fa",
            data={
                "csrf": self.csrf(client.get(r.location)),
                "codigo": pyotp.TOTP(segredo).at(self.tempo[0]),
            },
        )
        self.assertEqual(r.location, "/codigos-recuperacao")
        return segredo

    def perfil(self, perfil):
        with self.db() as db:
            db.execute("UPDATE usuarios SET perfil=? WHERE id=?", (perfil, self.uid))

    def outro(self, nome="outro", perfil="atendente"):
        uid = criar_usuario(self.app, nome, self.senha, perfil)
        client = self.app.test_client()
        self.entrar(client, nome)
        return client, uid

    def post(self, rota, dados=None, pagina="/painel", client=None):
        client = client or self.client
        csrf = self.csrf(client.get(pagina))
        return client.post(rota, data={"csrf": csrf, **(dados or {})})

    def enviar(
        self,
        nome="relatorio.txt",
        conteudo=b"Documento interno de teste.",
        visibilidade="privado",
    ):
        r = self.post(
            "/enviar",
            {
                "arquivo": (io.BytesIO(conteudo), nome),
                "categoria": "Geral",
                "visibilidade": visibilidade,
            },
            "/enviar",
        )
        return r

    def id_enviado(self, **dados):
        r = self.enviar(**dados)
        self.assertEqual(r.status_code, 302, r.data)
        return r.location.split("?")[0].split("/")[-1]

    def test_docx_pequeno_e_218kb_passam_no_scanner_e_download(self):
        self.entrar()
        self.app.config.update(
            SCANNER_ENGINE="defender",
            SCANNER_PATH="C:/Defender/MpCmdRun.exe",
            DEFENDER_POWERSHELL="C:/Windows/PowerShell/powershell.exe",
            ALLOW_UNSCANNED_UPLOADS=False,
        )
        for tamanho in (33587, 218000, 218 * 1024, 1024 * 1024):
            with self.subTest(tamanho=tamanho):
                conteudo = docx_tamanho(tamanho)
                with patch(
                    "antivirus.subprocess.run",
                    side_effect=[
                        SimpleNamespace(returncode=0, stdout=json.dumps(ESTADO_PRONTO)),
                        SimpleNamespace(returncode=0),
                    ],
                ):
                    file_id = self.id_enviado(nome="documento.docx", conteudo=conteudo)
                recebido = self.client.get("/arquivos/" + file_id + "/baixar")
                self.assertEqual(recebido.status_code, 200)
                self.assertEqual(recebido.data, conteudo)
                with self.db() as db:
                    row = db.execute(
                        "SELECT tamanho,scanner FROM arquivos WHERE id=?", (file_id,)
                    ).fetchone()
                self.assertEqual(tuple(row), (tamanho, "defender"))

    def test_docx_no_limite_de_10mib_e_download_integral(self):
        self.entrar()
        conteudo = docx_tamanho(self.app.config["MAX_FILE_SIZE"])
        file_id = self.id_enviado(nome="limite.docx", conteudo=conteudo)
        recebido = self.client.get("/arquivos/" + file_id + "/baixar")
        self.assertEqual(recebido.status_code, 200)
        self.assertEqual(recebido.data, conteudo)

    def test_docx_um_byte_acima_do_limite_continua_bloqueado(self):
        self.entrar()
        conteudo = docx_tamanho(self.app.config["MAX_FILE_SIZE"] + 1)
        r = self.enviar(nome="excedido.docx", conteudo=conteudo)
        self.assertEqual(r.status_code, 413)
        self.assertIn("10 MB", r.get_data(as_text=True))
        with self.db() as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM arquivos").fetchone()[0], 0
            )

    def test_upload_campo_de_texto_excessivo_nao_chega_ao_scanner(self):
        self.entrar()
        with patch("arquivos.verificar_antivirus") as scanner:
            r = self.post(
                "/enviar",
                {
                    "arquivo": (io.BytesIO(b"Documento"), "documento.txt"),
                    "descricao": "x" * (129 * 1024),
                },
                "/enviar",
            )
        self.assertEqual(r.status_code, 413)
        scanner.assert_not_called()
        self.assertNotIn("capacity limit", r.get_data(as_text=True))

    def test_upload_excesso_de_partes_continua_bloqueado(self):
        self.entrar()
        r = self.post(
            "/enviar",
            {
                "arquivo": (io.BytesIO(b"Documento"), "documento.txt"),
                **{f"campo_{n}": "texto" for n in range(12)},
            },
            "/enviar",
        )
        self.assertEqual(r.status_code, 413)
        with self.db() as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM arquivos").fetchone()[0], 0
            )

    def test_login_mantem_limite_pequeno_de_formulario(self):
        r = self.client.post("/login", data={"senha": "x" * (17 * 1024)})
        self.assertEqual(r.status_code, 413)
        self.assertNotIn("capacity limit", r.get_data(as_text=True))

    def test_paginas_nao_sao_liberadas_por_senha_sozinha(self):
        self.assertEqual(
            self.client.post(
                "/enviar", data={"arquivo": (io.BytesIO(b"abc"), "x.txt")}
            ).status_code,
            302,
        )
        self.client.post(
            "/login",
            data={
                "csrf": self.csrf(self.client.get("/login")),
                "nome": "amy",
                "senha": self.senha,
            },
        )
        self.assertEqual(
            self.client.post(
                "/enviar", data={"arquivo": (io.BytesIO(b"abc"), "x.txt")}
            ).status_code,
            302,
        )
        for rota in (
            "/arquivos",
            "/compartilhados",
            "/enviar",
            "/armazenamento",
            "/perfil",
            "/seguranca",
            "/lixeira",
        ):
            with self.subTest(rota=rota):
                self.assertEqual(self.client.get(rota).status_code, 302)

    def test_documento_privado_nao_aparece_para_outro_usuario(self):
        self.entrar()
        file_id = self.id_enviado(nome="confidencial-amy.txt")
        outro, _ = self.outro()
        for rota in ("/arquivos/" + file_id, "/arquivos/" + file_id + "/baixar"):
            self.assertEqual(outro.get(rota).status_code, 404)
        for rota in ("/arquivos", "/compartilhados", "/painel"):
            self.assertNotIn(b"confidencial-amy.txt", outro.get(rota).data)
        self.assertIn(b"confidencial-amy.txt", self.client.get("/arquivos").data)

    def test_compartilhamento_exige_autenticacao(self):
        self.entrar()
        file_id = self.id_enviado(visibilidade="equipe")
        outro, _ = self.outro()
        self.assertEqual(outro.get("/arquivos/" + file_id + "/baixar").status_code, 200)
        self.assertEqual(
            self.app.test_client().get("/arquivos/" + file_id + "/baixar").status_code,
            302,
        )

    def test_admin_pode_consultar_documento_privado(self):
        self.entrar()
        file_id = self.id_enviado()
        admin, _ = self.outro("admin", "administrador")
        self.assertEqual(admin.get("/arquivos/" + file_id + "/baixar").status_code, 200)

    def test_atendente_nao_edita_ou_exclui_mesmo_se_for_dono(self):
        self.entrar()
        file_id = self.id_enviado()
        for acao in ("editar", "excluir", "restaurar", "remover"):
            self.assertEqual(
                self.post("/arquivos/" + file_id + "/" + acao).status_code, 403
            )
        self.assertEqual(
            self.client.get("/arquivos/" + file_id + "/baixar").status_code, 200
        )

    def test_supervisor_nao_muda_acesso_de_documento_alheio(self):
        self.entrar()
        file_id = self.id_enviado(visibilidade="equipe")
        outro, _ = self.outro("supervisor", "supervisor")
        dados = {
            "nome": "renomeado.txt",
            "categoria": "Geral",
            "descricao": "Atualizado",
            "visibilidade": "privado",
        }
        self.assertEqual(
            self.post(
                "/arquivos/" + file_id + "/editar", dados, client=outro
            ).status_code,
            403,
        )
        dados["visibilidade"] = "equipe"
        self.assertEqual(
            self.post(
                "/arquivos/" + file_id + "/editar", dados, client=outro
            ).status_code,
            302,
        )
        self.assertIn(b"renomeado.txt", self.client.get("/arquivos").data)

    def test_tipo_e_caminho_de_arquivo_sao_validados(self):
        self.entrar()
        for nome, dados in (
            ("../fora.txt", b"abc"),
            ("x.exe", b"MZ"),
            ("falso.pdf", b"abc"),
            ("binario.txt", b"abc\x00"),
            ("x\u202etxt.txt", b"abc"),
        ):
            with self.subTest(nome=nome):
                self.assertEqual(
                    self.enviar(nome=nome, conteudo=dados).status_code, 400
                )
        with self.db() as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM arquivos").fetchone()[0], 0
            )
        self.assertFalse((Path(self.tmp.name).parent / "fora.txt").exists())

    def test_formula_no_csv_e_recusada(self):
        self.entrar()
        for separador in (",", ";", "\t"):
            with self.subTest(separador=separador):
                dados = f"nome{separador}total\nAmy{separador}=WEBSERVICE(1)".encode()
                self.assertEqual(
                    self.enviar(nome="dados.csv", conteudo=dados).status_code, 400
                )
        self.assertEqual(
            self.enviar(nome="dados.csv", conteudo=b"nome,total\nAmy,-10").status_code,
            302,
        )

    def test_documento_office_com_macro_ou_caminho_invalido_e_recusado(self):
        self.entrar()
        for nome_interno in ("word/vbaProject.bin", "../sair.xml"):
            b = io.BytesIO()
            with zipfile.ZipFile(b, "w") as z:
                z.writestr("[Content_Types].xml", "<Types/>")
                z.writestr("word/document.xml", "<document/>")
                z.writestr(nome_interno, "conteudo")
            self.assertEqual(
                self.enviar(nome="documento.docx", conteudo=b.getvalue()).status_code,
                400,
            )

    def test_zip_bomb_em_documento_office_e_recusada(self):
        self.entrar()
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("[Content_Types].xml", "<Types/>")
            z.writestr("word/document.xml", b"a" * (2 * 1024 * 1024))
        self.assertEqual(
            self.enviar(nome="grande.docx", conteudo=b.getvalue()).status_code, 400
        )

    def test_envio_sem_scanner_e_bloqueado_por_padrao(self):
        self.entrar()
        self.app.config["ALLOW_UNSCANNED_UPLOADS"] = False
        self.assertEqual(self.enviar().status_code, 503)
        with self.db() as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM arquivos").fetchone()[0], 0
            )

    def test_documento_demo_nao_e_baixado_no_modo_padrao(self):
        self.entrar()
        conteudo = b"Documento enviado sem antivirus na demonstracao."
        file_id = self.id_enviado(conteudo=conteudo)
        rota = "/arquivos/" + file_id + "/baixar"
        self.assertEqual(self.client.get(rota).data, conteudo)
        self.app.config["ALLOW_UNSCANNED_UPLOADS"] = False
        for perfil in ("atendente", "administrador"):
            with self.subTest(perfil=perfil):
                self.perfil(perfil)
                resposta = self.client.get(rota)
                self.assertEqual(resposta.status_code, 403)
                self.assertNotIn(conteudo, resposta.data)

    def test_documento_verificado_continua_disponivel_no_modo_padrao(self):
        self.entrar()
        self.app.config.update(
            SCANNER_PATH="/scanner/clamscan", SCANNER_ENGINE="clamav"
        )
        conteudo = b"Documento aprovado pelo scanner."
        with patch(
            "antivirus.subprocess.run", return_value=SimpleNamespace(returncode=0)
        ):
            file_id = self.id_enviado(conteudo=conteudo)
        self.app.config["ALLOW_UNSCANNED_UPLOADS"] = False
        self.app.config["SCANNER_PATH"] = None
        resposta = self.client.get("/arquivos/" + file_id + "/baixar")
        self.assertEqual(resposta.status_code, 200)
        self.assertEqual(resposta.data, conteudo)

    def test_antivirus_malware_e_erro_nao_liberam_arquivos(self):
        self.entrar()
        self.app.config["ALLOW_UNSCANNED_UPLOADS"] = False
        self.app.config.update(
            SCANNER_PATH="/caminho-configurado/clamscan", SCANNER_ENGINE="clamav"
        )
        for retorno, status in ((1, 400), (2, 503)):
            with patch(
                "antivirus.subprocess.run",
                return_value=SimpleNamespace(returncode=retorno),
            ) as scanner:
                self.assertEqual(self.enviar().status_code, status)
                self.assertFalse(scanner.call_args.kwargs["shell"])
                self.assertIn("--alert-exceeds-max=yes", scanner.call_args.args[0])
        with self.db() as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM arquivos").fetchone()[0], 0
            )
        self.assertEqual(list((Path(self.tmp.name) / "temporarios").iterdir()), [])

    def test_defender_aprova_upload_e_download_no_modo_padrao(self):
        self.entrar()
        self.app.config.update(
            SCANNER_ENGINE="defender",
            SCANNER_PATH="C:/Defender/MpCmdRun.exe",
            DEFENDER_POWERSHELL="C:/Windows/PowerShell/powershell.exe",
            ALLOW_UNSCANNED_UPLOADS=False,
        )
        with patch(
            "antivirus.subprocess.run",
            side_effect=[
                SimpleNamespace(returncode=0, stdout=json.dumps(ESTADO_PRONTO)),
                SimpleNamespace(returncode=0),
            ],
        ):
            file_id = self.id_enviado()
        with self.db() as db:
            self.assertEqual(
                db.execute(
                    "SELECT scanner FROM arquivos WHERE id=?", (file_id,)
                ).fetchone()[0],
                "defender",
            )
        self.assertEqual(
            self.client.get("/arquivos/" + file_id + "/baixar").status_code, 200
        )
        self.assertIn(b"Verificado pelo antiv", self.client.get("/arquivos").data)
        self.assertEqual(list((Path(self.tmp.name) / "temporarios").iterdir()), [])

    def test_defender_rejeitado_ou_indisponivel_nao_armazena_documento(self):
        self.entrar()
        self.app.config.update(
            SCANNER_ENGINE="defender",
            SCANNER_PATH="C:/Defender/MpCmdRun.exe",
            DEFENDER_POWERSHELL="C:/Windows/PowerShell/powershell.exe",
            ALLOW_UNSCANNED_UPLOADS=False,
        )
        for retorno, status in ((2, 400), (5, 503)):
            with (
                self.subTest(retorno=retorno),
                patch(
                    "antivirus.subprocess.run",
                    side_effect=[
                        SimpleNamespace(returncode=0, stdout=json.dumps(ESTADO_PRONTO)),
                        SimpleNamespace(returncode=retorno),
                    ],
                ),
            ):
                self.assertEqual(self.enviar().status_code, status)
        with self.db() as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM arquivos").fetchone()[0], 0
            )
        self.assertEqual(list((Path(self.tmp.name) / "temporarios").iterdir()), [])

    def test_defender_desativado_bloqueia_upload_e_limpa_temporario(self):
        self.entrar()
        self.app.config.update(
            SCANNER_ENGINE="defender",
            SCANNER_PATH="C:/Defender/MpCmdRun.exe",
            DEFENDER_POWERSHELL="C:/Windows/PowerShell/powershell.exe",
            ALLOW_UNSCANNED_UPLOADS=False,
        )
        with patch(
            "antivirus.subprocess.run",
            return_value=SimpleNamespace(
                returncode=0,
                stdout=json.dumps({**ESTADO_PRONTO, "AntivirusEnabled": False}),
            ),
        ) as executar:
            self.assertEqual(self.enviar().status_code, 503)
        self.assertEqual(executar.call_count, 1)
        with self.db() as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM arquivos").fetchone()[0], 0
            )
        self.assertEqual(list((Path(self.tmp.name) / "temporarios").iterdir()), [])

    def test_timeout_do_antivirus_cancela_envio_e_limpa_temporario(self):
        self.entrar()
        self.app.config.update(
            SCANNER_PATH="/scanner/clamscan", SCANNER_ENGINE="clamav"
        )
        with patch(
            "antivirus.subprocess.run",
            side_effect=subprocess.TimeoutExpired("scanner", 30),
        ):
            self.assertEqual(self.enviar().status_code, 503)
        self.assertEqual(list((Path(self.tmp.name) / "temporarios").iterdir()), [])

    def test_scanner_concluido_e_armazenamento_cifrado(self):
        self.entrar()
        self.app.config.update(
            SCANNER_PATH="/scanner/clamscan", SCANNER_ENGINE="clamav"
        )
        conteudo = b"Conteudo confidencial nunca em texto puro."
        with patch(
            "antivirus.subprocess.run", return_value=SimpleNamespace(returncode=0)
        ):
            file_id = self.id_enviado(conteudo=conteudo)
        cifrado = (
            Path(self.tmp.name) / "documentos" / (file_id + ".vault")
        ).read_bytes()
        self.assertNotIn(conteudo, cifrado)
        r = self.client.get("/arquivos/" + file_id + "/baixar")
        self.assertEqual(r.data, conteudo)
        self.assertTrue(r.headers["Content-Disposition"].startswith("attachment;"))
        self.assertEqual(r.headers["Content-Type"], "application/octet-stream")
        self.assertIn(b"Verificado pelo antiv", self.client.get("/arquivos").data)

    def test_conta_revogada_durante_scan_nao_conclui_envio(self):
        self.entrar()
        self.app.config.update(
            SCANNER_PATH="/scanner/clamscan", SCANNER_ENGINE="clamav"
        )

        def revogar(*args, **kwargs):
            with self.db() as db:
                db.execute("UPDATE usuarios SET ativo=0 WHERE id=?", (self.uid,))
                db.execute("DELETE FROM sessoes WHERE usuario_id=?", (self.uid,))
            return SimpleNamespace(returncode=0)

        with patch("antivirus.subprocess.run", side_effect=revogar):
            self.assertEqual(self.enviar().status_code, 401)
        with self.db() as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM arquivos").fetchone()[0], 0
            )

    def test_arquivo_adulterado_no_disco_nao_e_baixado(self):
        self.entrar()
        file_id = self.id_enviado()
        (Path(self.tmp.name) / "documentos" / (file_id + ".vault")).write_bytes(
            b"arquivo adulterado"
        )
        r = self.client.get("/arquivos/" + file_id + "/baixar")
        self.assertEqual(r.status_code, 503)
        self.assertNotIn(b"arquivo adulterado", r.data)

    def test_tamanho_e_cota_nao_podem_ser_contornados(self):
        self.entrar()
        self.app.config["MAX_FILE_SIZE"] = 100
        self.assertEqual(self.enviar(conteudo=b"a" * 101).status_code, 413)
        self.app.config["STORAGE_QUOTA"] = 100
        self.assertEqual(self.enviar().status_code, 413)
        self.assertEqual(list((Path(self.tmp.name) / "documentos").iterdir()), [])

    def test_lixeira_restauracao_e_exclusao_definitiva(self):
        self.perfil("administrador")
        self.entrar()
        file_id = self.id_enviado()
        self.assertEqual(
            self.post("/arquivos/" + file_id + "/excluir").status_code, 302
        )
        self.assertEqual(
            self.client.get("/arquivos/" + file_id + "/baixar").status_code, 404
        )
        self.assertEqual(
            self.post("/arquivos/" + file_id + "/restaurar").status_code, 302
        )
        self.assertEqual(
            self.client.get("/arquivos/" + file_id + "/baixar").status_code, 200
        )
        self.post("/arquivos/" + file_id + "/excluir")
        self.assertEqual(
            self.post(
                "/arquivos/" + file_id + "/remover", {"confirmacao": "sim"}
            ).status_code,
            400,
        )
        self.assertEqual(
            self.post(
                "/arquivos/" + file_id + "/remover", {"confirmacao": "EXCLUIR"}
            ).status_code,
            302,
        )
        self.assertFalse(
            (Path(self.tmp.name) / "documentos" / (file_id + ".vault")).exists()
        )

    def test_exclusao_definitiva_exige_confirmacao_recente(self):
        self.perfil("administrador")
        self.entrar()
        file_id = self.id_enviado()
        self.post("/arquivos/" + file_id + "/excluir")
        self.tempo[0] += 301
        self.assertEqual(
            self.post(
                "/arquivos/" + file_id + "/remover", {"confirmacao": "EXCLUIR"}
            ).status_code,
            403,
        )
        self.assertTrue(
            (Path(self.tmp.name) / "documentos" / (file_id + ".vault")).exists()
        )

    def test_get_nao_exclui_arquivos(self):
        self.perfil("administrador")
        self.entrar()
        file_id = self.id_enviado()
        self.assertEqual(
            self.client.get("/arquivos/" + file_id + "/excluir").status_code, 405
        )
        self.assertEqual(
            self.client.get("/arquivos/" + file_id + "/baixar").status_code, 200
        )

    def test_novas_operacoes_exigem_csrf_e_recusam_unicode_invalido(self):
        self.perfil("administrador")
        self.entrar()
        file_id = self.id_enviado()
        for rota in (
            "/enviar",
            "/perfil/senha",
            "/usuarios/criar",
            "/usuarios/1/atualizar",
            "/arquivos/" + file_id + "/excluir",
            "/perfil/encerrar-outras-sessoes",
            "/codigos-recuperacao/confirmar",
        ):
            for token in ("", "é"):
                with self.subTest(rota=rota, token=token):
                    self.assertEqual(
                        self.client.post(rota, data={"csrf": token}).status_code, 400
                    )

    def test_origem_cruzada_nao_e_aceita_com_csrf_valido(self):
        self.entrar()
        csrf = self.csrf(self.client.get("/painel"))
        for cabecalho in (
            {"Origin": "https://malicioso.exemplo"},
            {"Sec-Fetch-Site": "cross-site"},
        ):
            self.assertEqual(
                self.client.post(
                    "/sair", data={"csrf": csrf}, headers=cabecalho
                ).status_code,
                403,
            )
        self.assertEqual(self.client.get("/painel").status_code, 200)

    def test_pesquisa_sql_injection_e_descricao_xss_sao_inofensivas(self):
        self.perfil("supervisor")
        self.entrar()
        file_id = self.id_enviado()
        self.post(
            "/arquivos/" + file_id + "/editar",
            {
                "nome": "x.txt",
                "categoria": "Geral",
                "visibilidade": "privado",
                "descricao": "<script>alert(1)</script>",
            },
        )
        html = self.client.get("/arquivos/" + file_id).data
        self.assertNotIn(b"<script>alert(1)</script>", html)
        self.assertIn(b"&lt;script&gt;", html)
        self.assertNotIn(
            b"x.txt",
            self.client.get("/arquivos", query_string={"q": "' OR 1=1 --"}).data,
        )

    def test_usuario_novo_exige_admin_senha_atual_e_confirmacao(self):
        self.entrar()
        dados = {
            "nome": "novo",
            "senha": self.senha,
            "perfil": "administrador",
            "senha_atual": self.senha,
        }
        self.assertEqual(self.post("/usuarios/criar", dados).status_code, 403)
        self.perfil("administrador")
        dados["senha_atual"] = "errada"
        self.assertEqual(self.post("/usuarios/criar", dados).status_code, 403)
        dados["senha_atual"] = self.senha
        self.tempo[0] += 301
        self.assertEqual(self.post("/usuarios/criar", dados).status_code, 403)
        with self.db() as db:
            self.assertIsNone(
                db.execute("SELECT 1 FROM usuarios WHERE nome='novo'").fetchone()
            )

    def test_admin_cria_usuario_e_validacao_nao_depende_do_navegador(self):
        self.perfil("administrador")
        self.entrar()
        self.assertEqual(
            self.post(
                "/usuarios/criar",
                {
                    "nome": "curto",
                    "senha": "Q7!m2#L9",
                    "perfil": "atendente",
                    "senha_atual": self.senha,
                },
            ).status_code,
            400,
        )
        with self.db() as db:
            self.assertIsNone(
                db.execute("SELECT 1 FROM usuarios WHERE nome='curto'").fetchone()
            )
        self.assertEqual(
            self.post(
                "/usuarios/criar",
                {
                    "nome": "<script>",
                    "senha": "curta",
                    "perfil": "admin",
                    "senha_atual": self.senha,
                },
            ).status_code,
            400,
        )
        self.assertEqual(
            self.post(
                "/usuarios/criar",
                {
                    "nome": "novo",
                    "senha": self.senha,
                    "perfil": "atendente",
                    "senha_atual": self.senha,
                },
            ).status_code,
            302,
        )
        with self.db() as db:
            u = db.execute("SELECT * FROM usuarios WHERE nome='novo'").fetchone()
        self.assertEqual(u["perfil"], "atendente")
        self.assertIsNone(u["segredo_2fa"])
        self.assertNotEqual(u["senha_hash"], self.senha)

    def test_ultimo_administrador_nao_pode_ser_desativado(self):
        self.perfil("administrador")
        self.entrar()
        self.assertEqual(
            self.post(
                "/usuarios/" + str(self.uid) + "/atualizar",
                {"perfil": "atendente", "senha_atual": self.senha},
            ).status_code,
            400,
        )
        self.assertEqual(self.client.get("/administracao").status_code, 200)

    def test_alteracao_de_conta_revoga_sessoes(self):
        self.perfil("administrador")
        self.entrar()
        outro, uid = self.outro()
        self.assertEqual(
            self.post(
                "/usuarios/" + str(uid) + "/atualizar",
                {"perfil": "supervisor", "ativo": "1", "senha_atual": self.senha},
            ).status_code,
            302,
        )
        self.assertEqual(outro.get("/painel").status_code, 302)

    def test_reconfirmacao_rejeita_codigo_repetido_e_rotaciona_sessao(self):
        self.segredo = self.entrar()
        antigo = self.client.get_cookie(COOKIE).value
        self.assertEqual(
            self.post(
                "/confirmar-acesso",
                {
                    "senha": self.senha,
                    "codigo": pyotp.TOTP(self.segredo).at(self.tempo[0]),
                },
            ).status_code,
            401,
        )
        self.tempo[0] += 31
        self.assertEqual(
            self.post(
                "/confirmar-acesso",
                {
                    "senha": self.senha,
                    "codigo": pyotp.TOTP(self.segredo).at(self.tempo[0]),
                },
            ).status_code,
            302,
        )
        self.assertNotEqual(antigo, self.client.get_cookie(COOKIE).value)
        self.client.set_cookie(COOKIE, antigo)
        self.assertEqual(self.client.get("/painel").status_code, 302)

    def test_alterar_senha_exige_senha_atual_e_encerra_outras_sessoes(self):
        segredo = self.entrar()
        outro = self.app.test_client()
        self.tempo[0] += 31
        tela = outro.get("/login")
        r = outro.post(
            "/login", data={"csrf": self.csrf(tela), "nome": "amy", "senha": self.senha}
        )
        self.assertEqual(r.location, "/segundo-fator")
        outro.post(
            r.location,
            data={
                "csrf": self.csrf(outro.get(r.location)),
                "codigo": pyotp.TOTP(segredo).at(self.tempo[0]),
            },
        )
        curta = {
            "senha_atual": self.senha,
            "senha_nova": "R8!n3$M0",
            "confirmacao": "R8!n3$M0",
        }
        self.assertEqual(self.post("/perfil/senha", curta).status_code, 400)
        nova = "R8!n3$M0?"
        dados = {"senha_atual": "errada", "senha_nova": nova, "confirmacao": nova}
        self.assertEqual(self.post("/perfil/senha", dados).status_code, 403)
        dados["senha_atual"] = self.senha
        self.assertEqual(self.post("/perfil/senha", dados).status_code, 302)
        self.assertEqual(outro.get("/painel").status_code, 302)
        self.assertEqual(self.client.get("/painel").status_code, 200)

    def test_falhas_administrativas_sao_persistidas_e_bloqueadas(self):
        self.perfil("administrador")
        self.entrar()
        dados = {
            "nome": "novo",
            "senha": self.senha,
            "perfil": "atendente",
            "senha_atual": "errada",
        }
        for _ in range(5):
            self.assertEqual(self.post("/usuarios/criar", dados).status_code, 403)
        dados["senha_atual"] = self.senha
        self.assertEqual(self.post("/usuarios/criar", dados).status_code, 403)
        with self.db() as db:
            u = db.execute(
                "SELECT bloqueado_ate FROM usuarios WHERE id=?", (self.uid,)
            ).fetchone()
        self.assertGreater(u[0], self.tempo[0])

    def test_criptografia_nao_pode_ser_reinicializada_com_chave_ausente(self):
        self.entrar()
        self.id_enviado()
        (Path(self.tmp.name) / "chave_arquivos.key").unlink()
        with self.assertRaisesRegex(RuntimeError, "chave dos arquivos"):
            create_app({"DATA_DIR": self.tmp.name})

    @unittest.skipIf(os.name == "nt", "Windows exige configuração de ACL NTFS")
    def test_dados_e_chaves_existentes_recebem_permissoes_restritas(self):
        pasta = Path(self.tmp.name)
        os.chmod(pasta, 0o777)
        for nome in ("chave_2fa.key", "chave_arquivos.key"):
            os.chmod(pasta / nome, 0o644)
        os.chmod(pasta / "documentos", 0o777)
        create_app({"DATA_DIR": self.tmp.name})
        self.assertEqual(pasta.stat().st_mode & 0o777, 0o700)
        self.assertEqual((pasta / "documentos").stat().st_mode & 0o777, 0o700)
        for nome in ("chave_2fa.key", "chave_arquivos.key", "login.sqlite3"):
            self.assertEqual((pasta / nome).stat().st_mode & 0o777, 0o600)

    def test_modo_sem_antivirus_nao_pode_ser_habilitado_para_lan(self):
        with self.assertRaises(ValueError):
            create_app(
                {
                    "DATA_DIR": self.tmp.name,
                    "ALLOW_UNSCANNED_UPLOADS": True,
                    "ALLOWED_NETWORKS": ["192.168.1.0/24"],
                }
            )
        with self.assertRaises(ValueError):
            create_app(
                {
                    "DATA_DIR": self.tmp.name,
                    "ALLOW_UNSCANNED_UPLOADS": True,
                    "ALLOWED_NETWORKS": ["192.168.1.0/24"],
                }
            )

    def test_codigos_de_recuperacao_expiram_em_cinco_minutos(self):
        self.entrar()
        self.tempo[0] += 301
        self.assertEqual(self.client.get("/codigos-recuperacao").location, "/painel")

    def test_duas_tentativas_concorrentes_nao_reutilizam_otp(self):
        segredo = self.entrar()
        self.tempo[0] += 31
        clientes = [self.app.test_client(), self.app.test_client()]
        tokens = []
        for client in clientes:
            tela = client.get("/login")
            client.post(
                "/login",
                data={"csrf": self.csrf(tela), "nome": "amy", "senha": self.senha},
            )
            tokens.append(self.csrf(client.get("/segundo-fator")))
        codigo = pyotp.TOTP(segredo).at(self.tempo[0])

        def verificar(indice):
            return (
                clientes[indice]
                .post("/segundo-fator", data={"csrf": tokens[indice], "codigo": codigo})
                .status_code
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            resultado = sorted(pool.map(verificar, (0, 1)))
        self.assertEqual(resultado, [302, 401])

    def test_expiracao_absoluta_nao_e_renovada_por_atividade(self):
        self.entrar()
        for _ in range(57):
            self.tempo[0] += 500
            self.assertEqual(self.client.get("/painel").status_code, 200)
        self.tempo[0] += 301
        self.assertEqual(self.client.get("/painel").status_code, 302)

    def test_recursos_e_cabecalhos_offline(self):
        r = self.client.get("/login")
        self.assertIn(b"VaultNet", r.data)
        self.assertNotIn(b"fonts.googleapis", r.data)
        self.assertIn("script-src 'self'", r.headers["Content-Security-Policy"])
        self.assertNotIn("unsafe-inline", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["Cache-Control"], "no-store")
        for caminho in (
            "/static/estilo.css",
            "/static/interface.js",
            "/static/icons.svg",
            "/static/fonts/inter-latin-400-normal.woff2",
        ):
            with self.client.get(caminho) as recurso:
                self.assertEqual(recurso.status_code, 200)
        for caminho in (
            "/dados/login.sqlite3",
            "/dados/chave_2fa.key",
            "/dados/chave_arquivos.key",
        ):
            self.assertEqual(self.client.get(caminho).status_code, 404)

    def preparar_listagem(
        self, quantidade, dono=None, visibilidade="privado", inicio=1
    ):
        # Metadados sintéticos: estes testes avaliam a lista e a autorização,
        # não usam estes registros para downloads.
        with self.db() as db:
            db.executemany(
                """INSERT INTO arquivos(id,nome,extensao,tamanho,tamanho_disco,sha256,
                dono_id,criado,atualizado,categoria,descricao,visibilidade,scanner)
                VALUES(?,?,'txt',1,100,'hash',?,?,?,'Geral','',?,'demo-sem-antivirus')""",
                [
                    (
                        f"{n:032x}",
                        f"documento-{n:04}.txt",
                        dono or self.uid,
                        self.tempo[0] + n,
                        self.tempo[0] + n,
                        visibilidade,
                    )
                    for n in range(inicio, inicio + quantidade)
                ],
            )

    def test_paginacao_libera_documentos_antigos_sem_vazar_privados(self):
        self.entrar()
        _, outro_uid = self.outro()
        self.preparar_listagem(105)
        self.preparar_listagem(101, dono=outro_uid, inicio=1001)
        primeira = self.client.get("/arquivos").data
        segunda = self.client.get("/arquivos?pagina=2").data
        self.assertEqual(len(re.findall(rb'class="file-name"', primeira)), 100)
        self.assertEqual(len(re.findall(rb'class="file-name"', segunda)), 5)
        self.assertIn(b"105 arquivos", primeira)
        self.assertIn(b"documento-0001.txt", segunda)
        self.assertNotIn(b"documento-1001.txt", primeira + segunda)
        self.assertIn(b'rel="next"', primeira)
        self.assertIn(b'rel="prev"', segunda)
        self.assertNotIn(b'rel="next"', segunda)

    def test_paginacao_preserva_filtros_compartilhados_e_meus(self):
        self.entrar()
        self.preparar_listagem(105, visibilidade="equipe")
        resposta = self.client.get(
            "/compartilhados?q=documento&tipo=txt&categoria=Geral&meus=1"
        )
        self.assertEqual(resposta.status_code, 200)
        proxima = (
            re.search(rb'href="([^"]+)" rel="next"', resposta.data)
            .group(1)
            .decode()
            .replace("&amp;", "&")
        )
        self.assertIn("/compartilhados?", proxima)
        for filtro in (
            "q=documento",
            "tipo=txt",
            "categoria=Geral",
            "meus=1",
            "pagina=2",
        ):
            self.assertIn(filtro, proxima)
        segunda = self.client.get(proxima)
        self.assertEqual(len(re.findall(rb'class="file-name"', segunda.data)), 5)

    def test_paginas_invalidas_sao_recusadas_e_pagina_alta_tem_limite(self):
        self.entrar()
        self.preparar_listagem(105)
        for valor in ("0", "-1", "abc", "1.5", "1e10", "9" * 500):
            with self.subTest(valor=valor):
                self.assertEqual(
                    self.client.get(
                        "/arquivos", query_string={"pagina": valor}
                    ).status_code,
                    400,
                )
        resposta = self.client.get("/arquivos?pagina=999999999")
        self.assertEqual(resposta.status_code, 200)
        self.assertEqual(len(re.findall(rb'class="file-name"', resposta.data)), 5)

    def test_lixeira_tambem_tem_paginacao_e_exige_administrador(self):
        self.entrar()
        self.preparar_listagem(105)
        with self.db() as db:
            db.execute("UPDATE arquivos SET excluido_em=?", (self.tempo[0],))
        self.assertEqual(self.client.get("/lixeira?pagina=2").status_code, 403)
        self.perfil("administrador")
        segunda = self.client.get("/lixeira?pagina=2")
        self.assertEqual(segunda.status_code, 200)
        self.assertIn(b"105 documentos", segunda.data)
        self.assertEqual(len(re.findall(rb'class="trash-actions"', segunda.data)), 5)

    def test_pesquisa_respeita_acentos_e_caixa_unicode(self):
        self.entrar()
        file_id = self.id_enviado(nome="Relatório-ação.txt")
        for consulta in ("RELATÓRIO", "AÇÃO", "Relato\u0301rio"):
            with self.subTest(consulta=consulta):
                resposta = self.client.get("/arquivos", query_string={"q": consulta})
                self.assertEqual(resposta.status_code, 200)
                self.assertIn(file_id.encode(), resposta.data)

    def test_pesquisa_e_filtros_nao_interpolam_sql(self):
        self.entrar()
        self.id_enviado(nome="publico-para-dono.txt")
        _, outro_uid = self.outro()
        self.preparar_listagem(1, dono=outro_uid, inicio=9000)
        for consulta in ("' OR 1=1 --", "x'; DROP TABLE arquivos; --", "%", "_"):
            with self.subTest(consulta=consulta):
                resposta = self.client.get(
                    "/arquivos",
                    query_string={
                        "q": consulta,
                        "tipo": "txt' OR 1=1 --",
                        "categoria": "' OR 1=1 --",
                    },
                )
                self.assertEqual(resposta.status_code, 200)
                self.assertNotIn(b"documento-9000.txt", resposta.data)
        with self.db() as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM arquivos").fetchone()[0], 2
            )


if __name__ == "__main__":
    unittest.main()
