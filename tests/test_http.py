"""Transporte HTTP real, isolamento de cookies e migração sem perder usuários."""

import hashlib
import http.client
import io
import json
import socket
import sqlite3
import tempfile
import time
import unittest
from contextlib import closing, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from flask import request

import iniciar_windows
import manage
import servidor
from app import COOKIE, create_app, criar_usuario, digest


def porta_disponivel():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TransporteHttpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.pasta = Path(self.tmp.name)
        self.app = create_app({"DATA_DIR": self.tmp.name, "SCANNER_TYPE": "nenhum"})

    def tearDown(self):
        self.tmp.cleanup()

    def test_callback_so_abre_quando_http_responde_e_falha_fecha_a_porta(self):
        porta = porta_disponivel()

        def pronto(endereco):
            self.assertEqual(endereco, f"http://127.0.0.1:{porta}")
            conn = http.client.HTTPConnection("127.0.0.1", porta, timeout=3)
            try:
                conn.request("GET", "/login")
                resposta = conn.getresponse()
                self.assertEqual(resposta.status, 200)
                self.assertIn(COOKIE + "=", resposta.getheader("Set-Cookie"))
                self.assertNotIn("Secure", resposta.getheader("Set-Cookie"))
                self.assertIsNone(resposta.getheader("Strict-Transport-Security"))
                resposta.read()
            finally:
                conn.close()
            raise RuntimeError("Parada controlada do teste.")

        with (
            redirect_stdout(io.StringIO()),
            self.assertRaisesRegex(RuntimeError, "Parada controlada"),
        ):
            servidor.servir_http(self.app, porta=porta, ao_iniciar=pronto)
        with socket.socket() as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", porta))
        self.assertFalse((self.pasta / "https").exists())

    def test_waitress_remove_cabecalhos_forjados_e_preserva_ip_real(self):
        @self.app.get("/qa-transporte")
        def informacao():
            return {
                "ip": request.remote_addr,
                "protocolo": request.scheme,
                "encaminhado": request.headers.get("X-Forwarded-For"),
            }

        porta = porta_disponivel()

        def pronto(_):
            conn = http.client.HTTPConnection("127.0.0.1", porta, timeout=3)
            try:
                conn.request(
                    "GET",
                    "/qa-transporte",
                    headers={
                        "X-Forwarded-For": "192.168.1.25",
                        "X-Forwarded-Proto": "https",
                        "X-Forwarded-Host": "outro.example",
                        "Forwarded": "for=192.168.1.25;proto=https;host=outro.example",
                    },
                )
                resposta = conn.getresponse()
                self.assertEqual(resposta.status, 200)
                self.assertEqual(
                    json.loads(resposta.read()),
                    {"ip": "127.0.0.1", "protocolo": "http", "encaminhado": None},
                )
            finally:
                conn.close()
            raise RuntimeError("Parada controlada.")

        with (
            redirect_stdout(io.StringIO()),
            self.assertRaisesRegex(RuntimeError, "Parada controlada"),
        ):
            servidor.servir_http(self.app, porta=porta, ao_iniciar=pronto)

    def test_bind_externo_exige_configuracao_de_rede(self):
        with self.assertRaisesRegex(ValueError, "subredes autorizadas"):
            servidor.servir_http(self.app, host="0.0.0.0")

    def test_portas_invalidas_sao_recusadas_antes_de_criar_servidor(self):
        for porta in (0, -1, 65536):
            with self.subTest(porta=porta), patch("servidor.create_server") as criar:
                with self.assertRaises(ValueError):
                    servidor.servir_http(self.app, porta=porta)
                criar.assert_not_called()

    def test_cookie_da_edicao_anterior_nao_autentica_http(self):
        uid = criar_usuario(
            self.app, "carlos", "uma frase longa do teste", "administrador"
        )
        token = "token-de-sessao-apenas-para-testes-http"
        agora = time.time()
        with closing(sqlite3.connect(self.app.database_path)) as db, db:
            db.execute(
                "UPDATE usuarios SET segredo_2fa=? WHERE id=?",
                (self.app.fernet.encrypt(b"JBSWY3DPEHPK3PXP").decode(), uid),
            )
            db.execute(
                "INSERT INTO sessoes(token_hash,usuario_id,etapa,csrf,criado,expira,ultimo_acesso,mfa_em) VALUES(?,?,?,?,?,?,?,?)",
                (
                    digest(token),
                    uid,
                    "autenticada",
                    "csrf-do-teste",
                    agora,
                    agora + 300,
                    agora,
                    agora,
                ),
            )
        cliente = self.app.test_client()
        for nome in ("__Host-vaultnet", "login_local"):
            cliente.set_cookie(nome, token)
        self.assertEqual(cliente.get("/painel").status_code, 302)
        cliente.set_cookie(COOKIE, token)
        self.assertEqual(cliente.get("/painel").status_code, 200)

    def test_migracao_revoga_sessoes_anteriores_uma_vez_e_preserva_conta_e_chaves(self):
        uid = criar_usuario(
            self.app, "carlos", "uma frase longa de teste", "administrador"
        )
        segredo = self.app.fernet.encrypt(b"JBSWY3DPEHPK3PXP").decode()
        with closing(sqlite3.connect(self.app.database_path)) as db, db:
            db.execute("UPDATE usuarios SET segredo_2fa=? WHERE id=?", (segredo, uid))
            usuario_antes = db.execute(
                "SELECT * FROM usuarios WHERE id=?", (uid,)
            ).fetchone()
            db.execute("DELETE FROM configuracoes WHERE chave='protocolo'")
            db.execute(
                "INSERT INTO sessoes(token_hash,etapa,csrf,criado,expira,ultimo_acesso) VALUES('antiga','anonima','csrf',0,300,0)"
            )
        chaves = {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in self.pasta.glob("*.key")
        }
        app_novo = create_app({"DATA_DIR": self.tmp.name, "SCANNER_TYPE": "nenhum"})
        with closing(sqlite3.connect(app_novo.database_path)) as db, db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM sessoes").fetchone()[0], 0
            )
            self.assertEqual(
                db.execute("SELECT * FROM usuarios WHERE id=?", (uid,)).fetchone(),
                usuario_antes,
            )
        self.assertEqual(
            chaves,
            {
                p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                for p in self.pasta.glob("*.key")
            },
        )
        cliente = app_novo.test_client()
        cliente.get("/login")
        with closing(sqlite3.connect(app_novo.database_path)) as db:
            depois = db.execute("SELECT token_hash FROM sessoes").fetchall()
        create_app({"DATA_DIR": self.tmp.name, "SCANNER_TYPE": "nenhum"})
        with closing(sqlite3.connect(app_novo.database_path)) as db:
            self.assertEqual(
                db.execute("SELECT token_hash FROM sessoes").fetchall(), depois
            )

    def test_subrede_sem_limite_continua_proibida(self):
        with self.assertRaisesRegex(ValueError, "/0"):
            create_app({"DATA_DIR": self.tmp.name, "ALLOWED_NETWORKS": ["0.0.0.0/0"]})


class AberturaHttpTests(unittest.TestCase):
    def test_abre_http_sem_executar_instalador_ou_ferramenta_de_certificado(self):
        with (
            patch("iniciar_windows.webbrowser.open", return_value=True) as abrir,
            patch("iniciar_windows.subprocess.run") as executar,
            redirect_stdout(io.StringIO()),
        ):
            iniciar_windows.abrir_http("http://127.0.0.1:8080")
        abrir.assert_called_once_with("http://127.0.0.1:8080/login", new=2)
        executar.assert_not_called()

    def test_navegador_indisponivel_mostra_endereco_sem_interromper_servidor(self):
        saida = io.StringIO()
        with (
            patch("iniciar_windows.webbrowser.open", return_value=False),
            redirect_stdout(saida),
        ):
            iniciar_windows.abrir_http("http://127.0.0.1:8080")
        self.assertIn("http://127.0.0.1:8080/login", saida.getvalue())


class ComandosHttpTests(unittest.TestCase):
    def test_inicio_manual_padrao_usa_loopback_http(self):
        with (
            tempfile.TemporaryDirectory() as dados,
            patch(
                "sys.argv",
                ["manage.py", "--dados", dados, "executar", "--scanner", "nenhum"],
            ),
            patch("manage.servir_http") as servir,
            redirect_stdout(io.StringIO()),
        ):
            manage.main()
        self.assertEqual(servir.call_args.kwargs["host"], "127.0.0.1")
        self.assertEqual(servir.call_args.kwargs["host_login"], "127.0.0.1")
        self.assertEqual(servir.call_args.kwargs["porta"], 8080)

    def test_lan_sem_subrede_nao_inicia_nem_cria_aplicacao(self):
        with (
            patch("sys.argv", ["manage.py", "executar", "--rede-local"]),
            patch("manage.create_app") as criar,
            patch("manage.servir_http") as servir,
            patch("sys.stderr", io.StringIO()),
            self.assertRaises(SystemExit),
        ):
            manage.main()
        criar.assert_not_called()
        servir.assert_not_called()

    def test_lan_explicitamente_limitada_preserva_controle_de_origem(self):
        with tempfile.TemporaryDirectory() as dados:
            with (
                patch(
                    "sys.argv",
                    [
                        "manage.py",
                        "--dados",
                        dados,
                        "executar",
                        "--rede-local",
                        "--subrede",
                        "192.168.1.0/24",
                        "--host-login",
                        "192.168.1.10",
                        "--scanner",
                        "nenhum",
                    ],
                ),
                patch("manage.servir_http") as servir,
                redirect_stdout(io.StringIO()),
            ):
                manage.main()
            app = servir.call_args.args[0]
            cliente = app.test_client()
            self.assertEqual(
                cliente.get(
                    "/login",
                    base_url="http://192.168.1.10:8080",
                    environ_overrides={"REMOTE_ADDR": "192.168.1.11"},
                ).status_code,
                200,
            )
            self.assertEqual(
                cliente.get(
                    "/login",
                    base_url="http://192.168.1.10:8080",
                    environ_overrides={"REMOTE_ADDR": "192.168.2.11"},
                ).status_code,
                403,
            )
        self.assertEqual(servir.call_args.kwargs["host"], "0.0.0.0")
        self.assertEqual(servir.call_args.kwargs["host_login"], "192.168.1.10")


if __name__ == "__main__":
    unittest.main()
