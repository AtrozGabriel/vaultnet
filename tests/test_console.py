"""Cadastro, alteração de nome e limites da entrada HTTP e do terminal."""

import io
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import manage
from app import COOKIE, HASHER, create_app, criar_usuario
from servidor import servir_http, validar_host
from terminal import _ler_mascarado, ler_senha


class ConsoleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = create_app({"DATA_DIR": self.tmp.name, "SCANNER_TYPE": "nenhum"})

    def tearDown(self):
        self.tmp.cleanup()

    def executar(self, comandos, nomes=(), senhas=()):
        saida = io.StringIO()
        with (
            patch.object(
                sys, "argv", ["manage.py", "--dados", self.tmp.name, *comandos]
            ),
            patch("builtins.input", side_effect=nomes),
            patch("manage.ler_senha", side_effect=senhas),
            redirect_stdout(saida),
            redirect_stderr(saida),
        ):
            manage.main()
        return saida.getvalue()

    def test_cadastro_solicita_nome_antes_da_senha_sem_conta_padrao(self):
        ordem = []

        def nome(mensagem):
            ordem.append("nome")
            return "  carlos  "

        def senha(mensagem):
            ordem.append("senha")
            return "Q7!m2#L9?"

        with (
            patch.object(
                sys,
                "argv",
                [
                    "manage.py",
                    "--dados",
                    self.tmp.name,
                    "criar-usuario",
                    "--perfil",
                    "administrador",
                ],
            ),
            patch("builtins.input", side_effect=nome),
            patch("manage.ler_senha", side_effect=senha),
            redirect_stdout(io.StringIO()),
        ):
            manage.main()
        self.assertEqual(ordem, ["nome", "senha", "senha"])
        with closing(sqlite3.connect(self.app.database_path)) as db:
            contas = db.execute(
                "SELECT nome,senha_hash,perfil FROM usuarios"
            ).fetchall()
        self.assertEqual(len(contas), 1)
        self.assertEqual(contas[0][0], "carlos")
        self.assertEqual(contas[0][2], "administrador")
        self.assertTrue(HASHER.verify(contas[0][1], "Q7!m2#L9?"))

    def test_senhas_diferentes_nao_criam_conta(self):
        with self.assertRaises(SystemExit):
            self.executar(
                ["criar-usuario"],
                ["carlos"],
                ["senha longa de teste A", "senha longa de teste B"],
            )
        with closing(sqlite3.connect(self.app.database_path)) as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM usuarios").fetchone()[0], 0
            )

    def test_nome_invalido_nao_solicita_senha(self):
        with self.assertRaises(SystemExit):
            self.executar(["criar-usuario"], ["<script>"])

    def test_redefinir_senha_aceita_9_rejeita_8_e_revoga_sessoes(self):
        uid = self.preparar_conta("carlos")
        with self.assertRaises(SystemExit):
            self.executar(["redefinir-senha", "carlos"], ["carlos"], ["Q7!m2#L9"])
        with closing(sqlite3.connect(self.app.database_path)) as db:
            antigo = db.execute(
                "SELECT senha_hash FROM usuarios WHERE id=?", (uid,)
            ).fetchone()[0]
            self.assertTrue(HASHER.verify(antigo, "uma senha longa de teste"))
            self.assertEqual(
                db.execute("SELECT count(*) FROM sessoes").fetchone()[0], 1
            )
        self.executar(
            ["redefinir-senha", "carlos"], ["carlos"], ["Q7!m2#L9?", "Q7!m2#L9?"]
        )
        with closing(sqlite3.connect(self.app.database_path)) as db:
            usuario = db.execute(
                "SELECT senha_hash,segredo_2fa FROM usuarios WHERE id=?", (uid,)
            ).fetchone()
            self.assertTrue(HASHER.verify(usuario[0], "Q7!m2#L9?"))
            self.assertEqual(usuario[1], "segredo-cifrado-preservado")
            self.assertEqual(
                db.execute("SELECT count(*) FROM recuperacao").fetchone()[0], 1
            )
            self.assertEqual(
                db.execute("SELECT count(*) FROM sessoes").fetchone()[0], 0
            )

    def preparar_conta(self, nome):
        uid = criar_usuario(self.app, nome, "uma senha longa de teste", "administrador")
        with closing(sqlite3.connect(self.app.database_path)) as db, db:
            db.execute(
                "UPDATE usuarios SET segredo_2fa='segredo-cifrado-preservado' WHERE id=?",
                (uid,),
            )
            db.execute(
                "INSERT INTO recuperacao VALUES(?,?)", (uid, "codigo-hash-preservado")
            )
            db.execute(
                "INSERT INTO sessoes(token_hash,usuario_id,etapa,csrf,criado,expira,ultimo_acesso,mfa_em) VALUES('sessao',?,'autenticada','csrf',1,100,1,1)",
                (uid,),
            )
        return uid

    def test_renomear_preserva_identidade_senha_2fa_e_revoga_sessoes(self):
        uid = self.preparar_conta("nome_antigo")
        self.executar(["renomear-usuario", "nome_antigo"], ["nome_antigo", "novo_nome"])
        with closing(sqlite3.connect(self.app.database_path)) as db:
            conta = db.execute(
                "SELECT id,nome,senha_hash,segredo_2fa FROM usuarios"
            ).fetchone()
            self.assertEqual(conta[:2], (uid, "novo_nome"))
            self.assertTrue(HASHER.verify(conta[2], "uma senha longa de teste"))
            self.assertEqual(conta[3], "segredo-cifrado-preservado")
            self.assertEqual(
                db.execute("SELECT count(*) FROM sessoes").fetchone()[0], 0
            )
            self.assertEqual(
                db.execute("SELECT * FROM recuperacao").fetchone(),
                (uid, "codigo-hash-preservado"),
            )
            self.assertEqual(
                db.execute("SELECT evento FROM auditoria ORDER BY id DESC").fetchone()[
                    0
                ],
                "renomear-usuario_console",
            )

    def test_nome_duplicado_reverte_alteracao_e_preserva_sessoes(self):
        self.preparar_conta("nome_antigo")
        criar_usuario(self.app, "ja_existe", "outra senha longa de teste", "atendente")
        with self.assertRaises(SystemExit):
            self.executar(
                ["renomear-usuario", "nome_antigo"], ["nome_antigo", "ja_existe"]
            )
        with closing(sqlite3.connect(self.app.database_path)) as db:
            self.assertIsNotNone(
                db.execute("SELECT 1 FROM usuarios WHERE nome='nome_antigo'").fetchone()
            )
            self.assertEqual(
                db.execute("SELECT count(*) FROM sessoes").fetchone()[0], 1
            )

    def test_console_nao_desativa_ultimo_admin_nem_revoga_sua_sessao(self):
        uid = self.preparar_conta("unico_admin")
        criar_usuario(self.app, "admin_inativo", "outra frase longa", "administrador")
        with closing(sqlite3.connect(self.app.database_path)) as db, db:
            db.execute("UPDATE usuarios SET ativo=0 WHERE nome='admin_inativo'")
        with self.assertRaises(SystemExit):
            self.executar(["desativar-usuario", "unico_admin"], ["unico_admin"])
        with closing(sqlite3.connect(self.app.database_path)) as db:
            self.assertEqual(
                db.execute("SELECT ativo FROM usuarios WHERE id=?", (uid,)).fetchone()[
                    0
                ],
                1,
            )
            self.assertEqual(
                db.execute(
                    "SELECT count(*) FROM sessoes WHERE usuario_id=?", (uid,)
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                db.execute(
                    "SELECT count(*) FROM auditoria WHERE evento='desativar-usuario_console'"
                ).fetchone()[0],
                0,
            )

    def test_console_desativa_admin_quando_ha_outro_ativo(self):
        uid = self.preparar_conta("primeiro_admin")
        criar_usuario(self.app, "segundo_admin", "outra frase longa", "administrador")
        self.executar(["desativar-usuario", "primeiro_admin"], ["primeiro_admin"])
        with closing(sqlite3.connect(self.app.database_path)) as db:
            self.assertEqual(
                db.execute("SELECT ativo FROM usuarios WHERE id=?", (uid,)).fetchone()[
                    0
                ],
                0,
            )
            self.assertEqual(
                db.execute(
                    "SELECT count(*) FROM sessoes WHERE usuario_id=?", (uid,)
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                db.execute(
                    "SELECT count(*) FROM usuarios WHERE ativo=1 AND perfil='administrador'"
                ).fetchone()[0],
                1,
            )

    def test_diagnostico_antivirus_aprova_teste_e_remove_temporario(self):
        def verificar(caminho, dados, config):
            self.assertTrue(caminho.is_file())
            self.assertEqual(caminho.read_bytes(), dados)
            self.assertIn(b"inofensivo", dados)
            return "clamav"

        scanner = Path(self.tmp.name) / "clamscan"
        scanner.touch()
        with patch("manage.analisar_arquivo", side_effect=verificar):
            saida = self.executar(
                [
                    "verificar-antivirus",
                    "--scanner",
                    "clamav",
                    "--antivirus",
                    str(scanner),
                ]
            )
        self.assertIn("Verificação concluída", saida)
        self.assertEqual(list(Path(self.tmp.name).glob("verificacao-antivirus-*")), [])

    def test_diagnostico_antivirus_falha_sem_aprovar_e_limpa_temporario(self):
        from antivirus import ErroAntivirus

        scanner = Path(self.tmp.name) / "clamscan"
        scanner.touch()
        with (
            patch(
                "manage.analisar_arquivo",
                side_effect=ErroAntivirus("Análise indisponível."),
            ),
            self.assertRaises(SystemExit),
        ):
            self.executar(
                [
                    "verificar-antivirus",
                    "--scanner",
                    "clamav",
                    "--antivirus",
                    str(scanner),
                ]
            )
        self.assertEqual(list(Path(self.tmp.name).glob("verificacao-antivirus-*")), [])


class EntradaProtegidaTests(unittest.TestCase):
    def test_senha_mascarada_permite_corrigir_sem_expor_caracteres(self):
        entrada = iter("segredoX\b!\r")
        saida = []
        senha = _ler_mascarado(lambda: next(entrada), saida.append)
        self.assertEqual(senha, "segredo!")
        self.assertNotIn("segredo", "".join(saida))
        self.assertEqual("".join(saida), "********\b \b*\n")

    def test_cancelamento_nao_retorna_senha_parcial(self):
        entrada = iter("senha\x03")
        with self.assertRaises(KeyboardInterrupt):
            _ler_mascarado(lambda: next(entrada), lambda _: None)

    def test_redirecionamento_nao_expoe_senha(self):
        with (
            patch.object(sys, "stdin", io.StringIO("senha secreta\n")),
            self.assertRaisesRegex(ValueError, "terminal interativo"),
        ):
            ler_senha("Senha: ")

    def test_host_http_nao_permite_protocolo_porta_ou_injecao(self):
        for host in (
            "localhost:8080",
            "http://127.0.0.1",
            "https://localhost",
            "x\n}",
            "{$HOST}",
            ".local",
            "x..local",
        ):
            with self.subTest(host=host), self.assertRaises(ValueError):
                validar_host(host)

    def test_http_e_cookie_compativel_sao_padrao(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = create_app({"DATA_DIR": tmp, "SCANNER_TYPE": "nenhum"})
            cliente = app.test_client()
            resposta = cliente.get("/login", base_url="http://127.0.0.1:8080")
            self.assertEqual(resposta.status_code, 200)
            cookie = resposta.headers["Set-Cookie"]
            self.assertIn(COOKIE + "=", cookie)
            self.assertNotIn("Secure", cookie)
            self.assertIn("HttpOnly", cookie)
            self.assertIn("SameSite=Lax", cookie)
            self.assertNotIn("Strict-Transport-Security", resposta.headers)

    def test_demo_http_sem_antivirus_so_pode_ser_local(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = create_app(
                {
                    "DATA_DIR": tmp,
                    "ALLOW_UNSCANNED_UPLOADS": True,
                    "SCANNER_TYPE": "nenhum",
                }
            )
            self.assertEqual(
                app.test_client()
                .get("/login", base_url="http://127.0.0.1")
                .status_code,
                200,
            )
            with self.assertRaises(ValueError):
                create_app(
                    {
                        "DATA_DIR": tmp,
                        "ALLOW_UNSCANNED_UPLOADS": True,
                        "ALLOWED_NETWORKS": ["192.168.1.0/24"],
                    }
                )

    def test_servidor_http_local_nao_confia_em_proxy_nem_expoe_traceback(self):
        with tempfile.TemporaryDirectory(prefix="dados com espaco ") as tmp:
            app = create_app({"DATA_DIR": tmp, "SCANNER_TYPE": "nenhum"})
            with (
                patch("servidor.create_server") as criar,
                patch("servidor.threading.Thread") as thread,
            ):
                thread.return_value.is_alive.return_value = False
                servir_http(app)
        self.assertEqual(criar.call_args.kwargs["host"], "127.0.0.1")
        self.assertEqual(criar.call_args.kwargs["url_scheme"], "http")
        self.assertIsNone(criar.call_args.kwargs["trusted_proxy"])
        self.assertTrue(criar.call_args.kwargs["clear_untrusted_proxy_headers"])
        self.assertFalse(criar.call_args.kwargs["expose_tracebacks"])


if __name__ == "__main__":
    unittest.main()
