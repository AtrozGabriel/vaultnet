"""Regressões da preparação e do início automático, sem mudar confiança global."""

import hashlib
import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing, nullcontext, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import iniciar_windows as iniciar
from app import HASHER, create_app, criar_usuario


class CadastroInicialTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = create_app({"DATA_DIR": self.tmp.name, "SCANNER_TYPE": "nenhum"})

    def tearDown(self):
        self.tmp.cleanup()

    def test_primeiro_cadastro_solicita_opcao_nome_e_senha_sem_expor_segredo(self):
        segredo = "Q7!m2#L9?"
        ordem = []

        def entrada(mensagem):
            if "(y/n)" in mensagem:
                ordem.append("opcao")
                return " Y "
            ordem.append("nome")
            return "  CARLOS  "

        def senha(_):
            ordem.append("senha")
            return segredo

        saida = io.StringIO()
        with (
            patch("builtins.input", side_effect=entrada),
            patch("terminal.ler_senha", side_effect=senha),
            redirect_stdout(saida),
        ):
            self.assertTrue(iniciar.oferecer_cadastro_administrador(self.app))
        with closing(sqlite3.connect(self.app.database_path)) as db:
            conta = db.execute(
                "SELECT nome,perfil,senha_hash,segredo_2fa FROM usuarios"
            ).fetchone()
            evento = db.execute("SELECT evento,ip FROM auditoria").fetchone()
        self.assertEqual(ordem, ["opcao", "nome", "senha", "senha"])
        self.assertEqual(conta[:2], ("carlos", "administrador"))
        self.assertTrue(HASHER.verify(conta[2], segredo))
        self.assertTrue(conta[2].startswith("$argon2id$"))
        self.assertIsNone(conta[3])
        self.assertEqual(evento, ("usuario_criado_console", "console-local"))
        self.assertNotIn(segredo, saida.getvalue())

    def test_n_preserva_conta_existente_inclusive_inativa(self):
        uid = criar_usuario(
            self.app, "existente", "uma senha longa de teste", "administrador"
        )
        with closing(sqlite3.connect(self.app.database_path)) as db, db:
            db.execute(
                "UPDATE usuarios SET ativo=0,segredo_2fa='segredo-preservado' WHERE id=?",
                (uid,),
            )
            antes = list(db.iterdump())
        with (
            patch("builtins.input", return_value="n") as entrada,
            patch("terminal.ler_senha") as senha,
            redirect_stdout(io.StringIO()),
        ):
            self.assertFalse(iniciar.oferecer_cadastro_administrador(self.app))
        entrada.assert_called_once_with(
            "Deseja criar outra conta de administrador? (y/n): "
        )
        senha.assert_not_called()
        with closing(sqlite3.connect(self.app.database_path)) as db:
            self.assertEqual(list(db.iterdump()), antes)

    def test_y_adiciona_administrador_sem_alterar_conta_anterior_ou_chaves(self):
        uid = criar_usuario(
            self.app, "existente", "uma senha longa de teste", "administrador"
        )
        with closing(sqlite3.connect(self.app.database_path)) as db, db:
            db.execute(
                "UPDATE usuarios SET segredo_2fa='segredo-preservado' WHERE id=?",
                (uid,),
            )
            antiga = db.execute("SELECT * FROM usuarios WHERE id=?", (uid,)).fetchone()
        chaves = {p.name: p.read_bytes() for p in Path(self.tmp.name).glob("*.key")}
        with (
            patch("builtins.input", side_effect=["y", "novo_admin"]),
            patch("terminal.ler_senha", side_effect=["Q7!m2#L9?", "Q7!m2#L9?"]),
            redirect_stdout(io.StringIO()),
        ):
            self.assertTrue(iniciar.oferecer_cadastro_administrador(self.app))
        with closing(sqlite3.connect(self.app.database_path)) as db:
            self.assertEqual(
                db.execute("SELECT * FROM usuarios WHERE id=?", (uid,)).fetchone(),
                antiga,
            )
            nova = db.execute(
                "SELECT id,perfil,ativo,senha_hash,segredo_2fa FROM usuarios WHERE nome='novo_admin'"
            ).fetchone()
            self.assertEqual(
                db.execute("SELECT count(*) FROM usuarios").fetchone()[0], 2
            )
        self.assertNotEqual(nova[0], uid)
        self.assertEqual(nova[1:3], ("administrador", 1))
        self.assertTrue(HASHER.verify(nova[3], "Q7!m2#L9?"))
        self.assertIsNone(nova[4])
        self.assertEqual(
            {p.name: p.read_bytes() for p in Path(self.tmp.name).glob("*.key")}, chaves
        )

    def test_opcao_invalida_repete_sem_pedir_credenciais(self):
        with (
            patch("builtins.input", side_effect=["", "x", " N "]) as entrada,
            patch("terminal.ler_senha") as senha,
            redirect_stdout(io.StringIO()),
        ):
            self.assertFalse(iniciar.oferecer_cadastro_administrador(self.app))
        self.assertEqual(entrada.call_count, 3)
        senha.assert_not_called()
        with closing(sqlite3.connect(self.app.database_path)) as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM usuarios").fetchone()[0], 0
            )

    def test_nome_em_uso_nao_substitui_ou_promove_a_conta(self):
        uid = criar_usuario(
            self.app, "existente", "uma senha longa de teste", "atendente"
        )
        with closing(sqlite3.connect(self.app.database_path)) as db:
            antiga = db.execute("SELECT * FROM usuarios WHERE id=?", (uid,)).fetchone()
        with (
            patch("builtins.input", side_effect=["y", "  EXISTENTE  ", "novo_admin"]),
            patch(
                "terminal.ler_senha", side_effect=["Q7!m2#L9?", "Q7!m2#L9?"]
            ) as senha,
            redirect_stdout(io.StringIO()),
        ):
            self.assertTrue(iniciar.oferecer_cadastro_administrador(self.app))
        self.assertEqual(senha.call_count, 2)
        with closing(sqlite3.connect(self.app.database_path)) as db:
            self.assertEqual(
                db.execute("SELECT * FROM usuarios WHERE id=?", (uid,)).fetchone(),
                antiga,
            )
            self.assertEqual(
                db.execute(
                    "SELECT perfil FROM usuarios WHERE nome='novo_admin'"
                ).fetchone()[0],
                "administrador",
            )

    def test_nome_invalido_pode_ser_corrigido_antes_de_pedir_senha(self):
        with (
            patch("builtins.input", side_effect=["y", "<script>", "carlos"]),
            patch(
                "terminal.ler_senha", side_effect=["Q7!m2#L9?", "Q7!m2#L9?"]
            ) as senha,
            redirect_stdout(io.StringIO()),
        ):
            self.assertTrue(iniciar.oferecer_cadastro_administrador(self.app))
        self.assertEqual(senha.call_count, 2)
        with closing(sqlite3.connect(self.app.database_path)) as db:
            self.assertEqual(
                db.execute("SELECT nome FROM usuarios").fetchall(), [("carlos",)]
            )

    def test_senha_divergente_pode_ser_corrigida(self):
        with (
            patch("builtins.input", side_effect=["y", "carlos"]) as entrada,
            patch(
                "terminal.ler_senha",
                side_effect=[
                    "uma senha longa",
                    "outra senha longa",
                    "Q7!m2#L9?",
                    "Q7!m2#L9?",
                ],
            ),
            redirect_stdout(io.StringIO()),
        ):
            self.assertTrue(iniciar.oferecer_cadastro_administrador(self.app))
        self.assertEqual(entrada.call_count, 2)
        with closing(sqlite3.connect(self.app.database_path)) as db:
            senha_hash = db.execute("SELECT senha_hash FROM usuarios").fetchone()[0]
        self.assertTrue(HASHER.verify(senha_hash, "Q7!m2#L9?"))

    def test_senha_curta_pode_ser_corrigida_sem_mudar_o_nome(self):
        with (
            patch("builtins.input", side_effect=["y", "carlos"]) as entrada,
            patch(
                "terminal.ler_senha",
                side_effect=["Q7!m2#L9", "Q7!m2#L9", "Q7!m2#L9?", "Q7!m2#L9?"],
            ),
            redirect_stdout(io.StringIO()),
        ):
            self.assertTrue(iniciar.oferecer_cadastro_administrador(self.app))
        self.assertEqual(entrada.call_count, 2)
        with closing(sqlite3.connect(self.app.database_path)) as db:
            senha_hash = db.execute("SELECT senha_hash FROM usuarios").fetchone()[0]
        self.assertTrue(HASHER.verify(senha_hash, "Q7!m2#L9?"))

    def test_cancelamento_na_confirmacao_nao_deixa_conta_parcial(self):
        with (
            patch("builtins.input", side_effect=["y", "carlos"]),
            patch("terminal.ler_senha", side_effect=["Q7!m2#L9?", KeyboardInterrupt]),
            redirect_stdout(io.StringIO()),
            self.assertRaises(KeyboardInterrupt),
        ):
            iniciar.oferecer_cadastro_administrador(self.app)
        with closing(sqlite3.connect(self.app.database_path)) as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM usuarios").fetchone()[0], 0
            )
            self.assertEqual(
                db.execute("SELECT count(*) FROM auditoria").fetchone()[0], 0
            )

    def test_n_abre_o_servidor_e_a_pergunta_reaparece_em_cada_inicio(self):
        with (
            patch("app.create_app", return_value=self.app),
            patch("servidor.servir_http") as servir,
            patch("builtins.input", return_value="n") as entrada,
            patch("terminal.ler_senha") as senha,
        ):
            iniciar.executar_sistema(Path(self.tmp.name))
            iniciar.executar_sistema(Path(self.tmp.name))
        self.assertEqual(entrada.call_count, 2)
        self.assertEqual(servir.call_count, 2)
        servir.assert_called_with(self.app, ao_iniciar=iniciar.abrir_http)
        senha.assert_not_called()
        with closing(sqlite3.connect(self.app.database_path)) as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM usuarios").fetchone()[0], 0
            )


class PreparacaoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "manage.py").touch()
        self.lock = self.root / "requirements.lock"
        self.lock.write_text(
            "flask==3.1.3 \\\n    --hash=sha256:" + "a" * 64 + "\n"
            "pyotp==2.10.0 \\\n    --hash=sha256:" + "b" * 64 + "\n"
        )
        self.venv = iniciar.python_ambiente(self.root)
        self.venv.parent.mkdir(parents=True)
        self.venv.touch()
        self.wheels = self.root / "wheels/linux-py314-x64"
        self.wheels.mkdir(parents=True)
        self.info = {"versao": [3, 14], "bits": 64, "plataforma": "linux-x86_64"}

    def tearDown(self):
        self.tmp.cleanup()

    def test_segunda_abertura_aproveita_dependencias_sem_instalar_de_novo(self):
        esperado = {
            "lock_sha256": hashlib.sha256(
                (self.root / "requirements.lock").read_bytes()
            ).hexdigest(),
            **self.info,
        }
        (self.root / ".venv/vaultnet-preparado.json").write_text(json.dumps(esperado))
        with (
            patch("iniciar_windows.sondar_python", return_value=self.info),
            patch(
                "iniciar_windows.inspecionar_pacotes",
                return_value={"pendentes": [], "pip": True},
            ),
            patch("iniciar_windows.subprocess.run") as executar,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(iniciar.preparar_ambiente(self.root), self.venv)
        executar.assert_called_once()
        self.assertIn("check", executar.call_args.args[0])

    def test_pacotes_completos_sem_marca_nao_reinstalam(self):
        with (
            patch("iniciar_windows.sondar_python", return_value=self.info),
            patch(
                "iniciar_windows.inspecionar_pacotes",
                return_value={"pendentes": [], "pip": True},
            ),
            patch("iniciar_windows.subprocess.run") as executar,
            redirect_stdout(io.StringIO()),
        ):
            iniciar.preparar_ambiente(self.root)
        executar.assert_called_once()
        self.assertIn("check", executar.call_args.args[0])
        self.assertTrue((self.root / ".venv/vaultnet-preparado.json").is_file())

    def test_todos_instalados_dispensa_wheels(self):
        self.wheels.rmdir()
        with (
            patch("iniciar_windows.sondar_python", return_value=self.info),
            patch(
                "iniciar_windows.inspecionar_pacotes",
                return_value={"pendentes": [], "pip": True},
            ),
            patch("iniciar_windows.subprocess.run") as executar,
            redirect_stdout(io.StringIO()),
        ):
            iniciar.preparar_ambiente(self.root)
        self.assertIn("check", executar.call_args.args[0])

    def test_instalacao_parcial_nao_inclui_pacote_ja_presente(self):
        instalado = []

        def executar(comando, **_):
            if "install" in comando:
                instalado.append(Path(comando[-1]).read_text())
            return SimpleNamespace(returncode=0)

        with (
            patch("iniciar_windows.sondar_python", return_value=self.info),
            patch(
                "iniciar_windows.inspecionar_pacotes",
                return_value={"pendentes": ["pyotp"], "pip": True},
            ),
            patch("iniciar_windows.pacotes_corretos", return_value=True),
            patch("iniciar_windows.subprocess.run", side_effect=executar) as chamada,
            redirect_stdout(io.StringIO()),
        ):
            iniciar.preparar_ambiente(self.root)
        self.assertEqual(len(instalado), 1)
        self.assertIn("pyotp==2.10.0", instalado[0])
        self.assertIn("--hash=sha256:" + "b" * 64, instalado[0])
        self.assertNotIn("flask", instalado[0])
        self.assertFalse(any("ensurepip" in c.args[0] for c in chamada.call_args_list))

    def test_pip_ausente_preparado_sem_reinstalar_pacotes_presentes(self):
        with (
            patch("iniciar_windows.sondar_python", return_value=self.info),
            patch(
                "iniciar_windows.inspecionar_pacotes",
                return_value={"pendentes": [], "pip": False},
            ),
            patch("iniciar_windows.subprocess.run") as executar,
            redirect_stdout(io.StringIO()),
        ):
            iniciar.preparar_ambiente(self.root)
        comandos = [c.args[0] for c in executar.call_args_list]
        self.assertIn("ensurepip", comandos[0])
        self.assertFalse(any("install" in c for c in comandos))

    def test_instalacao_e_offline_com_hashes_e_preserva_dados(self):
        dados = self.root / "dados"
        dados.mkdir()
        chave = dados / "chave-preservada.key"
        chave.write_bytes(b"dados existentes")
        with (
            patch("iniciar_windows.sondar_python", return_value=self.info),
            patch(
                "iniciar_windows.inspecionar_pacotes",
                return_value={"pendentes": ["flask", "pyotp"], "pip": True},
            ),
            patch("iniciar_windows.pacotes_corretos", return_value=True),
            patch("iniciar_windows.subprocess.run") as executar,
            redirect_stdout(io.StringIO()),
        ):
            iniciar.preparar_ambiente(self.root)
        chamadas = [x.args[0] for x in executar.call_args_list]
        pip = next(x for x in chamadas if "install" in x)
        self.assertIn("--no-index", pip)
        self.assertIn("--require-hashes", pip)
        self.assertIn("--only-binary=:all:", pip)
        self.assertIn("--isolated", pip)
        self.assertIn("--no-deps", pip)
        self.assertEqual(chave.read_bytes(), b"dados existentes")
        self.assertTrue((self.root / ".venv/vaultnet-preparado.json").is_file())

    def test_falha_de_instalacao_nao_marca_ambiente_pronto(self):
        import subprocess

        with (
            patch("iniciar_windows.sondar_python", return_value=self.info),
            patch(
                "iniciar_windows.inspecionar_pacotes",
                return_value={"pendentes": ["flask"], "pip": True},
            ),
            patch(
                "iniciar_windows.subprocess.run",
                side_effect=subprocess.CalledProcessError(1, ["python", "pip"]),
            ),
            redirect_stdout(io.StringIO()),
            self.assertRaises(subprocess.CalledProcessError),
        ):
            iniciar.preparar_ambiente(self.root)
        self.assertFalse((self.root / ".venv/vaultnet-preparado.json").exists())

    def test_pacote_incompleto_nao_tenta_download_online(self):
        self.wheels.rmdir()
        with (
            patch("iniciar_windows.sondar_python", return_value=self.info),
            patch(
                "iniciar_windows.inspecionar_pacotes",
                return_value={"pendentes": ["flask"], "pip": True},
            ),
            patch("iniciar_windows.subprocess.run") as executar,
            self.assertRaisesRegex(RuntimeError, "ZIP completo"),
        ):
            iniciar.preparar_ambiente(self.root)
        executar.assert_not_called()

    def test_bloqueio_impede_aberturas_simultaneas_e_e_liberado(self):
        with (
            iniciar.instancia_unica(self.root),
            self.assertRaises(iniciar.SistemaJaAberto),
            iniciar.instancia_unica(self.root),
        ):
            self.fail("Dois inicializadores conseguiram o mesmo bloqueio.")
        with iniciar.instancia_unica(self.root):
            pass


class EtapasBatTests(unittest.TestCase):
    def test_cancelar_preparacao_impede_bat_de_avancar_para_login(self):
        with (
            patch("sys.argv", ["iniciar_windows.py", "--preparar"]),
            patch("iniciar_windows.os", SimpleNamespace(name="nt")),
            patch("iniciar_windows.instancia_unica", return_value=nullcontext()),
            patch("iniciar_windows.preparar_ambiente", side_effect=KeyboardInterrupt),
            patch("iniciar_windows.executar_sistema") as executar,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(iniciar.main(), 4)
        executar.assert_not_called()

    def test_ctrl_c_durante_execucao_encerra_sem_erro(self):
        with (
            patch("sys.argv", ["iniciar_windows.py", "--executar"]),
            patch("iniciar_windows.os", SimpleNamespace(name="nt")),
            patch("iniciar_windows.instancia_unica", return_value=nullcontext()),
            patch("iniciar_windows.executar_sistema", side_effect=KeyboardInterrupt),
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(iniciar.main(), 0)

    def test_bat_prepara_sem_iniciar_servidor(self):
        with (
            patch("sys.argv", ["iniciar_windows.py", "--preparar"]),
            patch("iniciar_windows.os", SimpleNamespace(name="nt")),
            patch("iniciar_windows.instancia_unica", return_value=nullcontext()),
            patch("iniciar_windows.preparar_ambiente") as preparar,
            patch("iniciar_windows.executar_sistema") as executar,
        ):
            self.assertEqual(iniciar.main(), 0)
        preparar.assert_called_once_with(iniciar.PROJETO)
        executar.assert_not_called()

    def test_bat_executa_sem_refazer_preparo(self):
        with (
            patch("sys.argv", ["iniciar_windows.py", "--executar"]),
            patch("iniciar_windows.os", SimpleNamespace(name="nt")),
            patch("iniciar_windows.instancia_unica", return_value=nullcontext()),
            patch("iniciar_windows.preparar_ambiente") as preparar,
            patch("iniciar_windows.executar_sistema") as executar,
        ):
            self.assertEqual(iniciar.main(), 0)
        executar.assert_called_once_with(iniciar.PROJETO)
        preparar.assert_not_called()


if __name__ == "__main__":
    unittest.main()
