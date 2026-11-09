"""Testes dos limites de autenticação; todos executam sem serviços externos."""

import re
import sqlite3
import tempfile
import unittest
from contextlib import closing, contextmanager

import pyotp

from app import COOKIE, HASHER, create_app, criar_usuario, digest


class LoginTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tempo = [1_700_000_000.0]
        self.app = create_app(
            {
                "TESTING": True,
                "DATA_DIR": self.tmp.name,
                "CLOCK": lambda: self.tempo[0],
                "SCANNER_TYPE": "nenhum",
            }
        )
        self.client = self.app.test_client()
        self.nome = "amy"
        self.senha = "Q7!m2#L9?"
        self.uid = criar_usuario(self.app, self.nome, self.senha, "atendente")

    def tearDown(self):
        self.tmp.cleanup()

    def test_limites_senha_no_cadastro(self):
        for tamanho in (8, 129):
            with self.subTest(tamanho=tamanho), self.assertRaises(ValueError):
                criar_usuario(self.app, "limite", "x" * tamanho, "atendente")
        with self.db() as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM usuarios").fetchone()[0], 1
            )
        for tamanho in (9, 128):
            with self.subTest(tamanho=tamanho):
                senha = "x" * tamanho
                uid = criar_usuario(self.app, f"limite{tamanho}", senha, "atendente")
                with self.db() as db:
                    usuario = db.execute(
                        "SELECT * FROM usuarios WHERE id=?", (uid,)
                    ).fetchone()
                self.assertTrue(HASHER.verify(usuario["senha_hash"], senha))
                self.assertIsNone(usuario["segredo_2fa"])

    @contextmanager
    def db(self):
        with closing(sqlite3.connect(self.app.database_path)) as db, db:
            db.row_factory = sqlite3.Row
            yield db

    def csrf(self, response):
        match = re.search(rb'name="csrf"\s+value="([^"]+)"', response.data)
        self.assertIsNotNone(match, response.status_code)
        return match.group(1).decode()

    def sessao(self, client):
        with self.db() as db:
            return db.execute(
                "SELECT * FROM sessoes WHERE token_hash=?",
                (digest(client.get_cookie(COOKIE).value),),
            ).fetchone()

    def entrar_senha(self, client=None, senha=None, nome=None):
        client = client or self.client
        tela = client.get("/login")
        response = client.post(
            "/login",
            data={
                "csrf": self.csrf(tela),
                "nome": nome or self.nome,
                "senha": senha or self.senha,
            },
        )
        return response

    def configurar(self, client=None):
        client = client or self.client
        self.assertEqual(self.entrar_senha(client).location, "/configurar-2fa")
        segredo = self.app.fernet.decrypt(
            self.sessao(client)["segredo_inicial"].encode()
        ).decode()
        tela = client.get("/configurar-2fa")
        codigo = pyotp.TOTP(segredo).at(self.tempo[0])
        resposta = client.post(
            "/configurar-2fa", data={"csrf": self.csrf(tela), "codigo": codigo}
        )
        self.assertEqual(resposta.location, "/codigos-recuperacao")
        recuperacao = client.get("/codigos-recuperacao")
        codigos = re.findall(rb"<code>\s*([0-9a-f]{32})\s*</code>", recuperacao.data)
        self.assertEqual(len(codigos), 10)
        return segredo, [c.decode() for c in codigos]

    def sair(self, client=None):
        client = client or self.client
        return client.post("/sair", data={"csrf": self.csrf(client.get("/painel"))})

    def autenticar_existente(self, segredo, client=None, codigo=None):
        client = client or self.client
        self.assertEqual(self.entrar_senha(client).location, "/segundo-fator")
        tela = client.get("/segundo-fator")
        return client.post(
            "/segundo-fator",
            data={
                "csrf": self.csrf(tela),
                "codigo": codigo or pyotp.TOTP(segredo).at(self.tempo[0]),
            },
        )

    def test_senha_sozinha_nao_libera_acesso(self):
        self.entrar_senha()
        for caminho in (
            "/painel",
            "/api/permissoes",
            "/administracao",
            "/codigos-recuperacao",
        ):
            self.assertEqual(self.client.get(caminho).status_code, 302)
        self.assertEqual(self.sessao(self.client)["etapa"], "configuracao")

    def test_configuracao_exige_prova_do_segundo_fator(self):
        self.entrar_senha()
        tela = self.client.get("/configurar-2fa")
        self.assertEqual(
            self.client.post(
                "/configurar-2fa", data={"csrf": self.csrf(tela), "codigo": "abcdef"}
            ).status_code,
            401,
        )
        self.assertEqual(self.client.get("/painel").status_code, 302)
        self.assertEqual(self.client.get("/qr-2fa.svg").status_code, 200)

    def test_login_completo_e_perfil(self):
        self.configurar()
        self.assertEqual(self.client.get("/painel").status_code, 200)
        dados = self.client.get("/api/permissoes").json
        self.assertEqual(dados["perfil"], "atendente")
        self.assertEqual(set(dados["permissoes"]), {"ler", "enviar"})

    def test_senha_e_totp_em_acessos_seguintes(self):
        segredo, _ = self.configurar()
        self.sair()
        self.tempo[0] += 31
        self.assertEqual(self.autenticar_existente(segredo).location, "/painel")
        self.assertEqual(self.client.get("/painel").status_code, 200)

    def test_codigo_da_configuracao_nao_pode_ser_reutilizado(self):
        segredo, _ = self.configurar()
        self.sair()
        self.assertEqual(self.autenticar_existente(segredo).status_code, 401)
        self.assertEqual(self.client.get("/painel").status_code, 302)

    def test_totp_usado_nao_pode_ser_repetido_em_outro_navegador(self):
        segredo, _ = self.configurar()
        self.sair()
        self.tempo[0] += 31
        self.assertEqual(self.autenticar_existente(segredo).status_code, 302)
        outro = self.app.test_client()
        self.assertEqual(self.autenticar_existente(segredo, outro).status_code, 401)

    def test_totp_expirado_e_rejeitado(self):
        segredo, _ = self.configurar()
        self.sair()
        antigo = pyotp.TOTP(segredo).at(self.tempo[0] + 31)
        self.tempo[0] += 150
        self.assertEqual(
            self.autenticar_existente(segredo, codigo=antigo).status_code, 401
        )

    def test_pequena_diferenca_de_relogio_e_aceita(self):
        segredo, _ = self.configurar()
        self.sair()
        self.tempo[0] += 90
        anterior = pyotp.TOTP(segredo).at(self.tempo[0] - 30)
        self.assertEqual(
            self.autenticar_existente(segredo, codigo=anterior).status_code, 302
        )

    def test_recuperacao_e_de_uso_unico_e_exige_senha(self):
        segredo, codigos = self.configurar()
        self.sair()
        self.assertEqual(
            self.autenticar_existente(segredo, codigo=codigos[0]).status_code, 302
        )
        outro = self.app.test_client()
        self.assertEqual(
            self.autenticar_existente(segredo, outro, codigos[0]).status_code, 401
        )
        with self.db() as db:
            self.assertEqual(
                db.execute(
                    "SELECT count(*) FROM recuperacao WHERE usuario_id=?", (self.uid,)
                ).fetchone()[0],
                9,
            )

    def test_codigos_de_recuperacao_exibidos_uma_vez(self):
        self.configurar()
        tela = self.client.get("/codigos-recuperacao")
        self.assertEqual(tela.status_code, 200)
        self.client.post(
            "/codigos-recuperacao/confirmar", data={"csrf": self.csrf(tela)}
        )
        self.assertEqual(self.client.get("/codigos-recuperacao").location, "/painel")

    def test_falta_de_csrf_no_login(self):
        self.client.get("/login")
        self.assertEqual(
            self.client.post(
                "/login", data={"nome": self.nome, "senha": self.senha}
            ).status_code,
            400,
        )

    def test_csrf_invalido_na_confirmacao(self):
        self.entrar_senha()
        self.assertEqual(
            self.client.post(
                "/configurar-2fa", data={"csrf": "falso", "codigo": "123456"}
            ).status_code,
            400,
        )
        self.assertEqual(self.client.get("/painel").status_code, 302)

    def test_bloqueio_temporario_apos_cinco_falhas(self):
        for _ in range(5):
            self.assertEqual(self.entrar_senha(senha="incorreta").status_code, 401)
        self.assertEqual(self.entrar_senha().status_code, 401)
        self.tempo[0] += 301
        self.assertEqual(self.entrar_senha().location, "/configurar-2fa")

    def test_limite_de_tentativas_por_ip(self):
        for _ in range(30):
            self.assertEqual(self.entrar_senha(nome="inexistente").status_code, 401)
        self.assertEqual(self.entrar_senha(nome="inexistente").status_code, 429)

    def test_perfil_administrativo_nao_pode_ser_enviado_pelo_cliente(self):
        tela = self.client.get("/login")
        self.client.post(
            "/login",
            data={
                "csrf": self.csrf(tela),
                "nome": self.nome,
                "senha": self.senha,
                "perfil": "administrador",
            },
        )
        with self.db() as db:
            self.assertEqual(
                db.execute(
                    "SELECT perfil FROM usuarios WHERE id=?", (self.uid,)
                ).fetchone()[0],
                "atendente",
            )

    def test_atendente_nao_acessa_administracao(self):
        self.configurar()
        self.assertEqual(self.client.get("/administracao").status_code, 403)

    def test_administrador_acessa_registros(self):
        with self.db() as db:
            db.execute(
                "UPDATE usuarios SET perfil='administrador' WHERE id=?", (self.uid,)
            )
        self.configurar()
        resposta = self.client.get("/administracao")
        self.assertEqual(resposta.status_code, 200)
        self.assertIn(b"login_concluido", resposta.data)

    def test_mudanca_de_perfil_tem_efeito_na_sessao_atual(self):
        with self.db() as db:
            db.execute(
                "UPDATE usuarios SET perfil='administrador' WHERE id=?", (self.uid,)
            )
        self.configurar()
        with self.db() as db:
            db.execute("UPDATE usuarios SET perfil='atendente' WHERE id=?", (self.uid,))
        self.assertEqual(self.client.get("/administracao").status_code, 403)

    def test_conta_desativada_perde_a_sessao(self):
        self.configurar()
        with self.db() as db:
            db.execute("UPDATE usuarios SET ativo=0 WHERE id=?", (self.uid,))
        self.assertEqual(self.client.get("/painel").status_code, 302)

    def test_sessao_antiga_e_invalidada_apos_2fa(self):
        self.entrar_senha()
        antiga = self.client.get_cookie(COOKIE).value
        segredo = self.app.fernet.decrypt(
            self.sessao(self.client)["segredo_inicial"].encode()
        ).decode()
        tela = self.client.get("/configurar-2fa")
        self.client.post(
            "/configurar-2fa",
            data={
                "csrf": self.csrf(tela),
                "codigo": pyotp.TOTP(segredo).at(self.tempo[0]),
            },
        )
        self.assertNotEqual(antiga, self.client.get_cookie(COOKIE).value)
        self.client.set_cookie(COOKIE, antiga)
        self.assertEqual(self.client.get("/painel").status_code, 302)

    def test_expiracao_por_inatividade(self):
        self.configurar()
        self.tempo[0] += 901
        self.assertEqual(self.client.get("/painel").status_code, 302)

    def test_expiracao_da_etapa_pendente(self):
        self.entrar_senha()
        self.tempo[0] += 301
        self.assertEqual(self.client.get("/configurar-2fa").location, "/login")

    def test_logout_invalida_cookie_e_sessao(self):
        self.configurar()
        antigo = self.client.get_cookie(COOKIE).value
        self.assertEqual(self.sair().status_code, 302)
        self.client.set_cookie(COOKIE, antigo)
        self.assertEqual(self.client.get("/painel").status_code, 302)

    def test_rede_nao_autorizada_e_negada(self):
        self.assertEqual(
            self.client.get(
                "/login", environ_overrides={"REMOTE_ADDR": "203.0.113.8"}
            ).status_code,
            403,
        )

    def test_cabecalho_de_ip_nao_burla_restricao_direta(self):
        self.assertEqual(
            self.client.get(
                "/login",
                headers={"X-Forwarded-For": "127.0.0.1"},
                environ_overrides={"REMOTE_ADDR": "203.0.113.8"},
            ).status_code,
            403,
        )

    def test_host_desconhecido_e_rejeitado(self):
        self.assertEqual(
            self.client.get("/login", headers={"Host": "outro.exemplo"}).status_code,
            400,
        )

    def test_sql_injection_nao_altera_a_consulta(self):
        self.assertEqual(self.entrar_senha(nome="' OR 1=1 --").status_code, 401)
        self.assertEqual(self.client.get("/painel").status_code, 302)

    def test_senha_e_segredo_nao_ficam_em_texto_puro(self):
        segredo, codigos = self.configurar()
        with self.db() as db:
            usuario = db.execute(
                "SELECT * FROM usuarios WHERE id=?", (self.uid,)
            ).fetchone()
            self.assertTrue(usuario["senha_hash"].startswith("$argon2id$"))
            self.assertNotIn(self.senha, usuario["senha_hash"])
            self.assertNotIn(segredo, usuario["segredo_2fa"])
            armazenado = db.execute(
                "SELECT codigo_hash FROM recuperacao WHERE usuario_id=?", (self.uid,)
            ).fetchone()[0]
            self.assertNotIn(armazenado, codigos)
            eventos = str([tuple(x) for x in db.execute("SELECT * FROM auditoria")])
            self.assertNotIn(segredo, eventos)
            self.assertNotIn(self.senha, eventos)

    def test_modo_rede_http_preserva_httponly_samesite_e_acl(self):
        rede = create_app(
            {
                "TESTING": True,
                "DATA_DIR": self.tmp.name,
                "CLOCK": lambda: self.tempo[0],
                "ALLOWED_NETWORKS": ["127.0.0.0/8", "192.168.1.0/24"],
            }
        )
        client = rede.test_client()
        resposta = client.get(
            "/login",
            base_url="http://localhost",
            environ_overrides={"REMOTE_ADDR": "192.168.1.10"},
        )
        self.assertEqual(resposta.status_code, 200)
        self.assertNotIn("Secure", resposta.headers["Set-Cookie"])
        self.assertIn("HttpOnly", resposta.headers["Set-Cookie"])
        self.assertIn("SameSite=Lax", resposta.headers["Set-Cookie"])
        self.assertEqual(
            client.get(
                "/login", environ_overrides={"REMOTE_ADDR": "172.20.1.10"}
            ).status_code,
            403,
        )


if __name__ == "__main__":
    unittest.main()
