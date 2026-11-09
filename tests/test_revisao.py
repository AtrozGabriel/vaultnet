"""Regressões de configuração e de validação de documentos encontradas na revisão."""

import io
import struct
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest.mock import patch

from flask import Flask

from app import create_app
from arquivos import validar_conteudo, validar_nome

PROJECT = Path(__file__).resolve().parents[1]


class PastaPrivadaTests(unittest.TestCase):
    def test_dados_publicos_sao_recusados_antes_de_criar_chaves(self):
        with tempfile.TemporaryDirectory() as tmp:
            publicos = Path(tmp) / "static"
            publicos.mkdir()
            for dados in (publicos, publicos / "dados"):
                with (
                    self.subTest(dados=dados),
                    patch(
                        "app.Flask",
                        side_effect=lambda nome: Flask(
                            nome, static_folder=str(publicos), root_path=str(PROJECT)
                        ),
                    ),
                    self.assertRaisesRegex(ValueError, "arquivos são públicos"),
                ):
                    create_app({"DATA_DIR": str(dados), "SCANNER_TYPE": "nenhum"})
                self.assertFalse((dados / "chave_2fa.key").exists())
                self.assertFalse((dados / "login.sqlite3").exists())

    def test_caminho_normalizado_tambem_nao_pode_apontar_para_static(self):
        with tempfile.TemporaryDirectory() as tmp:
            publicos = Path(tmp) / "static"
            publicos.mkdir()
            dados = publicos / ".." / "static" / "dados"
            with (
                patch(
                    "app.Flask",
                    side_effect=lambda nome: Flask(
                        nome, static_folder=str(publicos), root_path=str(PROJECT)
                    ),
                ),
                self.assertRaises(ValueError),
            ):
                create_app({"DATA_DIR": str(dados), "SCANNER_TYPE": "nenhum"})
            self.assertFalse((publicos / "dados").exists())


class IntegridadeOfficeTests(unittest.TestCase):
    def documento(self, extensao="docx", compressao=zipfile.ZIP_STORED, extras=()):
        parte = {
            "docx": "word/document.xml",
            "xlsx": "xl/workbook.xml",
            "pptx": "ppt/presentation.xml",
        }[extensao]
        buffer = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(buffer, "w", compressao) as z:
                z.writestr("[Content_Types].xml", "<Types/>")
                z.writestr(parte, "<document/>")
                for nome, conteudo in extras:
                    z.writestr(nome, conteudo)
        return buffer.getvalue()

    def adulterar(self, dados, cabecalho=False):
        dados = bytearray(dados)
        with zipfile.ZipFile(io.BytesIO(dados)) as z:
            item = z.getinfo("word/document.xml")
        pos = item.header_offset
        tamanho_nome, tamanho_extra = struct.unpack_from("<HH", dados, pos + 26)
        if cabecalho:
            dados[pos + 30] = ord("x")
        else:
            dados[pos + 30 + tamanho_nome + tamanho_extra] ^= 1
        return bytes(dados)

    def test_office_valido_armazenado_e_deflate_continuam_aceitos(self):
        for extensao in ("docx", "xlsx", "pptx"):
            for compressao in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                with self.subTest(extensao=extensao, compressao=compressao):
                    validar_conteudo(self.documento(extensao, compressao), extensao)

    def test_crc_corrompido_e_recusado(self):
        with self.assertRaisesRegex(ValueError, "validar este documento"):
            validar_conteudo(self.adulterar(self.documento()), "docx")

    def test_nome_no_cabecalho_local_divergente_e_recusado(self):
        with self.assertRaisesRegex(ValueError, "validar este documento"):
            validar_conteudo(self.adulterar(self.documento(), cabecalho=True), "docx")

    def test_nomes_duplicados_ou_diferentes_so_em_caixa_sao_recusados(self):
        for nome in ("word/document.xml", "word/Document.xml"):
            with (
                self.subTest(nome=nome),
                self.assertRaisesRegex(ValueError, "duplicados"),
            ):
                validar_conteudo(self.documento(extras=[(nome, "<outro/>")]), "docx")

    def test_compressao_que_nao_faz_parte_da_politica_e_recusada(self):
        dados = self.documento(compressao=zipfile.ZIP_BZIP2)
        with self.assertRaisesRegex(ValueError, "estrutura não permitida"):
            validar_conteudo(dados, "docx")


class NomeCompativelTests(unittest.TestCase):
    def test_nomes_reservados_do_windows_sao_recusados(self):
        for nome in (
            "CON.txt",
            "nul.csv",
            "PRN.pdf",
            "AUX.png",
            "COM1.txt",
            "LPT9.txt",
            "COM¹.txt",
            "NUL.tar.txt",
            "CON .txt",
        ):
            with (
                self.subTest(nome=nome),
                self.assertRaisesRegex(ValueError, "reservado pelo Windows"),
            ):
                validar_nome(nome)

    def test_nomes_comuns_e_com_acentos_continuam_aceitos(self):
        for nome in ("Contrato.pdf", "relatório.txt", "COM10.txt", "Auxiliar.csv"):
            with self.subTest(nome=nome):
                self.assertEqual(validar_nome(nome)[0], nome)


if __name__ == "__main__":
    unittest.main()
