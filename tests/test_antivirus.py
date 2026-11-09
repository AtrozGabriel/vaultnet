"""Integração do Defender: detecção de instalação e falha impedindo a liberação."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from antivirus import (
    ErroAntivirus,
    analisar_arquivo,
    configurar_scanner,
    encontrar_defender,
)

ESTADO_PRONTO = {
    "AMRunningMode": "Normal",
    "AMServiceEnabled": True,
    "AntivirusEnabled": True,
    "AntivirusSignatureVersion": "1.449.10.0",
    "DefenderSignaturesOutOfDate": False,
}


class AntivirusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.arquivo = self.root / "documento.tmp"
        self.dados = b"Documento para verificar a integracao."
        self.arquivo.write_bytes(self.dados)
        self.config = {
            "SCANNER_ENGINE": "defender",
            "SCANNER_PATH": "C:/Defender/MpCmdRun.exe",
            "DEFENDER_POWERSHELL": "C:/Windows/PowerShell/powershell.exe",
        }

    def resposta_estado(self, estado=None):
        return SimpleNamespace(returncode=0, stdout=json.dumps(estado or ESTADO_PRONTO))

    def test_auto_seleciona_a_plataforma_defender_mais_recente(self):
        base = self.root / "Microsoft/Windows Defender/Platform"
        for versao in ("4.18.26090.5-0", "4.18.26030.9-0", "nao-e-versao"):
            pasta = base / versao
            pasta.mkdir(parents=True)
            (pasta / "MpCmdRun.exe").touch()
        powershell = self.root / "System32/WindowsPowerShell/v1.0/powershell.exe"
        powershell.parent.mkdir(parents=True)
        powershell.touch()
        config = {
            "SCANNER_TYPE": "auto",
            "SCANNER_PATH": None,
            "ALLOW_UNSCANNED_UPLOADS": False,
        }
        with (
            patch("antivirus.windows", return_value=True),
            patch.dict(
                "os.environ",
                {"ProgramData": str(self.root), "SystemRoot": str(self.root)},
            ),
        ):
            configurar_scanner(config)
        self.assertEqual(config["SCANNER_ENGINE"], "defender")
        self.assertEqual(
            config["SCANNER_PATH"],
            str((base / "4.18.26090.5-0/MpCmdRun.exe").resolve()),
        )
        self.assertEqual(config["DEFENDER_POWERSHELL"], str(powershell.resolve()))

    def test_defender_usa_program_files_quando_nao_ha_plataforma(self):
        exe = self.root / "Windows Defender/MpCmdRun.exe"
        exe.parent.mkdir()
        exe.touch()
        with (
            patch("antivirus.windows", return_value=True),
            patch.dict(
                "os.environ",
                {"ProgramData": str(self.root), "ProgramFiles": str(self.root)},
            ),
        ):
            self.assertEqual(encontrar_defender(), exe.resolve())

    def test_auto_linux_mantem_envios_bloqueados_sem_scanner(self):
        config = {
            "SCANNER_TYPE": "auto",
            "SCANNER_PATH": None,
            "ALLOW_UNSCANNED_UPLOADS": False,
        }
        with patch("antivirus.windows", return_value=False):
            configurar_scanner(config)
        self.assertIsNone(config["SCANNER_PATH"])
        self.assertEqual(config["SCANNER_ENGINE"], "nenhum")

    def test_nao_aceita_executavel_diferente_do_scanner(self):
        exe = self.root / "outro.exe"
        exe.touch()
        config = {
            "SCANNER_TYPE": "auto",
            "SCANNER_PATH": str(exe),
            "ALLOW_UNSCANNED_UPLOADS": False,
        }
        with self.assertRaises(ValueError):
            configurar_scanner(config)
        exe = exe.rename(self.root / "clamscan.exe")
        config.update(SCANNER_TYPE="defender", SCANNER_PATH=str(exe))
        with self.assertRaises(ValueError):
            configurar_scanner(config)

    def test_demonstracao_nao_mistura_scanner_com_modo_sem_analise(self):
        for tipo, caminho in (("defender", None), ("auto", "clamscan")):
            with self.subTest(tipo=tipo), self.assertRaises(ValueError):
                configurar_scanner(
                    {
                        "SCANNER_TYPE": tipo,
                        "SCANNER_PATH": caminho,
                        "ALLOW_UNSCANNED_UPLOADS": True,
                    }
                )

    def test_defender_explicito_nao_e_habilitado_fora_do_windows(self):
        exe = self.root / "MpCmdRun.exe"
        exe.touch()
        with (
            patch("antivirus.windows", return_value=False),
            self.assertRaises(ValueError),
        ):
            configurar_scanner(
                {
                    "SCANNER_TYPE": "defender",
                    "SCANNER_PATH": str(exe),
                    "ALLOW_UNSCANNED_UPLOADS": False,
                }
            )

    def test_defender_aprova_somente_scan_customizado_concluido(self):
        with patch(
            "antivirus.subprocess.run",
            side_effect=[self.resposta_estado(), SimpleNamespace(returncode=0)],
        ) as executar:
            self.assertEqual(
                analisar_arquivo(self.arquivo, self.dados, self.config), "defender"
            )
        consulta, scan = executar.call_args_list
        self.assertIn("Get-MpComputerStatus", consulta.args[0][-1])
        self.assertNotIn(str(self.arquivo), consulta.args[0][-1])
        self.assertEqual(
            scan.args[0],
            [
                self.config["SCANNER_PATH"],
                "-Scan",
                "-ScanType",
                "3",
                "-File",
                str(self.arquivo),
                "-DisableRemediation",
            ],
        )
        self.assertFalse(scan.kwargs["shell"])
        self.assertEqual(scan.kwargs["timeout"], 30)

    def test_estado_inativo_passivo_desatualizado_ou_invalido_bloqueia_scan(self):
        estados = [
            {**ESTADO_PRONTO, "AMServiceEnabled": False},
            {**ESTADO_PRONTO, "AntivirusEnabled": False},
            {**ESTADO_PRONTO, "AMRunningMode": "Passive Mode"},
            {**ESTADO_PRONTO, "DefenderSignaturesOutOfDate": True},
            {**ESTADO_PRONTO, "AntivirusSignatureVersion": "0.0.0.0"},
            {},
            [],
            "json-invalido",
        ]
        for estado in estados:
            with self.subTest(estado=estado):
                with (
                    patch(
                        "antivirus.subprocess.run",
                        return_value=SimpleNamespace(
                            returncode=0, stdout=json.dumps(estado)
                        ),
                    ) as executar,
                    self.assertRaises(ErroAntivirus),
                ):
                    analisar_arquivo(self.arquivo, self.dados, self.config)
                self.assertEqual(executar.call_count, 1)

    def test_qualquer_retorno_nao_zero_do_defender_bloqueia_o_arquivo(self):
        for codigo in (1, 2, 3, -2147024891):
            with (
                self.subTest(codigo=codigo),
                patch(
                    "antivirus.subprocess.run",
                    side_effect=[
                        self.resposta_estado(),
                        SimpleNamespace(returncode=codigo),
                    ],
                ),
                self.assertRaises(ErroAntivirus),
            ):
                analisar_arquivo(self.arquivo, self.dados, self.config)

    def test_timeout_e_permissao_negada_bloqueiam_defender(self):
        for erro in (
            subprocess.TimeoutExpired("scanner", 30),
            PermissionError("sem acesso"),
        ):
            with (
                self.subTest(erro=type(erro).__name__),
                patch(
                    "antivirus.subprocess.run",
                    side_effect=[self.resposta_estado(), erro],
                ),
                self.assertRaises(ErroAntivirus),
            ):
                analisar_arquivo(self.arquivo, self.dados, self.config)

    def test_scan_zero_nao_aprova_original_modificado_ou_removido(self):
        for remover in (False, True):
            with self.subTest(remover=remover):
                self.arquivo.write_bytes(self.dados)

                def executar(comando, remover=remover, **kwargs):
                    if "-Command" in comando:
                        return self.resposta_estado()
                    if remover:
                        self.arquivo.unlink()
                    else:
                        self.arquivo.write_bytes(b"conteudo diferente")
                    return SimpleNamespace(returncode=0)

                with (
                    patch("antivirus.subprocess.run", side_effect=executar),
                    self.assertRaises(ErroAntivirus),
                ):
                    analisar_arquivo(self.arquivo, self.dados, self.config)
