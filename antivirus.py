"""Scanners locais: ClamAV e Microsoft Defender, com liberação somente após sucesso."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

SCANNERS_VERIFICADOS = {"clamav", "defender"}
ESTADO_DEFENDER = (
    "$ErrorActionPreference='Stop'; "
    "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); "
    "Get-MpComputerStatus | Select-Object AMRunningMode,AMServiceEnabled,"
    "AntivirusEnabled,AntivirusSignatureVersion,DefenderSignaturesOutOfDate "
    "| ConvertTo-Json -Compress"
)


class ErroAntivirus(Exception):
    def __init__(self, mensagem, rejeitado=False):
        super().__init__(mensagem)
        self.rejeitado = rejeitado


def windows():
    return sys.platform == "win32"


def encontrar_defender():
    if not windows():
        return None
    base = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
    plataforma = base / "Microsoft" / "Windows Defender" / "Platform"
    candidatos = []
    if plataforma.is_dir():
        for pasta in plataforma.iterdir():
            if re.fullmatch(r"\d+(?:\.\d+){3}(?:-\d+)?", pasta.name):
                exe = pasta / "MpCmdRun.exe"
                if exe.is_file():
                    versao = tuple(int(x) for x in re.split(r"[.-]", pasta.name))
                    candidatos.append((versao, exe))
    if candidatos:
        return max(candidatos, key=lambda item: item[0])[1].resolve()
    exe = (
        Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
        / "Windows Defender"
        / "MpCmdRun.exe"
    )
    return exe.resolve() if exe.is_file() else None


def configurar_scanner(config):
    tipo = config["SCANNER_TYPE"]
    caminho = config["SCANNER_PATH"]
    if tipo not in {"auto", "clamav", "defender", "nenhum"}:
        raise ValueError("Antivírus inválido. Use auto, defender, clamav ou nenhum.")
    if config["ALLOW_UNSCANNED_UPLOADS"]:
        if caminho or tipo not in {"auto", "nenhum"}:
            raise ValueError("Escolha o antivírus ou a demonstração sem antivírus.")
        tipo = "nenhum"
    if tipo == "nenhum":
        if caminho:
            raise ValueError(
                "O modo sem scanner não aceita um executável de antivírus."
            )
        config.update(SCANNER_ENGINE="nenhum", SCANNER_PATH=None)
        return
    if caminho:
        exe = Path(caminho).resolve()
        nomes = {
            "clamscan": "clamav",
            "clamscan.exe": "clamav",
            "mpcmdrun.exe": "defender",
        }
        engine = nomes.get(exe.name.lower())
        if not exe.is_file() or not engine or tipo not in {"auto", engine}:
            raise ValueError("O executável não corresponde ao antivírus escolhido.")
    elif tipo in {"auto", "defender"}:
        exe = encontrar_defender()
        engine = "defender" if exe else "nenhum"
        if tipo == "defender" and not exe:
            raise ValueError("O Microsoft Defender não foi encontrado neste Windows.")
    else:
        raise ValueError("Informe --antivirus com o caminho do clamscan.")
    if engine == "defender":
        if not windows():
            raise ValueError("O Microsoft Defender deste projeto exige Windows.")
        powershell = (
            Path(os.environ.get("SystemRoot", r"C:\Windows"))
            / "System32"
            / "WindowsPowerShell"
            / "v1.0"
            / "powershell.exe"
        ).resolve()
        if not powershell.is_file():
            raise ValueError("Não foi possível localizar o Windows PowerShell.")
        config["DEFENDER_POWERSHELL"] = str(powershell)
    config.update(SCANNER_ENGINE=engine, SCANNER_PATH=str(exe) if exe else None)


def verificar_estado_defender(config):
    try:
        resultado = subprocess.run(
            [
                config["DEFENDER_POWERSHELL"],
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                ESTADO_DEFENDER,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=8,
            check=False,
            shell=False,
            encoding="utf-8-sig",
        )
        if resultado.returncode != 0:
            raise ValueError("Consulta não concluída.")
        estado = json.loads(resultado.stdout)
        if (
            not isinstance(estado, dict)
            or estado.get("AMRunningMode") != "Normal"
            or estado.get("AMServiceEnabled") is not True
            or estado.get("AntivirusEnabled") is not True
            or estado.get("DefenderSignaturesOutOfDate") is not False
            or not re.fullmatch(
                r"\d+(?:\.\d+){3}", estado.get("AntivirusSignatureVersion", "")
            )
            # Versão de assinatura ausente; não é um endereço de escuta.
            or estado["AntivirusSignatureVersion"] == "0.0.0.0"  # nosec B104
        ):
            raise ValueError("Defender não está pronto.")
    except (
        OSError,
        subprocess.TimeoutExpired,
        ValueError,
        TypeError,
        UnicodeError,
    ) as erro:
        raise ErroAntivirus(
            "O Microsoft Defender não está pronto para verificar arquivos. "
            "Confira o antivírus e as atualizações na Segurança do Windows. "
            "Se o problema continuar, contate o responsável pelo servidor."
        ) from erro


def analisar_arquivo(caminho, dados, config):
    # Executáveis e comandos são definidos pelo servidor, nunca pelos dados de um formulário.
    engine = config["SCANNER_ENGINE"]
    scanner = config["SCANNER_PATH"]
    if engine not in SCANNERS_VERIFICADOS or not scanner:
        raise ErroAntivirus("O antivírus não está configurado para verificar arquivos.")
    if engine == "defender":
        verificar_estado_defender(config)
        comando = [
            scanner,
            "-Scan",
            "-ScanType",
            "3",
            "-File",
            str(caminho),
            "-DisableRemediation",
        ]
    else:
        comando = [
            scanner,
            "--no-summary",
            "--max-filesize=10M",
            "--max-scansize=30M",
            "--max-files=1000",
            "--alert-exceeds-max=yes",
            "--alert-encrypted=yes",
            "--",
            str(caminho),
        ]
    try:
        resultado = subprocess.run(
            comando,
            timeout=30,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            shell=False,
        )
        if engine == "defender" and resultado.returncode == 2:
            # O código 2 também pode significar erro; nunca o apresentar como prova de malware.
            raise ErroAntivirus(
                "O Microsoft Defender não aprovou este arquivo. O envio foi cancelado.",
                rejeitado=True,
            )
        if engine != "defender" and resultado.returncode == 1:
            raise ErroAntivirus(
                "O antivírus rejeitou este arquivo. O envio foi cancelado.",
                rejeitado=True,
            )
        if resultado.returncode != 0:
            raise ErroAntivirus(
                "O antivírus não concluiu a verificação. Nenhum arquivo foi liberado."
            )
        # Um resultado limpo não aprova o original se o scanner o removeu ou modificou.
        with caminho.open("rb") as origem:
            if origem.read(len(dados) + 1) != dados:
                raise ErroAntivirus(
                    "O arquivo foi alterado durante a verificação. O envio foi cancelado."
                )
        return engine
    except (OSError, subprocess.TimeoutExpired) as erro:
        raise ErroAntivirus(
            "O antivírus está indisponível. Nenhum arquivo foi liberado."
        ) from erro
