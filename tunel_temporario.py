"""Quick Tunnel para o servidor local, sem alterar tuneis fixos existentes."""

import os
import re
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path


def localizar_cloudflared(projeto):
    def procurar():
        candidatos = [
            Path(projeto) / "cloudflared.exe",
            Path(projeto) / "cloudflared-windows-amd64.exe",
            shutil.which("cloudflared"),
            Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft/WinGet/Links/cloudflared.exe",
            Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "cloudflared/cloudflared.exe",
            Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "cloudflared/cloudflared.exe",
        ]
        for candidato in candidatos:
            if candidato and Path(candidato).is_file():
                return str(Path(candidato).resolve())
        return None

    existente = procurar()
    if existente:
        return existente
    winget = shutil.which("winget")
    if winget:
        print("Instalando cloudflared pelo WinGet...", flush=True)
        resultado = subprocess.run(
            [winget, "install", "--exact", "--id", "Cloudflare.cloudflared",
             "--source", "winget", "--accept-source-agreements",
             "--accept-package-agreements", "--disable-interactivity"],
            check=False,
        )
        existente = procurar()
        if resultado.returncode == 0 and existente:
            return existente
    raise RuntimeError(
        "Instale cloudflared (winget install --id Cloudflare.cloudflared -e) "
        "e reabra o BAT. Ou coloque cloudflared.exe na pasta do projeto. "
        "Download oficial: https://developers.cloudflare.com/tunnel/downloads/"
    )


class TunelTemporario:
    def __init__(self, executavel):
        self.executavel = executavel
        self.processo = None
        self.temporario = None
        self.leitor = None
        self.encerrando = threading.Event()

    def __enter__(self):
        self.temporario = tempfile.TemporaryDirectory(prefix="vaultnet-tunel-")
        # Configuracao explicita isolada: nao usa nem altera o tunel fixo.
        self.config = Path(self.temporario.name) / "config.yml"
        self.config.write_text("{}\n", encoding="utf-8")
        return self

    def iniciar(self):
        print("\nAbrindo tunel temporario. Aguarde o LINK PUBLICO abaixo...", flush=True)
        self.processo = subprocess.Popen(
            [self.executavel, "tunnel", "--config", str(self.config),
             "--url", "http://127.0.0.1:8080", "--no-autoupdate"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace",
        )
        self.leitor = threading.Thread(target=self._ler_saida, daemon=True)
        self.leitor.start()

    def _ler_saida(self):
        publicado = False
        for linha in self.processo.stdout:
            print(linha.rstrip(), flush=True)
            link = re.search(r"https://[a-z0-9-]+\.trycloudflare\.com\b", linha)
            if link and not publicado:
                publicado = True
                print("\nLINK PUBLICO: " + link.group(0) + "/login", flush=True)
                print("Compartilhe esse link. Mantenha esta janela aberta.\n", flush=True)
        if not self.encerrando.is_set():
            print("\nO tunel encerrou. O sistema local continua aberto. "
                  "Confira o erro acima; use Ctrl+C e reabra o BAT para tentar novamente.", flush=True)

    def __exit__(self, *exc):
        self.encerrando.set()
        try:
            if self.processo and self.processo.poll() is None:
                self.processo.terminate()
                try:
                    self.processo.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.processo.kill()
                    self.processo.wait(timeout=5)
            if self.leitor:
                self.leitor.join(timeout=2)
            if self.processo and self.processo.stdout:
                self.processo.stdout.close()
        finally:
            if self.temporario:
                self.temporario.cleanup()
