"""Inicialização Linux: Cloudflare em 8080 e manutenção por SSH em 8081."""
import signal
import threading
from pathlib import Path
from app import create_app
from acesso_rede import canal_local
from antivirus import analisar_arquivo
from waitress import create_server
import tempfile


def main():
    raiz = Path(__file__).resolve().parent
    app = create_app({"DATA_DIR": str(raiz / "dados"),
                      "SCANNER_TYPE": "clamav", "SCANNER_PATH": "/usr/bin/clamscan",
                      "ALLOW_UNSCANNED_UPLOADS": False})
    with tempfile.TemporaryDirectory(dir=app.config["DATA_DIR"]) as pasta:
        caminho = Path(pasta) / "teste.txt"
        dados = b"VaultNet: verificacao de inicializacao.\n"
        caminho.write_bytes(dados)
        analisar_arquivo(caminho, dados, app.config)
    servidores = []
    threads = []
    parar = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: parar.set())
    try:
        for porta, canal in ((8080, "tunel"), (8081, "local")):
            servidor = create_server(
                canal_local(app, canal), host="127.0.0.1", port=porta, threads=4,
                trusted_proxy="127.0.0.1" if canal == "tunel" else None,
                trusted_proxy_headers={"x-forwarded-proto"} if canal == "tunel" else set(),
                clear_untrusted_proxy_headers=True, expose_tracebacks=False,
                max_request_body_size=app.config["MAX_FILE_SIZE"] + 65536)
            servidores.append(servidor)
        for servidor in servidores:
            thread = threading.Thread(target=servidor.run, daemon=True)
            thread.start()
            threads.append(thread)
        print("VaultNet pronto. Cloudflare: http://127.0.0.1:8080", flush=True)
        while not parar.wait(0.5):
            if not all(t.is_alive() for t in threads):
                raise RuntimeError("Servidor HTTP encerrou inesperadamente.")
    finally:
        for servidor in servidores:
            servidor.close()
            servidor.task_dispatcher.shutdown()

if __name__ == "__main__":
    main()
