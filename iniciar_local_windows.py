"""Servidor de desenvolvimento Windows com dados separados e escuta local."""
import os
from pathlib import Path
import sys

RAIZ = Path(__file__).resolve().parent
sys.path.insert(0, str(RAIZ))


def main():
    if os.name != "nt":
        print("Use INICIAR_LOCAL.bat em um computador Windows.")
        return 1
    from iniciar_windows import instancia_unica, oferecer_cadastro_administrador, abrir_http
    from app import create_app
    from servidor import servir_http
    try:
        with instancia_unica(RAIZ):
            app = create_app({"DATA_DIR": str(RAIZ / "dados_local"),
                              "ALLOWED_NETWORKS": ["127.0.0.0/8", "::1/128"],
                              "TRUSTED_HOSTS": ["127.0.0.1", "localhost"],
                              "SCANNER_TYPE": "auto"})
            print("DESENVOLVIMENTO LOCAL — dados em dados_local.", flush=True)
            print("Endereco: http://127.0.0.1:8090/login", flush=True)
            print("Uploads usam o Microsoft Defender quando disponivel.", flush=True)
            oferecer_cadastro_administrador(app)
            servir_http(app, porta=8090, host="127.0.0.1", host_login="127.0.0.1",
                        ao_iniciar=abrir_http, proxy_cloudflare=False)
        return 0
    except (KeyboardInterrupt, EOFError):
        print("Servidor local encerrado.")
        return 0
    except Exception as erro:
        print("Nao foi possivel iniciar: " + str(erro), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
