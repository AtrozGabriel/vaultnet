"""Servidor HTTP direto com Waitress, sem confiar em cabeçalhos de proxy."""

import http.client
import ipaddress
import re
import threading
import time

from waitress import create_server


def validar_host(host):
    host = host.strip().lower()
    if len(host) > 253 or not all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", parte)
        for parte in host.split(".")
    ):
        raise ValueError(
            "Informe somente o nome ou IPv4 do servidor, sem protocolo ou porta."
        )
    return host


def _aguardar_http(thread, host, porta, prazo=10):
    fim = time.monotonic() + prazo
    while time.monotonic() < fim:
        if not thread.is_alive():
            raise RuntimeError("O servidor HTTP encerrou durante a preparação.")
        conexao = http.client.HTTPConnection(host, porta, timeout=0.5)
        try:
            conexao.request("HEAD", "/static/favicon.svg")
            resposta = conexao.getresponse()
            resposta.read()
            if resposta.status == 200:
                return
        except OSError:
            pass
        finally:
            conexao.close()
        time.sleep(0.1)
    raise RuntimeError(
        "O servidor HTTP não ficou disponível. Confira a porta e o endereço."
    )


def servir_http(
    app, porta=8080, host="0.0.0.0", host_login="127.0.0.1", ao_iniciar=None, proxy_cloudflare=False
):
    if not 1 <= porta <= 65535:
        raise ValueError("Informe uma porta de 1 a 65535.")
    host_login = validar_host(host_login)
    endereco_escuta = ipaddress.ip_address(host)
    from acesso_rede import canal_local
    servidor = create_server(
        canal_local(app, "tunel" if proxy_cloudflare else "local"),
        host="127.0.0.1" if proxy_cloudflare else str(endereco_escuta),
        port=porta,
        threads=4,
        trusted_proxy="127.0.0.1" if proxy_cloudflare else None,
        trusted_proxy_headers={"x-forwarded-proto"} if proxy_cloudflare else set(),
        clear_untrusted_proxy_headers=True,
        url_scheme="http",
        expose_tracebacks=False,
        max_request_body_size=app.config["MAX_FILE_SIZE"] + 65536,
    )
    servidores = [servidor]
    if proxy_cloudflare:
        try:
            servidores.append(create_server(
                canal_local(app, "local"), host="0.0.0.0", port=8081, threads=4,
                trusted_proxy=None, clear_untrusted_proxy_headers=True,
                expose_tracebacks=False, max_request_body_size=app.config["MAX_FILE_SIZE"] + 65536))
        except BaseException:
            servidor.close(); servidor.task_dispatcher.shutdown()
            raise
    threads = [threading.Thread(target=s.run, daemon=True) for s in servidores]
    try:
        for thread in threads: thread.start()
        local_porta = 8081 if proxy_cloudflare else porta
        endereco = f"http://{host_login}:{local_porta}"
        print(f"Acesso neste computador: {endereco}/login", flush=True)
        if proxy_cloudflare:
            print("Rede local: http://IP_DO_SERVIDOR:8081/login", flush=True)
            print("Cloudflare: mantenha o serviço apontado para http://127.0.0.1:8080", flush=True)
        print("Mantenha esta janela aberta; Ctrl+C encerra o sistema.", flush=True)
        if ao_iniciar:
            _aguardar_http(threads[-1], host_login, local_porta)
            ao_iniciar(endereco)
        while all(t.is_alive() for t in threads): time.sleep(0.2)
    finally:
        for s in servidores:
            s.close(); s.task_dispatcher.shutdown()
        for thread in threads:
            if thread.ident is not None: thread.join(timeout=3)
