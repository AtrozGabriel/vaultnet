"""Política persistente; o canal é marcado pelo servidor, nunca por cabeçalhos HTTP."""
import ipaddress
import json
import sqlite3
from pathlib import Path

PADRAO = {"modo": "internet", "redes": ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "fc00::/7"], "ips_publicos": []}
PRIVADAS = tuple(ipaddress.ip_network(x) for x in PADRAO["redes"])

def validar(modo, texto, texto_publicos=""):
    if modo not in {"internet", "local", "computador"}:
        raise ValueError("Escolha um modo de acesso válido.")
    itens = texto.replace(",", "\n").split()
    if len(texto) > 4096 or len(itens) > 32:
        raise ValueError("Use no máximo 32 sub-redes.")
    redes = []
    for item in itens:
        try:
            rede = ipaddress.ip_network(item, strict=False)
        except ValueError as erro:
            raise ValueError("Sub-rede inválida: " + item) from erro
        if not any(rede.version == base.version and rede.subnet_of(base) for base in PRIVADAS):
            raise ValueError("Use somente sub-redes privadas da sua rede local, sem faixas públicas ou /0.")
        if str(rede) not in redes: redes.append(str(rede))
    if modo == "local" and not redes:
        raise ValueError("Informe ao menos uma sub-rede local.")
    itens_publicos = texto_publicos.replace(",", "\n").split()
    if len(texto_publicos) > 4096 or len(itens_publicos) > 32:
        raise ValueError("Use no máximo 32 IPs públicos.")
    ips_publicos = []
    for item in itens_publicos:
        try:
            if "/" in item:
                rede = ipaddress.ip_network(item, strict=False)
                if rede.version != 6 or rede.prefixlen < 64 or not rede.network_address.is_global or not rede.broadcast_address.is_global or rede.network_address.is_multicast:
                    raise ValueError("Use faixas IPv6 públicas /64 ou mais específicas, pertencentes à empresa.")
                valor = str(rede)
            else:
                ip = ipaddress.ip_address(item)
                if ip.version == 6 and ip.ipv4_mapped: ip = ip.ipv4_mapped
                if not ip.is_global or ip.is_multicast:
                    raise ValueError("Use somente IPs públicos.")
                valor = str(ip)
        except ValueError as erro:
            raise ValueError("IP público ou faixa IPv6 inválida: " + item) from erro
        if valor not in ips_publicos: ips_publicos.append(valor)
    return {"modo": modo, "redes": redes, "ips_publicos": ips_publicos}

def carregar(db):
    row = db.execute("SELECT valor FROM configuracoes WHERE chave='politica_rede'").fetchone()
    if not row: return dict(PADRAO)
    try:
        dados = json.loads(row[0])
        return validar(dados["modo"], "\n".join(dados["redes"]), "\n".join(dados.get("ips_publicos", [])))
    except (ValueError, TypeError, KeyError):
        return {"modo": "computador", "redes": []}

def salvar(db, politica):
    db.execute("INSERT OR REPLACE INTO configuracoes(chave,valor) VALUES('politica_rede',?)", (json.dumps(politica),))

def permitido(politica, canal, endereco, ip_publico=None):
    try: ip = ipaddress.ip_address(endereco)
    except ValueError: return False
    if ip.version == 6 and ip.ipv4_mapped: ip = ip.ipv4_mapped
    if politica["modo"] == "internet": return True
    if canal == "tunel":
        if politica["modo"] != "local" or not ip.is_loopback or not ip_publico: return False
        try:
            visitante = ipaddress.ip_address(ip_publico)
            if visitante.version == 6 and visitante.ipv4_mapped: visitante = visitante.ipv4_mapped
        except ValueError: return False
        return visitante.is_global and not visitante.is_multicast and any(visitante in ipaddress.ip_network(item) for item in politica.get("ips_publicos", []))
    if canal != "local": return False
    if ip.is_loopback: return True
    if politica["modo"] == "computador": return False
    return any(ip in ipaddress.ip_network(rede) for rede in politica["redes"])

def canal_local(app, canal):
    def executar(environ, start_response):
        environ["vaultnet.canal"] = canal
        # Somente a conexão local do conector pode fornecer o IP do visitante.
        # Cabeçalhos com nomes parecidos nunca viram variáveis confiáveis.
        environ["vaultnet.ip_publico"] = None
        if canal == "tunel":
            try:
                peer = ipaddress.ip_address(environ.get("REMOTE_ADDR", ""))
                if peer.version == 6 and peer.ipv4_mapped: peer = peer.ipv4_mapped
                if peer.is_loopback:
                    visitante = ipaddress.ip_address(environ.get("HTTP_CF_CONNECTING_IP", ""))
                    if visitante.version == 6 and visitante.ipv4_mapped: visitante = visitante.ipv4_mapped
                    # Se o conector recebeu IPv4 sintético, preserve a identidade IPv6 original.
                    if visitante.version == 4 and visitante in ipaddress.ip_network("240.0.0.0/4"):
                        original = ipaddress.ip_address(environ.get("HTTP_CF_CONNECTING_IPV6", ""))
                        if original.version != 6: raise ValueError("IPv6 original inválido")
                        visitante = original
                    if visitante.is_global and not visitante.is_multicast:
                        environ["vaultnet.ip_publico"] = str(visitante)
            except ValueError:
                pass
        return app(environ, start_response)
    return executar

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Recuperação local do acesso VaultNet")
    parser.add_argument("--recuperar", action="store_true", required=True)
    parser.parse_args()
    caminho = Path(__file__).resolve().parent / "dados" / "login.sqlite3"
    if not caminho.is_file(): raise SystemExit("Banco não encontrado. Execute na pasta original do servidor.")
    with sqlite3.connect(caminho) as db:
        salvar(db, {"modo": "computador", "redes": PADRAO["redes"]})
        import time
        db.execute("INSERT INTO auditoria(momento,usuario_id,evento,ip) VALUES(?,NULL,'acesso_rede_recuperado','console-local')", (time.time(),))
    print("Acesso recuperado somente neste computador.")
    print("Abra http://127.0.0.1:8081/login e ajuste Administração > Acesso à rede.")
