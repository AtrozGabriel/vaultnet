"""Resposta de bloqueio independente de arquivos estáticos e do layout autenticado."""
import secrets
from flask import Response, g


def pagina_bloqueio():
    nonce = secrets.token_urlsafe(24)
    g.network_nonce = nonce
    html = """<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Acesso não autorizado · VaultNet</title>
<style nonce="NONCE">
*{box-sizing:border-box}body{margin:0;min-height:100vh;min-height:100dvh;display:grid;place-items:center;padding:24px;background:#0f172a;color:#f8fafc;font-family:system-ui,-apple-system,Segoe UI,sans-serif}
main{width:100%;max-width:480px;padding:44px 32px;text-align:center;background:#182338;border:1px solid #334155;border-radius:20px;box-shadow:0 24px 60px #0003}
.brand{font-size:13px;letter-spacing:3px;font-weight:700;color:#a5b4fc;margin:0 0 28px}.symbol{display:grid;place-items:center;width:64px;height:64px;border-radius:50%;background:#312d4d;color:#fbbf24;margin:0 auto 22px;font-size:32px;font-weight:700}
h1{font-size:clamp(23px,5vw,29px);line-height:1.2;margin:0 0 16px}p{font-size:16px;line-height:1.6;color:#cbd5e1;margin:0}.code{margin-top:28px;font-size:12px;letter-spacing:1px;color:#94a3b8}
</style></head><body><main aria-labelledby="titulo"><p class="brand">VAULTNET</p><div class="symbol" aria-hidden="true">!</div><h1 id="titulo">Acesso não autorizado</h1><p>Sua rede não tem permissão para acessar este sistema.</p><p class="code">ACESSO RESTRITO · 403</p></main></body></html>"""
    return Response(html.replace("NONCE", nonce), status=403, mimetype="text/html")
