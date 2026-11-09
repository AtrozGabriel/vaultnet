#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
[[ "$EUID" -ne 0 ]] || { echo 'Execute como seu usuário normal, sem sudo.' >&2; exit 1; }
[[ -x .venv-linux/bin/python ]] || { echo 'Execute bash preparar_linux.sh primeiro.' >&2; exit 1; }
raiz="$PWD"
# Caminho simples para a sintaxe de unidade systemd; espaços são suportados.
[[ "$raiz" != *'"'* && "$raiz" != *'%'* && "$raiz" != *'\\'* && "$raiz" != *$'\n'* ]] || exit 1
usuario="$(id -un)"
[[ "$usuario" =~ ^[a-zA-Z0-9_-]+$ ]] || exit 1
unidade="$(mktemp)"
trap 'rm -f -- "$unidade"' EXIT
cat > "$unidade" <<EOF
[Unit]
Description=VaultNet
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=$usuario
WorkingDirectory="$raiz"
ExecStart="$raiz/.venv-linux/bin/python" "$raiz/iniciar_linux.py"
Restart=on-failure
RestartSec=10
TimeoutStopSec=30
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
sudo install -m 644 "$unidade" /etc/systemd/system/vaultnet.service
sudo systemctl daemon-reload
sudo systemctl enable --now vaultnet.service
sudo systemctl --no-pager status vaultnet.service
