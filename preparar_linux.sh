#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
for arquivo in app.py acesso_rede.py antivirus.py; do
  [[ -f "$arquivo" ]] || { echo "Falta $arquivo. Extraia estes arquivos na raiz do projeto." >&2; exit 1; }
done
[[ -x /usr/bin/clamscan ]] || { echo 'Instale primeiro: sudo apt install python3-venv clamav' >&2; exit 1; }
python3 -m venv .venv-linux
.venv-linux/bin/python -m pip install --only-binary=:all: -r requirements-linux.txt
.venv-linux/bin/python -m pip check
printf '%s\n' 'Ambiente pronto. Confira as assinaturas do ClamAV antes de iniciar.'
