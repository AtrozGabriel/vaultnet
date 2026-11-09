#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ ! -x .venv-linux/bin/python ]]; then
  echo 'Execute primeiro: bash preparar_linux.sh' >&2
  exit 1
fi
exec .venv-linux/bin/python iniciar_linux.py
