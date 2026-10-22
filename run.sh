#!/usr/bin/env bash
set -euo pipefail

# Resolve o diretório do script mesmo quando chamado de outro cwd / via symlink.
SOURCE="${BASH_SOURCE[0]}"
while [[ -L "$SOURCE" ]]; do
  DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
  SOURCE="$(readlink "$SOURCE")"
  [[ "$SOURCE" != /* ]] && SOURCE="$DIR/$SOURCE"
done
ROOT="$(cd -P "$(dirname "$SOURCE")" && pwd)"
cd "$ROOT"

PYTHON="${ROOT}/.venv/bin/python"
PIP="${ROOT}/.venv/bin/pip"

if [[ ! -x "$PYTHON" ]] || ! "$PIP" -V >/dev/null 2>&1; then
  echo "A (re)criar ambiente virtual em .venv …"
  rm -rf .venv
  python3 -m venv .venv
  "$PIP" install -r requirements.txt
fi

exec "$PYTHON" app.py "$@"
