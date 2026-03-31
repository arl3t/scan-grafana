#!/usr/bin/env bash
# Arranca la consola web NiceGUI (webapp/main.py).
# Uso: ./start.sh
# Variables opcionales: NICEGUI_HOST, NICEGUI_PORT, NMAP_SQLITE, GRAFANA_BASE_URL, etc. (ver webapp/config.py)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEBAPP="$ROOT/webapp"

if [[ ! -f "$WEBAPP/main.py" ]]; then
  echo "Error: no se encuentra $WEBAPP/main.py" >&2
  exit 1
fi

cd "$WEBAPP"

if [[ -d "$WEBAPP/.venv" ]]; then
  # shellcheck source=/dev/null
  source "$WEBAPP/.venv/bin/activate"
fi

if ! python3 -c "import nicegui" 2>/dev/null; then
  echo "Instalando dependencias (nicegui, APScheduler)…" >&2
  python3 -m pip install -q -r requirements.txt
fi

exec python3 main.py "$@"
