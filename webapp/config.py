"""
Central configuration for the NiceGUI scanner UI.
Override via environment variables when deploying.
"""

from __future__ import annotations

import os
from pathlib import Path

# Repository root (parent of webapp/)
REPO_ROOT: Path = Path(__file__).resolve().parent.parent


def _env_path(key: str, default: Path) -> Path:
    """Treat unset or blank env as missing (avoid Path('') → cwd-relative DB)."""
    raw = os.environ.get(key)
    if raw is None or not str(raw).strip():
        return default
    return Path(os.path.expanduser(str(raw).strip()))


# SQLite used by nmap-to-sqlite.py (same file Grafana reads)
SQLITE_PATH: Path = _env_path("NMAP_SQLITE", REPO_ROOT / "nmap_scans.db")

# Importer script
NMAP_TO_SQLITE: Path = _env_path("NMAP_TO_SQLITE", REPO_ROOT / "nmap-to-sqlite.py")

# XML output directory for scans launched from the UI
XML_OUTPUT_DIR: Path = _env_path("NMAP_XML_DIR", REPO_ROOT / "xml_scans")

# --- Grafana (iframe + deep links) ---
GRAFANA_BASE_URL: str = os.environ.get("GRAFANA_BASE_URL", "http://127.0.0.1:3000").rstrip("/")
# Path or full URL to the main dashboard (e.g. /d/nmap-sqlite-inventory/nmap-sqlite)
GRAFANA_MAIN_DASHBOARD_PATH: str = os.environ.get(
    "GRAFANA_MAIN_DASHBOARD_PATH",
    "/d/pj-nmap-inventario/poder-judicial-inventario",
)
# Optional explore / second link
GRAFANA_EXPLORE_PATH: str = os.environ.get("GRAFANA_EXPLORE_PATH", "/explore")

# --- Nmap ---
# Default: TCP connect scan (no root). Prefix with sudo in env NMAP_PREFIX if you use -sS -O.
NMAP_BINARY: str = os.environ.get("NMAP_BINARY", "nmap")
# No uses aquí -oN/-oG/-oA/-oX: la consola fuerza solo -oX <xml> para importar a SQLite.
NMAP_EXTRA_ARGS: list[str] = os.environ.get(
    "NMAP_EXTRA_ARGS",
    "-sT -sV -O -T4",
).split()
MAX_CONCURRENT_SCANS: int = int(os.environ.get("MAX_CONCURRENT_SCANS", "3"))

# Perfiles de escaneo (UI). Claves: discovery | standard | vulners
SCAN_PRESET_DISCOVERY: str = "discovery"
SCAN_PRESET_STANDARD: str = "standard"
SCAN_PRESET_VULNERS: str = "vulners"

# Núcleo común (la web añade siempre `-oX <ruta.xml>` antes del objetivo).
_NMAP_CORE: tuple[str, ...] = ("-sT", "-sV", "-O", "-T4")

NMAP_SCAN_PRESETS: dict[str, tuple[str, ...]] = {
    # Perfiles 1 y 2: mismo comando base solicitado; reservados por si en el futuro divergen.
    SCAN_PRESET_DISCOVERY: _NMAP_CORE,
    SCAN_PRESET_STANDARD: _NMAP_CORE,
    # Mismo núcleo + NSE vulners (CVE por versiones).
    SCAN_PRESET_VULNERS: (*_NMAP_CORE, "--script", "vulners"),
}

PRESET_LABELS: dict[str, str] = {
    SCAN_PRESET_DISCOVERY: "1 · -sT -sV -O -T4 (-oX en la app)",
    SCAN_PRESET_STANDARD: "2 · -sT -sV -O -T4 (-oX en la app)",
    SCAN_PRESET_VULNERS: "3 · -sT -sV -O -T4 + vulners (-oX en la app)",
}


def nmap_args_for_preset(preset_id: str) -> list[str]:
    """Argumentos nmap para el perfil elegido; si no existe, usa NMAP_EXTRA_ARGS."""
    p = (preset_id or "").strip().lower()
    if p in NMAP_SCAN_PRESETS:
        return list(NMAP_SCAN_PRESETS[p])
    return list(NMAP_EXTRA_ARGS)


SCAN_QUICK_TIPS_MARKDOWN: str = """
**Recomendaciones rápidas**

- Todos los perfiles usan el núcleo **`nmap -sT -sV -O -T4`**; la consola añade **`-oX <xml>`** y el objetivo.
- El perfil **3 (vulners)** añade **`--script vulners`** (más lento; requiere el script en Nmap).
- Todo lo importado queda en **`nmap_scans.db`** (esta consola, **Grafana** e informes).
- **Solo** escanea redes y equipos **autorizados**. Sin `sudo` se usa **TCP connect** (`-sT`).
"""


def scan_profiles_help_markdown() -> str:
    """Texto fijo para la ayuda en la UI (3 tipos + recomendaciones)."""
    return """
### Tres tipos de escaneo

| # | Perfil | Comando (la app inserta `-oX` y el fichero XML) |
|---|--------|--------------------------------------------------|
| **1** | **Perfil 1** | `nmap -sT -sV -O -T4 -oX … <objetivo>` |
| **2** | **Perfil 2** | Igual que (1) (mismo núcleo). |
| **3** | **+ vulners** | `nmap -sT -sV -O -T4 --script vulners -oX … <objetivo>` |

---

### Recomendaciones

- **Autorización:** escanea solo redes y sistemas para los que tengas permiso.
- **Sin root:** `-sT` (TCP connect) no requiere privilegios; `-O` puede ser menos preciso que con root.
- **vulners:** si el script falla, revisa la salida en el terminal; a veces hace falta actualizar scripts NSE.
- **Datos:** todo termina en **`nmap_scans.db`** → historial en esta web, **Grafana** y `maintenance.py`.
"""

# --- NiceGUI ---
HOST: str = os.environ.get("NICEGUI_HOST", "0.0.0.0")
PORT: int = int(os.environ.get("NICEGUI_PORT", "8080"))

# Persist scheduled jobs
SCHEDULE_STORE: Path = Path(os.environ.get("SCHEDULE_STORE", Path(__file__).resolve().parent / "data" / "schedules.json"))
