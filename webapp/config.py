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
NMAP_EXTRA_ARGS: list[str] = os.environ.get(
    "NMAP_EXTRA_ARGS",
    "-sT -sV --open -T4 -F --max-retries 1 --host-timeout 90s",
).split()
MAX_CONCURRENT_SCANS: int = int(os.environ.get("MAX_CONCURRENT_SCANS", "3"))

# Perfiles de escaneo (UI). Claves: discovery | standard | vulners
SCAN_PRESET_DISCOVERY: str = "discovery"
SCAN_PRESET_STANDARD: str = "standard"
SCAN_PRESET_VULNERS: str = "vulners"

NMAP_SCAN_PRESETS: dict[str, tuple[str, ...]] = {
    # 1) Solo descubrimiento de hosts (sin enumeración de puertos). Muy rápido en /24.
    SCAN_PRESET_DISCOVERY: (
        "-sn",
        "-T4",
        "--max-retries",
        "1",
        "--host-timeout",
        "45s",
    ),
    # 2) Puertos frecuentes, servicio/versión, SO, traceroute (sin root: -sT).
    SCAN_PRESET_STANDARD: (
        "-sT",
        "-sV",
        "-O",
        "--traceroute",
        "--open",
        "-T4",
        "-F",
        "--max-retries",
        "1",
        "--host-timeout",
        "120s",
    ),
    # 3) Igual que estándar + NSE vulners (requiere script instalado; más lento).
    SCAN_PRESET_VULNERS: (
        "-sT",
        "-sV",
        "-O",
        "--traceroute",
        "--open",
        "-T4",
        "-F",
        "--script",
        "vulners",
        "--max-retries",
        "1",
        "--host-timeout",
        "180s",
    ),
}

PRESET_LABELS: dict[str, str] = {
    SCAN_PRESET_DISCOVERY: "1 · Solo hosts vivos (sin puertos)",
    SCAN_PRESET_STANDARD: "2 · Puertos, servicios, SO y traceroute",
    SCAN_PRESET_VULNERS: "3 · Estándar + script vulners (CVE)",
}


def nmap_args_for_preset(preset_id: str) -> list[str]:
    """Argumentos nmap para el perfil elegido; si no existe, usa NMAP_EXTRA_ARGS."""
    p = (preset_id or "").strip().lower()
    if p in NMAP_SCAN_PRESETS:
        return list(NMAP_SCAN_PRESETS[p])
    return list(NMAP_EXTRA_ARGS)


SCAN_QUICK_TIPS_MARKDOWN: str = """
**Recomendaciones rápidas**

- En redes **grandes o desconocidas**, usa primero el perfil **1 (solo hosts vivos)**; después el **2** sobre IPs o rangos concretos.
- El perfil **3 (vulners)** aporta **CVE** pero es **más lento** y exige el script NSE `vulners` en tu instalación de Nmap.
- Todo lo importado queda en **`nmap_scans.db`** (esta consola, **Grafana** e informes).
- **Solo** escanea redes y equipos **autorizados**. Sin `sudo`, Nmap usa **TCP connect** (`-sT`).
"""


def scan_profiles_help_markdown() -> str:
    """Texto fijo para la ayuda en la UI (3 tipos + recomendaciones)."""
    return """
### Tres tipos de escaneo

| # | Perfil | Qué obtienes | Cuándo usarlo |
|---|--------|----------------|---------------|
| **1** | **Solo hosts vivos** | `nmap -sn …` — responde qué IPs están *up*; **no** lista puertos abiertos. | Inventario rápido de una red grande antes de profundizar. |
| **2** | **Puertos + servicios + SO** | Top ports (`-F`), `-sV`, `-O`, `--traceroute`, solo `--open`. Rellena bien SQLite y Grafana. | Uso habitual: superficie de ataque y gráficos. |
| **3** | **+ vulners** | Igual que (2) más `--script vulners` (CVE asociados a versiones). | Auditorías; **más lento** y el script debe existir en tu Nmap. |

---

### Recomendaciones

- **Autorización:** escanea solo redes y sistemas para los que tengas permiso.
- **Orden práctico:** en un /24 desconocido, prueba primero **(1)**; luego **(2)** sobre rangos o hosts concretos.
- **Root / SYN:** sin `sudo`, la app usa **TCP connect** (`-sT`). Para `-sS` y a veces `-O` más fiable, ejecuta Nmap con privilegios (no está automatizado en la web).
- **vulners:** si el script falla, revisa la salida en el terminal; en algunas instalaciones hace falta actualizar scripts NSE.
- **Datos:** todo termina en **`nmap_scans.db`** → historial en esta web, **Grafana** y `maintenance.py`.
"""

# --- NiceGUI ---
HOST: str = os.environ.get("NICEGUI_HOST", "0.0.0.0")
PORT: int = int(os.environ.get("NICEGUI_PORT", "8080"))

# Persist scheduled jobs
SCHEDULE_STORE: Path = Path(os.environ.get("SCHEDULE_STORE", Path(__file__).resolve().parent / "data" / "schedules.json"))
