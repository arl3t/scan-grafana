"""
Central configuration for the NiceGUI scanner UI.
Override via environment variables when deploying.
"""

from __future__ import annotations

import os
from pathlib import Path

# Repository root (parent of webapp/)
REPO_ROOT: Path = Path(__file__).resolve().parent.parent

# SQLite used by nmap-to-sqlite.py (same file Grafana reads)
SQLITE_PATH: Path = Path(os.environ.get("NMAP_SQLITE", REPO_ROOT / "nmap_scans.db"))

# Importer script
NMAP_TO_SQLITE: Path = Path(os.environ.get("NMAP_TO_SQLITE", REPO_ROOT / "nmap-to-sqlite.py"))

# XML output directory for scans launched from the UI
XML_OUTPUT_DIR: Path = Path(os.environ.get("NMAP_XML_DIR", REPO_ROOT / "xml_scans"))

# --- Grafana (iframe + deep links) ---
GRAFANA_BASE_URL: str = os.environ.get("GRAFANA_BASE_URL", "http://127.0.0.1:3000").rstrip("/")
# Path or full URL to the main dashboard (e.g. /d/nmap-sqlite-inventory/nmap-sqlite)
GRAFANA_MAIN_DASHBOARD_PATH: str = os.environ.get(
    "GRAFANA_MAIN_DASHBOARD_PATH",
    "/d/nmap-sqlite-inventory/nmap-sqlite-inventario",
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

# --- NiceGUI ---
HOST: str = os.environ.get("NICEGUI_HOST", "0.0.0.0")
PORT: int = int(os.environ.get("NICEGUI_PORT", "8080"))

# Persist scheduled jobs
SCHEDULE_STORE: Path = Path(os.environ.get("SCHEDULE_STORE", Path(__file__).resolve().parent / "data" / "schedules.json"))
