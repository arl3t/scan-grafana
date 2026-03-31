#!/usr/bin/env bash
#
# Ejecuta Nmap con opciones recomendadas para inventario / análisis en Grafana,
# guarda el XML con marca de tiempo e importa el resultado en SQLite.
#
# Variables de entorno (opcionales):
#   NMAP_DB          Ruta a la base SQLite (por defecto: directorio del script/nmap_scans.db)
#   NMAP_XML_DIR     Directorio de salida XML (por defecto: directorio del script/xml_scans)
#   NMAP_TAGS        Tags separados por coma para el import (ej: Oficina,DMZ)
#   NMAP_EXTRA_ARGS  Argumentos extra para nmap (entre comillas)
#   NMAP_IMPORT_EXTRA  Argumentos extra para nmap-to-sqlite.py (ej: --vacuum)
#   NMAP_SKIP_SUDO   Si es 1, no usa sudo (recomendado con el núcleo -sT -sV -O -T4)
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="${NMAP_DB:-$ROOT_DIR/nmap_scans.db}"
XML_DIR="${NMAP_XML_DIR:-$ROOT_DIR/xml_scans}"
IMPORTER="$ROOT_DIR/nmap-to-sqlite.py"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
OUT_XML="$XML_DIR/nmap_${TIMESTAMP}.xml"

if [[ ! -f "$IMPORTER" ]]; then
  echo "Error: no se encuentra $IMPORTER" >&2
  exit 1
fi

if [[ $# -lt 1 ]]; then
  echo "Uso: $0 <objetivo(s) nmap> [...]" >&2
  echo "Ejemplo: $0 192.168.1.0/24" >&2
  echo "Ejemplo: NMAP_TAGS='Oficina,LAN' $0 10.0.0.1-50" >&2
  exit 1
fi

mkdir -p "$XML_DIR"

# Resultado del escaneo persistido únicamente en XML (mismo criterio que la consola web).
NMAP_CMD=(nmap -sT -sV -O -T4 -oX "$OUT_XML")
if [[ -n "${NMAP_EXTRA_ARGS:-}" ]]; then
  # shellcheck disable=SC2206
  NMAP_CMD+=(${NMAP_EXTRA_ARGS})
fi
NMAP_CMD+=("$@")

if [[ "${NMAP_SKIP_SUDO:-0}" == "1" ]]; then
  echo "[*] Ejecutando nmap (sin sudo): ${NMAP_CMD[*]}"
  "${NMAP_CMD[@]}"
elif [[ "${EUID:-0}" -eq 0 ]]; then
  echo "[*] Ejecutando nmap como root: ${NMAP_CMD[*]}"
  "${NMAP_CMD[@]}"
else
  echo "[*] Ejecutando nmap con sudo (usa NMAP_SKIP_SUDO=1 si no hace falta, p. ej. con -sT): ${NMAP_CMD[*]}"
  sudo "${NMAP_CMD[@]}"
fi

if [[ ! -s "$OUT_XML" ]]; then
  echo "Error: no se generó XML o está vacío: $OUT_XML" >&2
  exit 1
fi

IMPORT_ARGS=(-d "$DB_PATH")
if [[ -n "${NMAP_TAGS:-}" ]]; then
  IFS=',' read -ra _TAGS <<< "$NMAP_TAGS"
  for t in "${_TAGS[@]}"; do
    t="$(echo "$t" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ -z "$t" ]] && continue
    IMPORT_ARGS+=(--tag "$t")
  done
fi
if [[ -n "${NMAP_IMPORT_EXTRA:-}" ]]; then
  # shellcheck disable=SC2206
  IMPORT_ARGS+=(${NMAP_IMPORT_EXTRA})
fi

echo "[*] Importando en SQLite: ${IMPORT_ARGS[*]} $OUT_XML"
python3 "$IMPORTER" "${IMPORT_ARGS[@]}" "$OUT_XML"

echo "[*] Listo. XML: $OUT_XML | DB: $DB_PATH"
