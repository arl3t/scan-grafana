# scan-grafana — Nmap → SQLite → Grafana

Herramientas para **importar salidas XML de Nmap** a **SQLite**, mantener **varios escaneos sin duplicar** el mismo run, enriquecer con **MAC, SO, traceroute, NSE** y **tags**, y visualizar todo en **Grafana** con un dashboard importable.

## Requisitos

- **Python 3.10+** (solo librería estándar).
- **Nmap** instalado y, en la mayoría de sistemas Unix, privilegios **root** (o `sudo`) para `-sS` (SYN scan) y `-O` (detección de SO).
- **Grafana** con el plugin **[SQLite Data Source](https://grafana.com/grafana/plugins/frser-sqlite-datasource)** (`frser-sqlite-datasource`).

## Instalación

```bash
git clone <tu-repo> scan-grafana
cd scan-grafana
chmod +x run-nmap-scan.sh
```

Opcional: añade el directorio al `PATH` o invoca los scripts con ruta absoluta.

## Flujo rápido

1. Ejecuta un escaneo e importa a la base (wrapper):

   ```bash
   ./run-nmap-scan.sh 192.168.1.0/24
   ```

2. Crea/actualiza **vistas analíticas** para Grafana:

   ```bash
   python3 maintenance.py -d nmap_scans.db init-views
   ```

3. En Grafana, configura un datasource SQLite apuntando a `nmap_scans.db` e importa `nmap-dashboard.json`.

### Interfaz web (NiceGUI, opcional)

Consola en el navegador: scans concurrentes, programación, historial SQLite e iframe de Grafana. Ver **[webapp/README.md](webapp/README.md)** (`cd webapp && pip install -r requirements.txt && python main.py`).

## `nmap-to-sqlite.py` — Importador

Importa uno o más XML (`-oX`) en una base SQLite.

| Opción | Descripción |
|--------|-------------|
| `-d`, `--database` | Ruta del fichero SQLite (por defecto `./nmap_scans.db`). |
| `--tag TAG` | Etiqueta del escaneo (repetible). Se guarda en `scans.tags` como JSON. |
| `--tags-json` | Array JSON adicional, p. ej. `'["DMZ","semanal"]'`. |
| `--skip-if-exists` | Si el `scan_hash` ya existe, no hace nada (ni fusiona tags). |
| `--force` | Borra datos del mismo `scan_hash` y vuelve a importar; **fusiona** tags previos con los nuevos. |
| `--vacuum` | Ejecuta `VACUUM` tras cada archivo (más lento; reduce tamaño). |

**`scan_hash`**: SHA-256 de `command_line + "\0" + start_time` del XML (`<nmaprun args="…" start="…">`), de modo que el mismo comando y el mismo inicio de run no se duplican como filas de `scans`.

Ejemplos:

```bash
python3 nmap-to-sqlite.py -d nmap_scans.db --tag Oficina --tag LAN resultado.xml
python3 nmap-to-sqlite.py -d nmap_scans.db --force --tag Re-auditoria resultado.xml
```

### Esquema principal

- **`scans`**: metadatos del run, `tags`, rutas, tiempos.
- **`hosts`**: IP, MAC, vendor, hostname, SO y precisión, uptime, distancia (hops), estado.
- **`ports`**: puertos y servicios.
- **`traceroute_hops`**: hops (TTL, IP, RTT, nombre).
- **`nse_scripts`**: salida de scripts NSE (puerto y host), con `output_summary` para títulos habituales (`http-title`, `ssl-cert`, `vulners`, etc.).

## `run-nmap-scan.sh` — Wrapper

Ejecuta Nmap con un perfil orientado a inventario:

`s -sS -sV -O --traceroute --open -T4 -oX <xml_timestamped>`

Luego llama a `nmap-to-sqlite.py` sobre ese XML.

### Variables de entorno

| Variable | Uso |
|----------|-----|
| `NMAP_DB` | Ruta SQLite (por defecto `nmap_scans.db` junto al script). |
| `NMAP_XML_DIR` | Directorio del XML (por defecto `xml_scans/` junto al script). |
| `NMAP_TAGS` | Tags separados por comas (`DMZ,Prod`). |
| `NMAP_EXTRA_ARGS` | Argumentos extra de Nmap (entre comillas si hay varios). |
| `NMAP_IMPORT_EXTRA` | Flags extra para el importador, p. ej. `--vacuum`. |
| `NMAP_SKIP_SUDO=1` | No usar `sudo` (debes ser root si hace falta). |

Ejemplo:

```bash
NMAP_TAGS="DMZ,Servidores" NMAP_IMPORT_EXTRA="--vacuum" ./run-nmap-scan.sh 10.0.0.0/24
```

> **Nota:** `-sS` y `-O` suelen requerir capacidades elevadas; el script usa `sudo` si no eres root (salvo `NMAP_SKIP_SUDO=1`).

## `maintenance.py` — Mantenimiento y vistas

Subcomandos:

```bash
# Esquema base (vía nmap-to-sqlite.py) + vistas para informes/Grafana
python3 maintenance.py -d nmap_scans.db init-views

# Borrar escaneos con imported_at más antiguo que N días (CASCADE borra hosts/puertos/…)
python3 maintenance.py -d nmap_scans.db prune --days 90
python3 maintenance.py -d nmap_scans.db prune --days 90 --dry-run

python3 maintenance.py -d nmap_scans.db vacuum
python3 maintenance.py -d nmap_scans.db status

# Export CSV
python3 maintenance.py -d nmap_scans.db export --preset open_ports -o exports/puertos.csv
python3 maintenance.py -d nmap_scans.db export --sql "SELECT * FROM v_scan_summary LIMIT 100" -o exports/resumen.csv
```

**Presets de export:** `scan_summary`, `open_ports`, `dangerous`, `nse`, `hosts`.

### Vistas creadas (`init-views`)

| Vista | Propósito |
|-------|-----------|
| `v_scan_summary` | Por scan: hosts, puertos abiertos, tags, fechas. |
| `v_open_ports` | Puertos abiertos unidos a `scans`. |
| `v_host_open_port_counts` | Conteo de puertos abiertos por host. |
| `v_hosts_most_open_ports` | Ranking de hosts más expuestos. |
| `v_top_services` | Servicios más frecuentes (puertos abiertos). |
| `v_os_distribution` | Distribución de SO detectado. |
| `v_dangerous_open_ports` | Puertos abiertos en una lista de **alto interés** (ajustable en `maintenance.py`). |
| `v_scans_timeline` | Agregación diaria de imports y hosts. |
| `v_nse_highlights` | Scripts NSE con resumen y vista previa. |

## Grafana + SQLite

1. Instala el plugin:  
   `grafana-cli plugins install frser-sqlite-datasource`  
   y reinicia Grafana.

2. **Add data source → SQLite**  
   - **Path**: ruta absoluta al fichero `nmap_scans.db` en el servidor donde corre el plugin (Grafana debe poder leer ese path).

3. **Dashboards → Import** → sube `nmap-dashboard.json`.  
   Asigna el datasource cuando el asistente lo pida (`DS_SQLITE`).

4. Ejecuta al menos una vez:

   ```bash
   python3 maintenance.py -d /ruta/a/nmap_scans.db init-views
   ```

   para que existan las vistas usadas por el dashboard.

### Si un panel no muestra datos

- Comprueba que la consulta funcione en el editor del plugin.
- El panel de serie temporal usa epoch Unix derivado de `day_utc` en `v_scans_timeline`.
- Ajusta el rango temporal del dashboard (arriba a la derecha); algunos paneles son tablas y no dependen del tiempo.

## Queries útiles (SQL)

```sql
-- Últimos escaneos
SELECT * FROM v_scan_summary ORDER BY imported_at DESC LIMIT 20;

-- Servicios más comunes (abiertos)
SELECT * FROM v_top_services LIMIT 25;

-- Hosts con más superficie expuesta
SELECT * FROM v_hosts_most_open_ports LIMIT 50;

-- CVE / vulners (texto crudo; el resumen está en output_summary)
SELECT host_addr, port_id, output_summary, output
FROM nse_scripts
WHERE script_id = 'vulners'
ORDER BY id DESC LIMIT 30;

-- Traceroute de un host concreto
SELECT * FROM traceroute_hops
WHERE host_addr = '10.0.0.5'
ORDER BY scan_hash DESC, hop_index;
```

## Estructura recomendada del dashboard

El JSON incluido sigue esta lógica:

1. **Fila superior:** KPIs (hosts, puertos abiertos, escaneos, filas NSE).  
2. **Visualizaciones:** pastel de SO, barras de top servicios.  
3. **Tendencia:** imports y hosts por día.  
4. **Tablas:** resumen de scans, puertos “de interés”, hosts más expuestos, detalle de hosts, NSE.

Puedes añadir variables de plantilla en Grafana filtrando por `scan_hash` o por `tags` (p. ej. `WHERE tags LIKE '%DMZ%'`).

## Seguridad y legal

Usa estas herramientas **solo en redes y sistemas para los que tengas autorización**. Los datos en SQLite pueden contener información sensible; protege el fichero y el acceso a Grafana.

## Licencia

Este proyecto se distribuye bajo la **MIT License**. Consulta el fichero [`LICENSE`](LICENSE).
