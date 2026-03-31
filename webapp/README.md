# Scan Console (NiceGUI)

Interfaz web ligera para lanzar **Nmap** en paralelo, **programar** escaneos, ver **historial** en la SQLite del proyecto y enlazar / incrustar **Grafana**.

## Requisitos

- Python 3.10+
- `nmap` en el `PATH`
- Misma máquina (o acceso de lectura) al fichero `nmap_scans.db` del repositorio
- Grafana opcional (iframe y enlaces)

## Instalación

Desde el directorio `webapp/`:

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Configuración (`config.py`)

| Variable de entorno | Descripción |
|---------------------|-------------|
| `NMAP_SQLITE` | Ruta a `nmap_scans.db` (por defecto: carpeta superior del repo) |
| `GRAFANA_BASE_URL` | URL base, p. ej. `http://127.0.0.1:3000` |
| `GRAFANA_MAIN_DASHBOARD_PATH` | Ruta del dashboard, p. ej. `/d/uid/titulo` |
| `NMAP_EXTRA_ARGS` | Argumentos extra de nmap (separados por espacio) |
| `MAX_CONCURRENT_SCANS` | Límite de scans simultáneos (default 3) |
| `NICEGUI_HOST` / `NICEGUI_PORT` | Bind del servidor (default `0.0.0.0:8080`) |
| `TZ` | Zona horaria IANA (p. ej. `Europe/Madrid`). Si no está definida, `start.sh` y `main.py` usan `UTC` y evitan avisos de **tzlocal** por `/etc/timezone` obsoleto en algunas distros. |
| `SCHEDULER_TZ` | Opcional; si existe, tiene prioridad sobre `TZ` para **APScheduler** (cron / intervalos). |

En servidores Debian/Ubuntu recientes puedes **borrar** `/etc/timezone` si solo genera ruido y fijas `TZ` en **systemd** o en `start.sh`.

## Ejecución

Desde la raíz del repositorio:

```bash
./start.sh
```

O manualmente:

```bash
cd webapp
python main.py
```

Abre `http://127.0.0.1:8080` (o el puerto configurado; con `./start.sh` el bind por defecto es `0.0.0.0`).

## Funciones

- **Dashboard**: **tres perfiles** de Nmap (núcleo común `-sT -sV -O -T4`; el tercero añade `vulners`), campo **Red u objetivos**, tarjeta de **recomendaciones**, panel **«Cómo se ejecuta»** (tabla + vista previa con `-oX`), ruta de `nmap_scans.db`, terminal en vivo e **IMPORT_OK** con conteos.
- Programación (una vez / hora / 6h / 12h / diario), tarjetas de estado, cambios **MAC** / **puertos nuevos** (24h), **terminal en vivo** (verbose nmap + import) y enlace para abrir Grafana en otra pestaña.
- **Historial** (`/history`): lista filtrable y detalle por scan (hosts, puertos, NSE/CVE).

Las programaciones se guardan en `webapp/data/schedules.json`.

## Notas de seguridad

La app **no tiene autenticación**; no la expongas a Internet sin reverse proxy, TLS y control de acceso. Solo escanea redes **autorizadas**.

## Integración con el importador

Tras cada scan, se ejecuta `nmap-to-sqlite.py` sobre el XML generado en `xml_scans/` con tag `webui` (o `scheduled` / `sched-*` para tareas programadas).

Ejecuta al menos una vez en la base:

```bash
python ../maintenance.py -d ../nmap_scans.db init-views
```

para las vistas usadas por Grafana.
