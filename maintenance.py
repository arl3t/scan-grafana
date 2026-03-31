#!/usr/bin/env python3
"""
Mantenimiento de la base Nmap/SQLite: vistas analíticas, retención, VACUUM/ANALYZE y exportación.
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import logging
import sqlite3
import sys
from pathlib import Path
from typing import Iterable, Optional

LOG = logging.getLogger("maintenance")

# Vistas para estadísticas avanzadas (Grafana / informes)
ANALYTICS_VIEWS_SQL = """
CREATE VIEW IF NOT EXISTS v_scan_summary AS
SELECT
    s.scan_hash,
    s.command_line,
    s.start_time,
    s.finished_time,
    s.imported_at,
    s.tags,
    s.nmap_version,
    s.xml_path,
    (SELECT COUNT(*) FROM hosts h WHERE h.scan_hash = s.scan_hash) AS host_count,
    (SELECT COUNT(*) FROM ports p
     WHERE p.scan_hash = s.scan_hash AND (p.state IS NULL OR LOWER(TRIM(p.state)) = 'open')) AS open_port_count
FROM scans s;

CREATE VIEW IF NOT EXISTS v_open_ports AS
SELECT
    p.scan_hash,
    p.host_addr,
    p.protocol,
    p.portid,
    p.state,
    p.service_name,
    p.product,
    p.version,
    p.extrainfo,
    s.imported_at,
    s.tags
FROM ports p
JOIN scans s ON s.scan_hash = p.scan_hash
WHERE p.state IS NULL OR LOWER(TRIM(p.state)) = 'open';

CREATE VIEW IF NOT EXISTS v_host_open_port_counts AS
SELECT
    h.scan_hash,
    h.addr,
    h.hostname,
    h.os_name,
    h.os_accuracy,
    h.state,
    COUNT(p.rowid) AS open_port_count
FROM hosts h
LEFT JOIN ports p
    ON p.scan_hash = h.scan_hash
    AND p.host_addr = h.addr
    AND (p.state IS NULL OR LOWER(TRIM(p.state)) = 'open')
GROUP BY h.scan_hash, h.addr;

CREATE VIEW IF NOT EXISTS v_top_services AS
SELECT
    MIN(p.service_name) AS service_name,
    COUNT(*) AS occurrences
FROM ports p
WHERE (p.state IS NULL OR LOWER(TRIM(p.state)) = 'open')
  AND p.service_name IS NOT NULL AND TRIM(p.service_name) != ''
GROUP BY LOWER(TRIM(p.service_name))
ORDER BY occurrences DESC;

CREATE VIEW IF NOT EXISTS v_os_distribution AS
SELECT
    MIN(COALESCE(NULLIF(TRIM(h.os_name), ''), '(unknown)')) AS os_name,
    COUNT(*) AS host_count,
    AVG(h.os_accuracy) AS avg_os_accuracy
FROM hosts h
WHERE h.state IS NULL OR LOWER(TRIM(h.state)) = 'up'
GROUP BY LOWER(COALESCE(NULLIF(TRIM(h.os_name), ''), '(unknown)'))
ORDER BY host_count DESC;

-- Puertos frecuentemente sensibles si están expuestos (ajusta la lista según tu política)
CREATE VIEW IF NOT EXISTS v_dangerous_open_ports AS
SELECT
    p.scan_hash,
    p.host_addr,
    p.protocol,
    p.portid,
    p.service_name,
    p.product,
    p.version,
    s.imported_at,
    s.tags
FROM ports p
JOIN scans s ON s.scan_hash = p.scan_hash
WHERE (p.state IS NULL OR LOWER(TRIM(p.state)) = 'open')
  AND p.portid IN (
    21, 22, 23, 25, 53, 110, 111, 135, 139, 143, 445, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017
  );

CREATE VIEW IF NOT EXISTS v_hosts_most_open_ports AS
SELECT
    scan_hash,
    addr,
    hostname,
    os_name,
    open_port_count
FROM v_host_open_port_counts
ORDER BY open_port_count DESC;

CREATE VIEW IF NOT EXISTS v_scans_timeline AS
SELECT
    date(s.imported_at) AS day_utc,
    COUNT(*) AS scans_imported,
    SUM((SELECT COUNT(*) FROM hosts h WHERE h.scan_hash = s.scan_hash)) AS hosts_recorded
FROM scans s
WHERE s.imported_at IS NOT NULL
GROUP BY date(s.imported_at)
ORDER BY day_utc DESC;

CREATE VIEW IF NOT EXISTS v_nse_highlights AS
SELECT
    n.scan_hash,
    n.host_addr,
    n.port_protocol,
    n.port_id,
    n.script_id,
    n.output_summary,
    substr(n.output, 1, 500) AS output_preview,
    s.imported_at,
    s.tags
FROM nse_scripts n
JOIN scans s ON s.scan_hash = n.scan_hash;
"""


def load_importer_module(repo_root: Path):
    path = repo_root / "nmap-to-sqlite.py"
    spec = importlib.util.spec_from_file_location("nmap_to_sqlite", path)
    if spec is None or spec.loader is None:
        raise FileNotFoundError(f"No se pudo cargar {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def connect(db: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row
    return conn


def ensure_schema_and_views(conn: sqlite3.Connection, repo_root: Path) -> None:
    mod = load_importer_module(repo_root)
    mod.ensure_schema(conn)
    conn.executescript(ANALYTICS_VIEWS_SQL)
    conn.commit()
    LOG.info("Esquema base y vistas analíticas aplicados.")


def prune_old_scans(conn: sqlite3.Connection, days: int, dry_run: bool) -> int:
    if days < 1:
        raise ValueError("days debe ser >= 1")
    cutoff = (f"-{int(days)} days",)
    cur = conn.execute(
        """
        SELECT scan_hash, imported_at, command_line
        FROM scans
        WHERE imported_at IS NOT NULL
          AND datetime(imported_at) < datetime('now', ?)
        """,
        cutoff,
    )
    rows = cur.fetchall()
    if dry_run:
        LOG.info("DRY-RUN: se eliminarían %d scan(s) más antiguos que %d día(s).", len(rows), days)
        for r in rows[:20]:
            LOG.info("  %s  %s  %s", r["scan_hash"][:16], r["imported_at"], (r["command_line"] or "")[:80])
        if len(rows) > 20:
            LOG.info("  ... (%d más)", len(rows) - 20)
        return len(rows)
    conn.execute(
        """
        DELETE FROM scans
        WHERE imported_at IS NOT NULL
          AND datetime(imported_at) < datetime('now', ?)
        """,
        cutoff,
    )
    conn.commit()
    LOG.info("Eliminados %d scan(s) con imported_at anterior a %d día(s).", len(rows), days)
    return len(rows)


def vacuum_analyze(conn: sqlite3.Connection) -> None:
    conn.execute("VACUUM")
    conn.execute("ANALYZE")
    conn.commit()
    LOG.info("VACUUM y ANALYZE completados.")


def export_query_csv(conn: sqlite3.Connection, sql: str, out_path: Path) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    cur = conn.execute(sql)
    cols = [d[0] for d in cur.description] if cur.description else []
    n = 0
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if cols:
            w.writerow(cols)
        for row in cur:
            w.writerow(list(row))
            n += 1
    LOG.info("Exportadas %d filas → %s", n, out_path)
    return n


def print_status(conn: sqlite3.Connection) -> None:
    one = lambda q: conn.execute(q).fetchone()[0]
    LOG.info("scans:        %s", one("SELECT COUNT(*) FROM scans"))
    LOG.info("hosts:        %s", one("SELECT COUNT(*) FROM hosts"))
    LOG.info("ports:        %s", one("SELECT COUNT(*) FROM ports"))
    LOG.info("traceroute:   %s", one("SELECT COUNT(*) FROM traceroute_hops"))
    LOG.info("nse_scripts:  %s", one("SELECT COUNT(*) FROM nse_scripts"))
    row = conn.execute(
        "SELECT MIN(imported_at), MAX(imported_at) FROM scans WHERE imported_at IS NOT NULL"
    ).fetchone()
    LOG.info("imported_at:  %s … %s", row[0], row[1])


def default_repo_root() -> Path:
    return Path(__file__).resolve().parent


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Mantenimiento Nmap → SQLite (vistas, retención, export).")
    p.add_argument("-d", "--database", type=Path, default=Path("nmap_scans.db"), help="Ruta SQLite")
    p.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Directorio del proyecto (para cargar nmap-to-sqlite.py); por defecto junto a este script",
    )
    p.add_argument("-v", "--verbose", action="store_true")

    sub = p.add_subparsers(dest="cmd", required=True)

    s_init = sub.add_parser("init-views", help="Asegura esquema y crea/actualiza vistas analíticas")
    s_init.set_defaults(handler="init")

    s_prune = sub.add_parser("prune", help="Borra scans antiguos por imported_at")
    s_prune.add_argument("--days", type=int, required=True, help="Conservar scans de los últimos N días")
    s_prune.add_argument("--dry-run", action="store_true")
    s_prune.set_defaults(handler="prune")

    s_vac = sub.add_parser("vacuum", help="Ejecutar VACUUM y ANALYZE")
    s_vac.set_defaults(handler="vacuum")

    s_stat = sub.add_parser("status", help="Resumen de filas y rango de fechas")
    s_stat.set_defaults(handler="status")

    s_exp = sub.add_parser("export", help="Exportar resultado de una consulta a CSV")
    s_exp.add_argument("-o", "--output", type=Path, required=True)
    s_exp.add_argument(
        "--preset",
        choices=("scan_summary", "open_ports", "dangerous", "nse", "hosts"),
        default=None,
        help="Consulta predefinida (si no se usa --sql)",
    )
    s_exp.add_argument("--sql", type=str, default=None, help="SQL arbitrario (SELECT …)")
    s_exp.set_defaults(handler="export")

    return p.parse_args(list(argv) if argv is not None else None)


PRESETS = {
    "scan_summary": "SELECT * FROM v_scan_summary ORDER BY imported_at DESC",
    "open_ports": "SELECT * FROM v_open_ports ORDER BY imported_at DESC, host_addr, portid LIMIT 50000",
    "dangerous": "SELECT * FROM v_dangerous_open_ports ORDER BY imported_at DESC",
    "nse": "SELECT * FROM v_nse_highlights ORDER BY imported_at DESC LIMIT 20000",
    "hosts": "SELECT h.*, s.imported_at, s.tags FROM hosts h JOIN scans s ON s.scan_hash = h.scan_hash ORDER BY s.imported_at DESC",
}


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(message)s")

    db: Path = args.database
    repo_root = (args.repo_root or default_repo_root()).resolve()

    try:
        conn = connect(db)
    except sqlite3.Error as e:
        LOG.error("No se pudo abrir la base: %s", e)
        return 1

    try:
        handler = args.handler
        if handler == "init":
            ensure_schema_and_views(conn, repo_root)
        elif handler == "prune":
            ensure_schema_and_views(conn, repo_root)
            prune_old_scans(conn, args.days, args.dry_run)
        elif handler == "vacuum":
            vacuum_analyze(conn)
        elif handler == "status":
            try:
                ensure_schema_and_views(conn, repo_root)
            except FileNotFoundError:
                LOG.warning("nmap-to-sqlite.py no encontrado; mostrando estado sin recrear vistas.")
            print_status(conn)
        elif handler == "export":
            ensure_schema_and_views(conn, repo_root)
            sql = args.sql
            if not sql:
                if not args.preset:
                    LOG.error("Indica --preset o --sql")
                    return 2
                sql = PRESETS[args.preset]
            if not sql.strip().lower().startswith("select"):
                LOG.error("Solo se permiten consultas SELECT para export.")
                return 2
            export_query_csv(conn, sql, args.output)
        else:
            return 2
    except (FileNotFoundError, ValueError) as e:
        LOG.error("%s", e)
        return 1
    except sqlite3.Error as e:
        LOG.error("SQLite: %s", e)
        return 1
    finally:
        conn.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
