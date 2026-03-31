"""
SQLite access for the existing nmap_scans.db schema (scans, hosts, ports, nse_scripts).
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from typing import Any, Iterator

import config
from models import ChangeHighlight, NseRow, PortRow, ScanRow


def _conn() -> sqlite3.Connection:
    config.SQLITE_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(config.SQLITE_PATH), timeout=30.0)
    c.row_factory = sqlite3.Row
    return c


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    conn = _conn()
    try:
        yield conn
    finally:
        conn.close()


def count_scans_total() -> int:
    try:
        with get_connection() as conn:
            row = conn.execute("SELECT COUNT(*) AS c FROM scans").fetchone()
        return int(row["c"]) if row else 0
    except sqlite3.Error:
        return 0


def sqlite_path_resolved() -> str:
    return str(config.SQLITE_PATH.resolve())


def fetch_scans(
    limit: int = 200,
    date_from: str | None = None,
    date_to: str | None = None,
    ip_search: str | None = None,
) -> list[ScanRow]:
    """History list with optional filters (imported_at is TEXT ISO-like)."""
    where: list[str] = []
    params: list[Any] = []
    if date_from:
        where.append("datetime(imported_at) >= datetime(?)")
        params.append(date_from)
    if date_to:
        where.append("datetime(imported_at) <= datetime(?)")
        params.append(date_to)
    if ip_search and ip_search.strip():
        where.append(
            "(command_line LIKE ? OR xml_path LIKE ? OR scan_hash IN "
            "(SELECT DISTINCT scan_hash FROM hosts WHERE addr LIKE ?))"
        )
        pat = f"%{ip_search.strip()}%"
        params.extend([pat, pat, pat])
    sql = (
        "SELECT scan_hash, imported_at, command_line, tags, xml_path FROM scans "
        + ("WHERE " + " AND ".join(where) if where else "")
        + " ORDER BY datetime(imported_at) DESC LIMIT ?"
    )
    params.append(limit)
    with get_connection() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [
        ScanRow(
            scan_hash=r["scan_hash"],
            imported_at=str(r["imported_at"] or ""),
            command_line=r["command_line"] or "",
            tags=r["tags"] or "[]",
            xml_path=r["xml_path"],
        )
        for r in rows
    ]


def count_scans_today() -> int:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS c FROM scans WHERE date(imported_at) = date('now')"
        ).fetchone()
    return int(row["c"]) if row else 0


def count_scans_this_week() -> int:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS c FROM scans WHERE datetime(imported_at) >= datetime('now', '-7 days')"
        ).fetchone()
    return int(row["c"]) if row else 0


def get_mac_changes_last_hours(hours: int = 24) -> list[ChangeHighlight]:
    """
    Hosts whose MAC differs from the previous observation for the same IP,
    limited to transitions seen in scans within the last `hours` hours.
    """
    with get_connection() as conn:
        rows = conn.execute(
            """
            WITH ordered AS (
                SELECT
                    h.addr,
                    h.mac,
                    s.imported_at,
                    LAG(h.mac) OVER (PARTITION BY h.addr ORDER BY datetime(s.imported_at)) AS prev_mac
                FROM hosts h
                JOIN scans s ON s.scan_hash = h.scan_hash
                WHERE h.mac IS NOT NULL AND TRIM(h.mac) != ''
            )
            SELECT addr, mac, prev_mac, imported_at
            FROM ordered
            WHERE prev_mac IS NOT NULL
              AND prev_mac != mac
              AND datetime(imported_at) >= datetime('now', '-' || ? || ' hours')
            ORDER BY datetime(imported_at) DESC
            LIMIT 100
            """,
            (str(int(hours)),),
        ).fetchall()
    out: list[ChangeHighlight] = []
    for r in rows:
        out.append(
            ChangeHighlight(
                kind="mac_change",
                host_addr=r["addr"],
                detail=f"{r['prev_mac']} → {r['mac']}",
                seen_at=str(r["imported_at"]),
            )
        )
    return out


def get_new_open_ports_last_hours(hours: int = 24) -> list[ChangeHighlight]:
    """
    Open port triples whose first appearance (by scan imported_at) falls in the window.
    """
    with get_connection() as conn:
        rows = conn.execute(
            """
            WITH open_ports AS (
                SELECT
                    p.host_addr,
                    p.protocol,
                    p.portid,
                    p.service_name,
                    datetime(s.imported_at) AS imp
                FROM ports p
                JOIN scans s ON s.scan_hash = p.scan_hash
                WHERE p.state IS NULL OR LOWER(TRIM(p.state)) = 'open'
            ),
            first_seen AS (
                SELECT host_addr, protocol, portid,
                       MIN(imp) AS first_at,
                       MAX(service_name) AS service_name
                FROM open_ports
                GROUP BY host_addr, protocol, portid
            )
            SELECT host_addr, protocol, portid, service_name, first_at
            FROM first_seen
            WHERE datetime(first_at) >= datetime('now', '-' || ? || ' hours')
            ORDER BY first_at DESC
            LIMIT 150
            """,
            (str(int(hours)),),
        ).fetchall()
    out: list[ChangeHighlight] = []
    for r in rows:
        svc = r["service_name"] or "?"
        out.append(
            ChangeHighlight(
                kind="new_port",
                host_addr=r["host_addr"],
                detail=f"{r['protocol']}/{r['portid']} ({svc})",
                seen_at=str(r["first_at"]),
            )
        )
    return out


def fetch_hosts_for_scan(scan_hash: str) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT addr, mac, mac_vendor, hostname, state, os_name, os_accuracy,
                   uptime_seconds, distance
            FROM hosts WHERE scan_hash = ? ORDER BY addr
            """,
            (scan_hash,),
        ).fetchall()
    return [dict(r) for r in rows]


def fetch_ports_for_scan(scan_hash: str) -> list[PortRow]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT host_addr, protocol, portid, service_name, product, version
            FROM ports WHERE scan_hash = ? ORDER BY host_addr, portid
            """,
            (scan_hash,),
        ).fetchall()
    return [
        PortRow(
            host_addr=r["host_addr"],
            protocol=r["protocol"],
            portid=int(r["portid"]),
            service_name=r["service_name"],
            product=r["product"],
            version=r["version"],
        )
        for r in rows
    ]


def fetch_nse_for_scan(scan_hash: str, vuln_only: bool = False) -> list[NseRow]:
    cond = ""
    if vuln_only:
        cond = " AND (LOWER(script_id) LIKE '%vuln%' OR output LIKE '%CVE-%')"
    with get_connection() as conn:
        rows = conn.execute(
            f"""
            SELECT script_id, host_addr, port_id, output_summary, output
            FROM nse_scripts WHERE scan_hash = ? {cond}
            ORDER BY host_addr, script_id
            LIMIT 500
            """,
            (scan_hash,),
        ).fetchall()
    return [
        NseRow(
            script_id=r["script_id"],
            host_addr=r["host_addr"],
            port_id=r["port_id"],
            output_summary=r["output_summary"],
            output=r["output"],
        )
        for r in rows
    ]


def fetch_scan_meta(scan_hash: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE scan_hash = ?", (scan_hash,)
        ).fetchone()
    return dict(row) if row else None


def tags_pretty(tags_json: str) -> str:
    try:
        data = json.loads(tags_json)
        if isinstance(data, list):
            return ", ".join(str(x) for x in data)
    except json.JSONDecodeError:
        pass
    return tags_json
