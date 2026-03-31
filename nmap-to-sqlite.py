#!/usr/bin/env python3
"""
Import Nmap XML scan results into SQLite for Grafana and analytics.

Features:
  - Multi-scan support with deduplication via scan_hash (command_line + start_time)
  - Rich host data: MAC, vendor, OS accuracy, uptime, hop distance, traceroute hops
  - Per-scan tags (JSON array in scans.tags)
  - NSE script extraction (host + port scripts) with light parsing for common scripts
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import sqlite3
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable, Optional

LOG = logging.getLogger("nmap-to-sqlite")

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

# nse_scripts has no UNIQUE on (script_id, port): host scripts use NULL port; re-import uses --force or DELETE.

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS scans (
    scan_hash       TEXT PRIMARY KEY,
    command_line    TEXT NOT NULL,
    start_time      TEXT NOT NULL,
    finished_time   TEXT,
    nmap_version    TEXT,
    xml_path        TEXT,
    tags            TEXT NOT NULL DEFAULT '[]',
    imported_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS hosts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_hash       TEXT NOT NULL REFERENCES scans(scan_hash) ON DELETE CASCADE,
    addr            TEXT NOT NULL,
    addrtype        TEXT,
    mac             TEXT,
    mac_vendor      TEXT,
    hostname        TEXT,
    state           TEXT,
    os_name         TEXT,
    os_accuracy     INTEGER,
    uptime_seconds  INTEGER,
    lastboot        TEXT,
    distance        INTEGER,
    host_start      TEXT,
    host_end        TEXT,
    UNIQUE (scan_hash, addr)
);

CREATE TABLE IF NOT EXISTS ports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_hash       TEXT NOT NULL REFERENCES scans(scan_hash) ON DELETE CASCADE,
    host_addr       TEXT NOT NULL,
    protocol        TEXT NOT NULL,
    portid          INTEGER NOT NULL,
    state           TEXT,
    service_name    TEXT,
    product         TEXT,
    version         TEXT,
    extrainfo       TEXT,
    UNIQUE (scan_hash, host_addr, protocol, portid)
);

CREATE TABLE IF NOT EXISTS traceroute_hops (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_hash       TEXT NOT NULL REFERENCES scans(scan_hash) ON DELETE CASCADE,
    host_addr       TEXT NOT NULL,
    hop_index       INTEGER NOT NULL,
    ttl             INTEGER,
    ipaddr          TEXT,
    rtt_ms          REAL,
    hop_host        TEXT,
    UNIQUE (scan_hash, host_addr, hop_index)
);

CREATE TABLE IF NOT EXISTS nse_scripts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_hash       TEXT NOT NULL REFERENCES scans(scan_hash) ON DELETE CASCADE,
    host_addr       TEXT NOT NULL,
    port_protocol   TEXT,
    port_id         INTEGER,
    script_id       TEXT NOT NULL,
    output          TEXT,
    output_summary  TEXT
);

CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_hash);
CREATE INDEX IF NOT EXISTS idx_ports_scan ON ports(scan_hash);
CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(scan_hash, host_addr);
CREATE INDEX IF NOT EXISTS idx_trace_scan ON traceroute_hops(scan_hash, host_addr);
CREATE INDEX IF NOT EXISTS idx_nse_scan ON nse_scripts(scan_hash, host_addr);
CREATE INDEX IF NOT EXISTS idx_nse_script_id ON nse_scripts(script_id);
"""


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_SQL)
    conn.commit()


def compute_scan_hash(command_line: str, start_time: str) -> str:
    """Stable hash for deduplication: SHA-256 of command_line + NUL + start_time."""
    payload = f"{command_line}\0{start_time}".encode("utf-8", errors="replace")
    return hashlib.sha256(payload).hexdigest()


def _attr(elem: Optional[ET.Element], name: str, default: Optional[str] = None) -> Optional[str]:
    if elem is None:
        return default
    v = elem.get(name)
    return v if v is not None else default


def _int_attr(elem: Optional[ET.Element], name: str) -> Optional[int]:
    v = _attr(elem, name)
    if v is None or v == "":
        return None
    try:
        return int(v, 10)
    except ValueError:
        try:
            return int(float(v))
        except ValueError:
            return None


def _float_attr(elem: Optional[ET.Element], name: str) -> Optional[float]:
    v = _attr(elem, name)
    if v is None or v == "":
        return None
    try:
        return float(v)
    except ValueError:
        return None


def parse_rtt_ms(rtt_str: Optional[str]) -> Optional[float]:
    if not rtt_str:
        return None
    s = rtt_str.strip()
    if s.endswith("ms"):
        s = s[:-2].strip()
    try:
        return float(s)
    except ValueError:
        return None


def pick_ipv4_address(host_el: ET.Element) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """
    Returns (primary_ip, addrtype, mac, mac_vendor) from <address> elements.
    Prefer ipv4; MAC may appear as separate address with addrtype mac.
    """
    primary, atype, mac, mac_vendor = None, None, None, None
    for addr in host_el.findall("address"):
        ad = _attr(addr, "addr")
        typ = _attr(addr, "addrtype", "")
        vendor = _attr(addr, "vendor")
        if typ == "mac" and ad:
            mac = ad
            mac_vendor = vendor
        elif typ in ("ipv4", "ipv6") and ad:
            if typ == "ipv4" or primary is None:
                primary, atype = ad, typ
    return primary, atype, mac, mac_vendor


def parse_hostname(host_el: ET.Element) -> Optional[str]:
    hn = host_el.find("hostnames")
    if hn is None:
        return None
    for h in hn.findall("hostname"):
        name = _attr(h, "name")
        typ = _attr(h, "type", "")
        if name and typ in ("user", "PTR", ""):
            return name
    for h in hn.findall("hostname"):
        name = _attr(h, "name")
        if name:
            return name
    return None


def parse_os_best(host_el: ET.Element) -> tuple[Optional[str], Optional[int]]:
    """Best OS match: highest accuracy among osmatch elements."""
    os_el = host_el.find("os")
    if os_el is None:
        return None, None
    best_name: Optional[str] = None
    best_acc: Optional[int] = -1
    for om in os_el.findall("osmatch"):
        name = _attr(om, "name")
        acc = _int_attr(om, "accuracy")
        if name and acc is not None and acc > (best_acc or -1):
            best_name, best_acc = name, acc
    if best_name is None:
        return None, None
    return best_name, best_acc if best_acc is not None and best_acc >= 0 else None


def parse_uptime(host_el: ET.Element) -> tuple[Optional[int], Optional[str]]:
    up = host_el.find("uptime")
    if up is None:
        return None, None
    return _int_attr(up, "seconds"), _attr(up, "lastboot")


def parse_distance(host_el: ET.Element) -> Optional[int]:
    d = host_el.find("distance")
    if d is None:
        return None
    return _int_attr(d, "value")


def parse_traceroute(host_el: ET.Element) -> list[dict[str, Any]]:
    hops: list[dict[str, Any]] = []
    tr = host_el.find("trace")
    if tr is None:
        return hops
    for idx, hop in enumerate(tr.findall("hop")):
        hops.append(
            {
                "hop_index": idx,
                "ttl": _int_attr(hop, "ttl"),
                "ipaddr": _attr(hop, "ipaddr") or _attr(hop, "ip"),
                "rtt_ms": parse_rtt_ms(_attr(hop, "rtt") or _attr(hop, "hosttime")),
                "hop_host": _attr(hop, "host"),
            }
        )
    return hops


def summarize_nse_output(script_id: str, output: str) -> Optional[str]:
    """
    Extract a short summary for well-known NSE scripts (vulners, http-title, etc.).
    Full output is always stored in nse_scripts.output.
    """
    if not output:
        return None
    text = output.strip()
    sid = script_id.lower()

    if sid == "http-title":
        # Often: "Site doesn't have a title" or 1st line is title
        m = re.search(r'["\']([^"\']+)["\']', text)
        if m:
            return m.group(1)[:500]
        line = text.split("\n", 1)[0].strip()
        return line[:500] if line else None

    if sid == "ssl-cert":
        for pat in (
            r"commonName=([^,\n]+)",
            r"subject:\s*([^\n]+)",
            r"Subject:\s*([^\n]+)",
        ):
            m = re.search(pat, text, re.I)
            if m:
                return m.group(1).strip()[:500]
        return text[:300]

    if sid == "smb-os-discovery":
        # Key=value pairs
        parts = []
        for key in ("OS", "Computer name", "Domain name", "Workgroup"):
            m = re.search(rf"{re.escape(key)}:\s*([^\n|]+)", text, re.I)
            if m:
                parts.append(f"{key}: {m.group(1).strip()}")
        return " | ".join(parts)[:500] if parts else text[:300]

    if sid == "vulners":
        # Count CVE-like tokens and show first few
        cves = re.findall(r"CVE-\d{4}-\d+", text)
        if cves:
            uniq = sorted(set(cves))
            head = ", ".join(uniq[:5])
            extra = f" (+{len(uniq) - 5} more)" if len(uniq) > 5 else ""
            return f"{len(uniq)} CVE refs: {head}{extra}"
        return text[:400]

    if sid in ("http-server-header", "ssh-hostkey"):
        line = text.split("\n", 1)[0].strip()
        return line[:400] if line else None

    # Default: first non-empty line, capped
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line[:400]
    return None


def collect_port_scripts(
    port_el: ET.Element, protocol: str, portid: int
) -> list[tuple[Optional[str], Optional[int], str, str]]:
    """List of (port_protocol, port_id, script_id, output)."""
    out: list[tuple[Optional[str], Optional[int], str, str]] = []
    for scr in port_el.findall("script"):
        sid = _attr(scr, "id") or ""
        raw = _attr(scr, "output") or ""
        if sid:
            out.append((protocol, portid, sid, raw))
    return out


def collect_host_scripts(host_el: ET.Element) -> list[tuple[Optional[str], Optional[int], str, str]]:
    out: list[tuple[Optional[str], Optional[int], str, str]] = []
    for block in ("hostscript", "postscript"):
        hs = host_el.find(block)
        if hs is None:
            continue
        for scr in hs.findall("script"):
            sid = _attr(scr, "id") or ""
            raw = _attr(scr, "output") or ""
            if sid:
                out.append((None, None, sid, raw))
    return out


def delete_scan_data(conn: sqlite3.Connection, scan_hash: str) -> None:
    """Remove all rows for a scan (for --force re-import)."""
    conn.execute("DELETE FROM nse_scripts WHERE scan_hash = ?", (scan_hash,))
    conn.execute("DELETE FROM traceroute_hops WHERE scan_hash = ?", (scan_hash,))
    conn.execute("DELETE FROM ports WHERE scan_hash = ?", (scan_hash,))
    conn.execute("DELETE FROM hosts WHERE scan_hash = ?", (scan_hash,))
    conn.execute("DELETE FROM scans WHERE scan_hash = ?", (scan_hash,))


def merge_tags_json(existing: str, new_tags: list[str]) -> str:
    try:
        cur = json.loads(existing) if existing else []
    except json.JSONDecodeError:
        cur = []
    if not isinstance(cur, list):
        cur = []
    seen = {str(x).strip() for x in cur if str(x).strip()}
    for t in new_tags:
        t = t.strip()
        if t and t not in seen:
            seen.add(t)
            cur.append(t)
    return json.dumps(cur, ensure_ascii=False)


def import_xml(
    conn: sqlite3.Connection,
    xml_path: Path,
    tags: list[str],
    skip_if_exists: bool,
    force: bool,
    vacuum: bool,
) -> str:
    tree = ET.parse(xml_path)
    root = tree.getroot()
    if root.tag != "nmaprun":
        raise ValueError(f"Not an nmaprun XML root: {xml_path}")

    command_line = _attr(root, "args") or ""
    start_time = _attr(root, "start") or _attr(root, "startstr") or ""
    if not start_time:
        raise ValueError("nmaprun missing start time; cannot compute scan_hash")

    scan_hash = compute_scan_hash(command_line, start_time)
    finished = _attr(root, "finished") or _attr(root, "finishedstr")
    nmap_version = _attr(root, "version") or _attr(root, "scanner")

    cur = conn.cursor()
    cur.execute("SELECT scan_hash, tags FROM scans WHERE scan_hash = ?", (scan_hash,))
    row = cur.fetchone()
    tags_base_for_insert = "[]"

    if row and skip_if_exists and not force:
        LOG.info("Skipping duplicate scan %s… (use --force to re-import)", scan_hash[:12])
        return scan_hash

    if row and force:
        tags_base_for_insert = row[1] or "[]"
        delete_scan_data(conn, scan_hash)
    elif row and not force:
        # Same hash, re-run without force: merge tags only, skip data duplicate
        LOG.info("Scan already imported; merging tags only (%s…)", scan_hash[:12])
        old_tags = row[1] or "[]"
        merged = merge_tags_json(old_tags, tags)
        cur.execute(
            "UPDATE scans SET tags = ?, xml_path = ?, imported_at = datetime('now') WHERE scan_hash = ?",
            (merged, str(xml_path.resolve()), scan_hash),
        )
        conn.commit()
        if vacuum:
            conn.execute("VACUUM")
        return scan_hash

    tags_json = merge_tags_json(tags_base_for_insert, tags)

    cur.execute(
        """
        INSERT INTO scans (scan_hash, command_line, start_time, finished_time, nmap_version, xml_path, tags)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(scan_hash) DO UPDATE SET
            finished_time = excluded.finished_time,
            nmap_version = excluded.nmap_version,
            xml_path = excluded.xml_path,
            tags = excluded.tags,
            imported_at = datetime('now')
        """,
        (scan_hash, command_line, start_time, finished, nmap_version, str(xml_path.resolve()), tags_json),
    )

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        state = _attr(status_el, "state") if status_el is not None else None
        addr, addrtype, mac, mac_vendor = pick_ipv4_address(host_el)
        if not addr:
            # Skip hosts without IP (e.g. placeholder)
            continue

        hostname = parse_hostname(host_el)
        os_name, os_accuracy = parse_os_best(host_el)
        uptime_s, lastboot = parse_uptime(host_el)
        distance = parse_distance(host_el)
        host_start = _attr(host_el, "starttime")
        host_end = _attr(host_el, "endtime")

        cur.execute(
            """
            INSERT INTO hosts (
                scan_hash, addr, addrtype, mac, mac_vendor, hostname, state,
                os_name, os_accuracy, uptime_seconds, lastboot, distance, host_start, host_end
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scan_hash, addr) DO UPDATE SET
                addrtype = excluded.addrtype,
                mac = excluded.mac,
                mac_vendor = excluded.mac_vendor,
                hostname = excluded.hostname,
                state = excluded.state,
                os_name = excluded.os_name,
                os_accuracy = excluded.os_accuracy,
                uptime_seconds = excluded.uptime_seconds,
                lastboot = excluded.lastboot,
                distance = excluded.distance,
                host_start = excluded.host_start,
                host_end = excluded.host_end
            """,
            (
                scan_hash,
                addr,
                addrtype,
                mac,
                mac_vendor,
                hostname,
                state,
                os_name,
                os_accuracy,
                uptime_s,
                lastboot,
                distance,
                host_start,
                host_end,
            ),
        )

        for hop in parse_traceroute(host_el):
            cur.execute(
                """
                INSERT INTO traceroute_hops (
                    scan_hash, host_addr, hop_index, ttl, ipaddr, rtt_ms, hop_host
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_hash, host_addr, hop_index) DO UPDATE SET
                    ttl = excluded.ttl,
                    ipaddr = excluded.ipaddr,
                    rtt_ms = excluded.rtt_ms,
                    hop_host = excluded.hop_host
                """,
                (
                    scan_hash,
                    addr,
                    hop["hop_index"],
                    hop["ttl"],
                    hop["ipaddr"],
                    hop["rtt_ms"],
                    hop["hop_host"],
                ),
            )

        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                proto = _attr(port_el, "protocol") or "tcp"
                pid = _int_attr(port_el, "portid")
                if pid is None:
                    continue
                st_el = port_el.find("state")
                pstate = _attr(st_el, "state") if st_el is not None else None
                svc = port_el.find("service")
                svc_name = _attr(svc, "name") if svc is not None else None
                product = _attr(svc, "product") if svc is not None else None
                version = _attr(svc, "version") if svc is not None else None
                extrainfo = _attr(svc, "extrainfo") if svc is not None else None

                cur.execute(
                    """
                    INSERT INTO ports (
                        scan_hash, host_addr, protocol, portid, state,
                        service_name, product, version, extrainfo
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(scan_hash, host_addr, protocol, portid) DO UPDATE SET
                        state = excluded.state,
                        service_name = excluded.service_name,
                        product = excluded.product,
                        version = excluded.version,
                        extrainfo = excluded.extrainfo
                    """,
                    (
                        scan_hash,
                        addr,
                        proto,
                        pid,
                        pstate,
                        svc_name,
                        product,
                        version,
                        extrainfo,
                    ),
                )

                for pp, pn, sid, raw in collect_port_scripts(port_el, proto, pid):
                    summ = summarize_nse_output(sid, raw)
                    cur.execute(
                        """
                        INSERT INTO nse_scripts (
                            scan_hash, host_addr, port_protocol, port_id, script_id, output, output_summary
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (scan_hash, addr, pp, pn, sid, raw, summ),
                    )

        for pp, pn, sid, raw in collect_host_scripts(host_el):
            summ = summarize_nse_output(sid, raw)
            cur.execute(
                """
                INSERT INTO nse_scripts (
                    scan_hash, host_addr, port_protocol, port_id, script_id, output, output_summary
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (scan_hash, addr, pp, pn, sid, raw, summ),
            )

    conn.commit()
    if vacuum:
        conn.execute("VACUUM")
    LOG.info("Imported %s → scan_hash=%s", xml_path.name, scan_hash)
    return scan_hash


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Import Nmap XML into SQLite (multi-scan, tags, traceroute, NSE)."
    )
    p.add_argument("xml_files", nargs="+", type=Path, help="Nmap XML file(s) (-oX)")
    p.add_argument(
        "-d",
        "--database",
        type=Path,
        default=Path("nmap_scans.db"),
        help="SQLite database path (default: ./nmap_scans.db)",
    )
    p.add_argument(
        "--tag",
        action="append",
        default=[],
        metavar="TAG",
        help="Tag for this import (repeatable). Merged with existing tags on duplicate scan.",
    )
    p.add_argument(
        "--tags-json",
        type=str,
        default=None,
        help='JSON array of tags, e.g. \'["DMZ","weekly"]\' (combined with --tag)',
    )
    p.add_argument(
        "--skip-if-exists",
        action="store_true",
        help="If scan_hash already exists, skip file entirely (no tag merge).",
    )
    p.add_argument(
        "--force",
        action="store_true",
        help="Re-import: delete existing rows for this scan_hash then insert fresh data.",
    )
    p.add_argument(
        "--vacuum",
        action="store_true",
        help="Run VACUUM after each imported file (slower; shrinks DB).",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    return p.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    tag_list = list(args.tag or [])
    if args.tags_json:
        try:
            extra = json.loads(args.tags_json)
            if isinstance(extra, list):
                tag_list.extend(str(x) for x in extra)
            else:
                LOG.error("--tags-json must be a JSON array")
                return 2
        except json.JSONDecodeError as e:
            LOG.error("Invalid --tags-json: %s", e)
            return 2

    db_path: Path = args.database
    db_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        conn = sqlite3.connect(str(db_path))
    except sqlite3.Error as e:
        LOG.error("Cannot open database %s: %s", db_path, e)
        return 1

    try:
        ensure_schema(conn)
        for xf in args.xml_files:
            if not xf.is_file():
                LOG.error("File not found: %s", xf)
                return 1
            try:
                import_xml(
                    conn,
                    xf,
                    tags=tag_list,
                    skip_if_exists=args.skip_if_exists,
                    force=args.force,
                    vacuum=args.vacuum,
                )
            except (ET.ParseError, ValueError) as e:
                LOG.error("%s: %s", xf, e)
                return 1
            except sqlite3.Error as e:
                LOG.error("SQLite error on %s: %s", xf, e)
                return 1
    finally:
        conn.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
