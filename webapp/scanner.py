"""
Concurrent nmap execution + import into SQLite (non-blocking for NiceGUI).
"""

from __future__ import annotations

import asyncio
import shlex
import sqlite3
import sys
import uuid
from collections import deque
from datetime import datetime
from typing import Callable

import config
from models import ScanJob, ScanJobStatus


def normalize_target(raw: str) -> str:
    """IPs, CIDRs: separados por comas o por líneas → argumentos para nmap."""
    t = raw.strip()
    if not t:
        raise ValueError("Target vacío")
    parts: list[str] = []
    for chunk in t.replace("\n", ",").split(","):
        s = chunk.strip()
        if s:
            parts.append(s)
    return " ".join(parts)


def _safe_target_display(t: str) -> str:
    return t[:500]


def preview_pipeline_markdown(target_raw: str) -> str:
    """
    Texto para la UI: comandos que se ejecutarán y destino de la base de datos.
    """
    db = config.SQLITE_PATH.resolve()
    xml_dir = config.XML_OUTPUT_DIR.resolve()
    imp = config.NMAP_TO_SQLITE.resolve()
    try:
        nt = normalize_target(target_raw)
    except ValueError as e:
        return f"**{e}** — escribe al menos un objetivo (IP, CIDR o lista separada por comas)."

    xml_example = str(xml_dir / "ui_<job_id>_<timestamp>.xml")
    nmap_parts = [
        config.NMAP_BINARY,
        *config.NMAP_EXTRA_ARGS,
        "-oX",
        xml_example,
        *nt.split(),
    ]
    nmap_line = " ".join(shlex.quote(p) for p in nmap_parts)
    imp_line = (
        f"{shlex.quote(sys.executable)} {shlex.quote(str(imp))} "
        f"-d {shlex.quote(str(db))} --tag webui "
        f"`{xml_dir}/ui_<job_id>_<timestamp>.xml`"
    )
    exists = "✓ existe" if config.NMAP_TO_SQLITE.is_file() else "✗ no encontrado (revisa ruta)"
    return (
        f"**Destino de datos:** `{db}`  \n"
        f"**Importador:** `{imp}` ({exists})  \n\n"
        "---\n\n"
        "**Paso 1 — Nmap** (genera XML):\n\n"
        f"`{nmap_line}`\n\n"
        "**Paso 2 — Importación** (escribe en SQLite, mismo fichero que usa Grafana):\n\n"
        f"`{imp_line}`\n\n"
        "Tras un **IMPORT_OK** en el log, las tablas `scans`, `hosts`, `ports` y `nse_scripts` "
        "incluyen este run."
    )


class ScanManager:
    """
    Runs multiple nmap processes concurrently (bounded by semaphore).
    Each job captures merged stdout/stderr as live logs.
    """

    def __init__(self, max_concurrent: int | None = None) -> None:
        self._sem = asyncio.Semaphore(max_concurrent or config.MAX_CONCURRENT_SCANS)
        self.jobs: dict[str, ScanJob] = {}
        self._processes: dict[str, asyncio.subprocess.Process] = {}
        self._lock = asyncio.Lock()
        self._on_update: Callable[[], None] | None = None

    def set_notify(self, fn: Callable[[], None] | None) -> None:
        """Optional UI refresh callback (e.g. bump a counter for ui.timer)."""
        self._on_update = fn

    async def _notify_safe(self) -> None:
        if self._on_update:
            try:
                self._on_update()
            except Exception:
                pass

    async def list_jobs_ordered(self) -> list[ScanJob]:
        async with self._lock:
            return sorted(self.jobs.values(), key=lambda j: j.started_at or 0, reverse=True)

    async def get_job(self, job_id: str) -> ScanJob | None:
        async with self._lock:
            return self.jobs.get(job_id)

    async def start_scan(self, target: str, tag: str = "webui") -> str:
        nt = normalize_target(target)
        job_id = uuid.uuid4().hex[:12]
        job = ScanJob(id=job_id, target=_safe_target_display(nt))
        async with self._lock:
            self.jobs[job_id] = job
        asyncio.create_task(self._run_pipeline(job, nt, tag))
        await self._notify_safe()
        return job_id

    async def _run_pipeline(self, job: ScanJob, target: str, tag: str) -> None:
        async with self._sem:
            job.status = ScanJobStatus.RUNNING
            job.started_at = datetime.now().timestamp()
            job.append_log(f"[{job.id}] Inicio: {target}")
            await self._notify_safe()

            config.XML_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
            xml_path = config.XML_OUTPUT_DIR / f"ui_{job.id}_{int(job.started_at)}.xml"

            cmd = [
                config.NMAP_BINARY,
                *config.NMAP_EXTRA_ARGS,
                "-oX",
                str(xml_path),
                *target.split(),
            ]
            job.append_log("$ " + " ".join(cmd))

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
                async with self._lock:
                    self._processes[job.id] = proc
                assert proc.stdout
                while True:
                    line = await proc.stdout.readline()
                    if not line:
                        break
                    job.append_log(line.decode(errors="replace").rstrip())
                    await self._notify_safe()
                job.exit_code = await proc.wait()
            except asyncio.CancelledError:
                job.status = ScanJobStatus.STOPPED
                job.append_log("Cancelado.")
                raise
            except Exception as e:
                job.status = ScanJobStatus.FAILED
                job.error_message = str(e)
                job.append_log(f"ERROR: {e}")
                job.exit_code = -1
            finally:
                async with self._lock:
                    self._processes.pop(job.id, None)

            if job.status == ScanJobStatus.STOPPED:
                await self._notify_safe()
                return

            if job.exit_code != 0:
                job.status = ScanJobStatus.FAILED
                job.append_log(f"nmap terminó con código {job.exit_code}")
                await self._notify_safe()
                return

            if not xml_path.is_file() or xml_path.stat().st_size == 0:
                job.status = ScanJobStatus.FAILED
                job.error_message = "XML vacío o inexistente"
                await self._notify_safe()
                return

            job.xml_path = str(xml_path.resolve())
            job.append_log("Importando a SQLite…")
            imp_cmd = [
                sys.executable,
                str(config.NMAP_TO_SQLITE.resolve()),
                "-d",
                str(config.SQLITE_PATH.resolve()),
                "--tag",
                tag,
                job.xml_path,
            ]
            job.append_log("$ " + " ".join(shlex.quote(p) for p in imp_cmd))
            await self._notify_safe()

            imp = await asyncio.get_event_loop().run_in_executor(
                None,
                self._import_xml_sync,
                job.xml_path,
                tag,
            )
            job.append_log(imp)
            if imp.startswith("IMPORT_OK"):
                job.status = ScanJobStatus.COMPLETED
            else:
                job.status = ScanJobStatus.FAILED
                job.error_message = imp

            job.finished_at = datetime.now().timestamp()
            await self._notify_safe()

    @staticmethod
    def _import_xml_sync(xml_path: str, tag: str) -> str:
        import subprocess

        if not config.NMAP_TO_SQLITE.is_file():
            return "IMPORT_FAIL: nmap-to-sqlite.py no encontrado"
        r = subprocess.run(
            [
                sys.executable,
                str(config.NMAP_TO_SQLITE),
                "-d",
                str(config.SQLITE_PATH),
                "--tag",
                tag,
                xml_path,
            ],
            capture_output=True,
            text=True,
            timeout=600,
        )
        if r.returncode != 0:
            return f"IMPORT_FAIL: {r.stderr or r.stdout or r.returncode}"
        try:
            conn = sqlite3.connect(str(config.SQLITE_PATH.resolve()), timeout=30.0)
            row = conn.execute(
                """
                SELECT s.scan_hash, s.imported_at,
                       (SELECT COUNT(*) FROM hosts h WHERE h.scan_hash = s.scan_hash),
                       (SELECT COUNT(*) FROM ports p WHERE p.scan_hash = s.scan_hash)
                FROM scans s
                ORDER BY datetime(s.imported_at) DESC
                LIMIT 1
                """
            ).fetchone()
            conn.close()
        except sqlite3.Error as e:
            return f"IMPORT_OK (no se pudo verificar DB: {e})"
        if row:
            h, p = int(row[2] or 0), int(row[3] or 0)
            return (
                f"IMPORT_OK → escrito en {config.SQLITE_PATH.name} | "
                f"scan …{row[0][:12]} | {row[1]} | hosts={h} puertos={p}"
            )
        return "IMPORT_OK (tabla scans vacía tras import — revisa permisos o ruta DB)"

    async def stop_scan(self, job_id: str) -> bool:
        async with self._lock:
            proc = self._processes.get(job_id)
            job = self.jobs.get(job_id)
        if proc is None or job is None:
            return False
        if job.status != ScanJobStatus.RUNNING:
            return False
        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            proc.kill()
        except ProcessLookupError:
            pass
        job.status = ScanJobStatus.STOPPED
        job.append_log("Detenido por el usuario.")
        job.finished_at = datetime.now().timestamp()
        await self._notify_safe()
        return True


# Global manager (wired from main)
scan_manager = ScanManager()
