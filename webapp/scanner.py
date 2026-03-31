"""
Concurrent nmap execution + import into SQLite (non-blocking for NiceGUI).
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from collections import deque
from datetime import datetime
from typing import Callable

import config
from models import ScanJob, ScanJobStatus


def normalize_target(raw: str) -> str:
    """Turn comma-separated IPs into nmap target string."""
    t = raw.strip()
    if not t:
        raise ValueError("Target vacío")
    # allow single string with commas
    parts = [p.strip() for p in t.split(",") if p.strip()]
    return " ".join(parts)


def _safe_target_display(t: str) -> str:
    return t[:500]


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
        if r.returncode == 0:
            return "IMPORT_OK"
        return f"IMPORT_FAIL: {r.stderr or r.stdout or r.returncode}"

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
