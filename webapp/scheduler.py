"""
Persistent scan scheduling on top of APScheduler (asyncio).
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Awaitable, Callable

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger

import config
from models import ScheduleFrequency, ScheduledJobSpec

ScanRunner = Callable[[str], Awaitable[str]]


def _store_path() -> Path:
    config.SCHEDULE_STORE.parent.mkdir(parents=True, exist_ok=True)
    return config.SCHEDULE_STORE


def load_specs() -> list[ScheduledJobSpec]:
    p = _store_path()
    if not p.is_file():
        return []
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    out: list[ScheduledJobSpec] = []
    for item in raw:
        try:
            out.append(
                ScheduledJobSpec(
                    id=item["id"],
                    target=item["target"],
                    frequency=ScheduleFrequency(item["frequency"]),
                    run_at_iso=item.get("run_at_iso"),
                    enabled=bool(item.get("enabled", True)),
                    label=item.get("label", ""),
                )
            )
        except (KeyError, ValueError):
            continue
    return out


def save_specs(specs: list[ScheduledJobSpec]) -> None:
    data = []
    for s in specs:
        d = asdict(s)
        d["frequency"] = s.frequency.value
        data.append(d)
    _store_path().write_text(json.dumps(data, indent=2), encoding="utf-8")


class ScheduleService:
    def __init__(self) -> None:
        self.scheduler = AsyncIOScheduler(timezone=config.SCHEDULER_TIMEZONE)
        self._specs: list[ScheduledJobSpec] = []
        self._runner: ScanRunner | None = None

    def set_runner(self, runner: ScanRunner) -> None:
        self._runner = runner

    def start(self) -> None:
        if not self.scheduler.running:
            self.scheduler.start()
        self._specs = load_specs()
        for s in self._specs:
            if s.enabled:
                try:
                    self._register_ap_job(s, replace_existing=True)
                except Exception:
                    continue

    def shutdown(self) -> None:
        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)

    def list_specs(self) -> list[ScheduledJobSpec]:
        return list(self._specs)

    async def _execute(self, target: str, schedule_id: str | None = None) -> None:
        if self._runner is None:
            return
        await self._runner(target)
        # one-shot cleanup
        if schedule_id:
            spec = next((x for x in self._specs if x.id == schedule_id), None)
            if spec and spec.frequency == ScheduleFrequency.ONCE:
                self.remove_schedule(schedule_id)

    def _trigger_for(self, spec: ScheduledJobSpec) -> Any:
        if spec.frequency == ScheduleFrequency.ONCE:
            if not spec.run_at_iso:
                raise ValueError("run_at_iso requerido para ejecución única")
            raw = spec.run_at_iso.strip().replace(" ", "T", 1)
            dt = datetime.fromisoformat(raw)
            return DateTrigger(run_date=dt)
        if spec.frequency == ScheduleFrequency.HOURLY:
            return IntervalTrigger(hours=1)
        if spec.frequency == ScheduleFrequency.EVERY_6H:
            return IntervalTrigger(hours=6)
        if spec.frequency == ScheduleFrequency.EVERY_12H:
            return IntervalTrigger(hours=12)
        if spec.frequency == ScheduleFrequency.DAILY:
            return CronTrigger(hour=0, minute=5)
        raise ValueError(spec.frequency)

    def _register_ap_job(self, spec: ScheduledJobSpec, replace_existing: bool = False) -> None:
        trigger = self._trigger_for(spec)
        sid_once = spec.id if spec.frequency == ScheduleFrequency.ONCE else None

        async def _fire() -> None:
            await self._execute(spec.target, sid_once)

        self.scheduler.add_job(
            _fire,
            trigger,
            id=f"sched_{spec.id}",
            replace_existing=replace_existing,
            misfire_grace_time=300,
        )

    def add_schedule(
        self,
        target: str,
        frequency: ScheduleFrequency,
        run_at_iso: str | None = None,
        label: str = "",
    ) -> ScheduledJobSpec:
        spec = ScheduledJobSpec(
            id=uuid.uuid4().hex[:16],
            target=target.strip(),
            frequency=frequency,
            run_at_iso=run_at_iso,
            enabled=True,
            label=label,
        )
        self._trigger_for(spec)  # validate
        self._specs.append(spec)
        save_specs(self._specs)
        self._register_ap_job(spec)
        return spec

    def remove_schedule(self, schedule_id: str) -> bool:
        self._specs = [s for s in self._specs if s.id != schedule_id]
        save_specs(self._specs)
        try:
            self.scheduler.remove_job(f"sched_{schedule_id}")
        except Exception:
            pass
        return True


schedule_service = ScheduleService()
