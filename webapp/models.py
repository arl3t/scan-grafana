"""
Dataclasses for scan jobs, schedules, and DB row shapes.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal


class ScanJobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


class ScheduleFrequency(str, Enum):
    ONCE = "once"
    HOURLY = "hourly"
    EVERY_6H = "every_6h"
    EVERY_12H = "every_12h"
    DAILY = "daily"


@dataclass
class ScanJob:
    """In-memory scan execution tracked by the UI."""

    id: str
    target: str
    status: ScanJobStatus = ScanJobStatus.QUEUED
    started_at: float | None = None
    finished_at: float | None = None
    exit_code: int | None = None
    xml_path: str | None = None
    error_message: str | None = None
    logs: deque[str] = field(default_factory=lambda: deque(maxlen=2000))

    def append_log(self, line: str) -> None:
        self.logs.append(line.rstrip())


@dataclass
class ScheduledJobSpec:
    """Serializable schedule definition (persisted to JSON)."""

    id: str
    target: str
    frequency: ScheduleFrequency
    # ISO datetime for next one-shot run (frequency == ONCE)
    run_at_iso: str | None = None
    enabled: bool = True
    label: str = ""


@dataclass
class ScanRow:
    """Row for history table."""

    scan_hash: str
    imported_at: str
    command_line: str
    tags: str
    xml_path: str | None


@dataclass
class ChangeHighlight:
    """MAC or new-port highlight for dashboard cards."""

    kind: Literal["mac_change", "new_port"]
    host_addr: str
    detail: str
    seen_at: str


@dataclass
class PortRow:
    host_addr: str
    protocol: str
    portid: int
    service_name: str | None
    product: str | None
    version: str | None


@dataclass
class NseRow:
    script_id: str
    host_addr: str
    port_id: int | None
    output_summary: str | None
    output: str | None
