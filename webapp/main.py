#!/usr/bin/env python3
"""
NiceGUI web UI: concurrent nmap scans, scheduling, SQLite history, live verbose terminal.
Run: python main.py   (from the webapp/ directory)
"""

from __future__ import annotations

import asyncio
import webbrowser
from typing import Any

from nicegui import app, ui

import config
import database as db
from models import ScanJobStatus, ScheduleFrequency
from scanner import preview_pipeline_markdown, scan_manager
from scheduler import schedule_service


class _Tick:
    __slots__ = ("n",)

    def __init__(self) -> None:
        self.n = 0

    def bump(self) -> None:
        self.n += 1


TICK = _Tick()
scan_manager.set_notify(TICK.bump)


def _grafana_url(path: str) -> str:
    p = path if path.startswith("/") else f"/{path}"
    return f"{config.GRAFANA_BASE_URL}{p}"


def _load_repo_markdown(relative_path: str) -> str:
    """Carga un .md bajo la raíz del repo (solo rutas relativas fijas en código)."""
    root = config.REPO_ROOT.resolve()
    path = (root / relative_path).resolve()
    if not str(path).startswith(str(root)) or not path.is_file():
        return f"*No se encontró la documentación en `{relative_path}`.*"
    try:
        return path.read_text(encoding="utf-8")
    except OSError as e:
        return f"*Error al leer `{relative_path}`: {e}*"


def _terminal_line_classes(line: str) -> str | None:
    """Clases Tailwind por tipo de línea (verbose nmap / import)."""
    if line.startswith("$"):
        return "text-amber-400/90 cyber-font-mono"
    if "IMPORT_OK" in line:
        return "text-emerald-400 font-medium cyber-font-mono"
    if "IMPORT_FAIL" in line or line.startswith("ERROR"):
        return "text-red-400 cyber-font-mono"
    if "Starting Nmap" in line or "Nmap done" in line or "Nmap scan report" in line:
        return "text-cyan-300/90 cyber-font-mono"
    return "text-[#6ee7b7]/80 cyber-font-mono"


def _log_push(log_el: Any, line: str, classes: str | None = None) -> None:
    try:
        if classes:
            log_el.push(line, classes=classes)
        else:
            log_el.push(line)
    except TypeError:
        log_el.push(line)


def _clear_scan_terminal(log_el: Any, term_state: dict[str, dict[str, int]]) -> None:
    log_el.clear()
    term_state["seen"].clear()


def _setup_theme() -> None:
    """Tailwind + tipografía y estilo «cyber / SOC» (oscuro, rejilla, acentos)."""
    try:
        ui.add_head_html(
            '<script src="https://cdn.tailwindcss.com"></script>',
            shared=True,
        )
    except TypeError:
        ui.add_head_html('<script src="https://cdn.tailwindcss.com"></script>')
    ui.add_head_html(
        """
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Share+Tech+Mono&display=swap" rel="stylesheet">
<style>
  html, body { background: #05080c !important; }
  .q-page, .q-layout { background: transparent !important; }
  .cyber-grid-bg {
    background-color: #05080c;
    background-image:
      linear-gradient(rgba(16, 185, 129, 0.045) 1px, transparent 1px),
      linear-gradient(90deg, rgba(16, 185, 129, 0.045) 1px, transparent 1px),
      radial-gradient(ellipse 80% 50% at 50% -20%, rgba(34, 211, 238, 0.12), transparent);
    background-size: 28px 28px, 28px 28px, 100% 100%;
  }
  .cyber-font-head {
    font-family: "Share Tech Mono", "JetBrains Mono", ui-monospace, monospace;
    letter-spacing: 0.12em;
  }
  .cyber-font-mono {
    font-family: "JetBrains Mono", ui-monospace, monospace;
  }
  @keyframes cyber-blink {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.25; }
  }
  .cyber-live-dot::before {
    content: "";
    display: inline-block;
    width: 8px;
    height: 8px;
    margin-right: 8px;
    border-radius: 50%;
    background: #34d399;
    box-shadow: 0 0 10px #34d399;
    animation: cyber-blink 1.8s ease-in-out infinite;
    vertical-align: middle;
  }
</style>
""",
        shared=True,
    )


# Clases reutilizables (Tailwind)
_C_CARD = (
    "rounded-xl border border-emerald-500/20 bg-zinc-950/80 backdrop-blur-md "
    "shadow-[0_0_0_1px_rgba(16,185,129,0.06),0_12px_40px_rgba(0,0,0,0.45)]"
)
# Barra superior (no usar ui.header dentro de ui.column: NiceGUI exige layout top-level directo al page)
_C_TOPBAR = (
    "w-full items-center justify-between flex-wrap gap-3 border-b border-emerald-500/25 "
    "bg-[#0a1018]/95 backdrop-blur-md shadow-[0_4px_24px_rgba(0,0,0,0.5)] px-4 py-3"
)


@ui.page("/")
def page_dashboard() -> None:
    _setup_theme()
    ui.dark_mode(True)

    with ui.column().classes("w-full min-h-screen cyber-grid-bg"):
        with ui.row().classes(_C_TOPBAR):
            with ui.row().classes("items-center gap-3"):
                ui.label("SEC // SCAN").classes(
                    "text-lg sm:text-xl font-bold text-emerald-400 cyber-font-head uppercase"
                )
                ui.label("operational").classes(
                    "cyber-live-dot text-[10px] sm:text-xs text-slate-500 uppercase tracking-widest cyber-font-head"
                )
            with ui.row().classes("gap-2 items-center"):
                ui.button(icon="history", on_click=lambda: ui.navigate.to("/history")).props(
                    "flat color=grey"
                ).tooltip("Historial SQLite")
                ui.button(icon="shield", on_click=lambda: ui.navigate.to("/blue-team")).props(
                    "flat color=grey"
                ).tooltip("Blue Team — guías ART, Wireshark, OpenVAS")
                ui.link("Grafana ↗", _grafana_url(config.GRAFANA_MAIN_DASHBOARD_PATH), new_tab=True).classes(
                    "text-cyan-400 text-sm cyber-font-mono hover:text-cyan-300"
                )

        with ui.column().classes("w-full max-w-7xl mx-auto p-4 sm:p-6 gap-6"):
            with ui.card().classes(f"w-full {_C_CARD} border-l-4 border-l-emerald-500/50"):
                ui.label("// Guía y buenas prácticas").classes(
                    "text-emerald-400/90 font-semibold text-sm mb-2 cyber-font-head"
                )
                ui.markdown(config.SCAN_QUICK_TIPS_MARKDOWN.strip()).classes("text-slate-300 text-sm")

            with ui.card().classes(f"w-full {_C_CARD} border-l-4 border-l-cyan-500/35"):
                ui.label("// Blue Team (laboratorio)").classes(
                    "text-cyan-400/90 font-semibold text-sm mb-2 cyber-font-head"
                )
                ui.markdown(
                    "Guías en esta consola: **Atomic Red Team** (MITRE ATT&CK), **Wireshark/tshark** "
                    "y **OpenVAS / Greenbone** — solo en entornos **autorizados**."
                ).classes("text-slate-300 text-sm mb-3")
                ui.button(
                    "Abrir guía Blue Team",
                    icon="menu_book",
                    on_click=lambda: ui.navigate.to("/blue-team"),
                ).props("outline color=cyan")

            with ui.card().classes(f"w-full {_C_CARD}"):
                ui.label("// Nuevo escaneo").classes(
                    "text-lg font-medium text-slate-100 mb-1 cyber-font-head text-cyan-400/90"
                )

                preset_sel = ui.select(
                    config.PRESET_LABELS,
                    value=config.SCAN_PRESET_STANDARD,
                    label="Tipo de escaneo (perfil Nmap)",
                ).classes("w-full max-w-2xl").props("outlined dense dark")

                with ui.column().classes(
                    "w-full mt-3 rounded-xl border-2 border-cyan-500/50 bg-black/40 p-4 "
                    "shadow-[inset_0_0_20px_rgba(34,211,238,0.06)]"
                ):
                    ui.label("▸ Red u objetivos").classes(
                        "text-cyan-300 font-semibold text-sm tracking-wide cyber-font-head"
                    )
                    ui.label("Campo de texto — hosts, CIDR o rangos").classes(
                        "text-slate-500 text-xs mb-2 -mt-0.5 cyber-font-mono"
                    )
                    target_in = ui.textarea(
                        placeholder=(
                            "Ej.: 192.168.1.0/24\n"
                            "172.30.8.1-50\n"
                            "10.0.0.1, 10.0.0.2\n"
                            "(una red por línea o separadas por comas)"
                        )
                    ).classes("w-full cyber-font-mono").props("outlined dark rows=5 color=cyan")

                db_stat = ui.label("").classes(
                    "text-emerald-300/90 text-xs mt-2 font-mono break-all cyber-font-mono"
                )
                ui.label(
                    "Cada escaneo se guarda solo en XML (`-oX` en `xml_scans/`) y ese fichero es lo que se importa a "
                    "`nmap_scans.db` (Grafana). No se generan -oN/-oG/-oA desde la consola."
                ).classes("text-slate-500 text-xs mt-1")

                with ui.expansion(
                    "Cómo se ejecuta el escaneo (3 perfiles, comandos y destino DB)",
                    icon="terminal",
                ).classes("w-full bg-black/30 border border-emerald-900/40 mt-3 rounded-lg"):
                    ui.markdown(config.scan_profiles_help_markdown().strip()).classes(
                        "text-slate-300 text-sm max-w-none mb-4"
                    )
                    ui.element("hr").classes("w-full border-0 border-t border-slate-600 my-3")
                    ui.label("Vista previa con tu objetivo y perfil seleccionados").classes(
                        "text-slate-400 text-xs uppercase tracking-wide mb-1 cyber-font-head"
                    )
                    cmd_preview = ui.markdown("Escribe un objetivo arriba para ver la vista previa.").classes(
                        "text-slate-300 text-sm max-w-none cyber-font-mono"
                    )

                    def refresh_cmd_preview() -> None:
                        pid = preset_sel.value or config.SCAN_PRESET_STANDARD
                        cmd_preview.content = preview_pipeline_markdown(target_in.value or "", pid)
                        cmd_preview.update()

                    ui.timer(0.7, refresh_cmd_preview)
                    refresh_cmd_preview()

                with ui.row().classes("w-full gap-3 flex-wrap items-end mt-4"):
                    ui.button("Ejecutar scan ahora", icon="radar", color="cyan").classes(
                        "px-6 py-3 text-base font-medium cyber-font-head"
                    ).on_click(lambda: asyncio.create_task(_run_now(target_in, preset_sel)))

                    freq_sel = ui.select(
                        {
                            ScheduleFrequency.ONCE.value: "Una vez (elige fecha/hora)",
                            ScheduleFrequency.HOURLY.value: "Cada hora",
                            ScheduleFrequency.EVERY_6H.value: "Cada 6 horas",
                            ScheduleFrequency.EVERY_12H.value: "Cada 12 horas",
                            ScheduleFrequency.DAILY.value: "Diario (00:05)",
                        },
                        value=ScheduleFrequency.HOURLY.value,
                        label="Programar",
                    ).classes("min-w-64").props("outlined dense dark")

                    once_dt = ui.input("Fecha/hora (solo «Una vez»)").classes("min-w-56").props(
                        "outlined dense dark type=datetime-local"
                    )

                    async def _sched() -> None:
                        try:
                            raw = target_in.value or ""
                            f = ScheduleFrequency(freq_sel.value)
                            run_at = (once_dt.value or "").strip()
                            if f == ScheduleFrequency.ONCE:
                                if not run_at:
                                    ui.notify("Indica fecha/hora para ejecución única.", type="warning")
                                    return
                                iso = run_at.replace("T", " ")
                                if len(iso) == 16:
                                    iso += ":00"
                                schedule_service.add_schedule(raw, f, run_at_iso=iso, label="UI")
                            else:
                                schedule_service.add_schedule(raw, f, label="UI")
                            ui.notify("Programación guardada.", type="positive")
                            TICK.bump()
                        except Exception as e:
                            ui.notify(str(e), type="negative")

                    ui.button(
                        "Añadir programación",
                        icon="schedule",
                        on_click=lambda: asyncio.create_task(_sched()),
                    ).props("outline color=white")

                def refresh_db_banner() -> None:
                    n, err = db.scans_db_banner()
                    p = db.sqlite_path_resolved()
                    line = f"Base de datos: {p}  ·  scans almacenados: {n}"
                    if err:
                        line += f"\n⚠ {err}"
                        db_stat.classes(remove="text-emerald-300/90", add="text-amber-300/90")
                    else:
                        db_stat.classes(remove="text-amber-300/90", add="text-emerald-300/90")
                    db_stat.set_text(line)

                ui.timer(3.0, refresh_db_banner)
                refresh_db_banner()

            with ui.row().classes("w-full gap-4 flex-wrap"):
                with ui.card().classes(f"{_C_CARD} p-4 min-w-[200px] flex-1"):
                    ui.label("// En ejecución").classes(
                        "text-cyan-400 font-semibold text-sm uppercase tracking-wide cyber-font-head"
                    )
                    lbl_run = ui.label("…").classes("text-slate-200 text-sm whitespace-pre-wrap cyber-font-mono")
                with ui.card().classes(f"{_C_CARD} p-4 min-w-[200px] flex-1 border-violet-500/20"):
                    ui.label("// Programados").classes(
                        "text-violet-400 font-semibold text-sm uppercase tracking-wide cyber-font-head"
                    )
                    lbl_sch = ui.label("…").classes("text-slate-200 text-sm whitespace-pre-wrap cyber-font-mono")
                with ui.card().classes(f"{_C_CARD} p-4 min-w-[200px] flex-1 border-amber-500/25"):
                    ui.label("// Δ 24h").classes(
                        "text-amber-400 font-semibold text-sm uppercase tracking-wide cyber-font-head"
                    )
                    lbl_chg = ui.label("…").classes(
                        "text-slate-200 text-sm whitespace-pre-wrap text-xs cyber-font-mono"
                    )
                with ui.card().classes(f"{_C_CARD} p-4 min-w-[200px] flex-1"):
                    ui.label("// Totales DB").classes(
                        "text-emerald-400 font-semibold text-sm uppercase tracking-wide cyber-font-head"
                    )
                    lbl_cnt = ui.label("…").classes("text-slate-200 text-sm whitespace-pre-wrap cyber-font-mono")

            async def refresh_summary() -> None:
                jobs = await scan_manager.list_jobs_ordered()
                running = [j for j in jobs if j.status == ScanJobStatus.RUNNING]
                queued = [j for j in jobs if j.status == ScanJobStatus.QUEUED]
                lbl_run.set_text(
                    f"Running: {len(running)}  |  Cola: {len(queued)}\n"
                    + ("\n".join(f"• {j.id} {j.target[:40]}" for j in running[:5]) if running else "—")
                )
                specs = schedule_service.list_specs()
                en = [s for s in specs if s.enabled]
                lines_s = "\n".join(f"• {s.frequency.value}: {s.target[:36]}" for s in en[:6]) or "—"
                lbl_sch.set_text(f"Activos: {len(en)}\n{lines_s}")
                try:
                    macs = db.get_mac_changes_last_hours(24)
                    ports = db.get_new_open_ports_last_hours(24)
                    lines = [f"[MAC] {m.host_addr} {m.detail}" for m in macs[:4]]
                    lines += [f"[PORT] {p.host_addr} {p.detail}" for p in ports[:4]]
                    lbl_chg.set_text("\n".join(lines) if lines else "Sin cambios detectados en 24h.")
                except Exception as ex:
                    lbl_chg.set_text(f"(DB) {ex}")
                try:
                    lbl_cnt.set_text(
                        f"Hoy: {db.count_scans_today()} scans\n"
                        f"Últimos 7 días: {db.count_scans_this_week()}\n"
                        f"SQLite: {config.SQLITE_PATH}"
                    )
                except Exception as ex:
                    lbl_cnt.set_text(str(ex))

            ui.label("// Jobs activos / recientes").classes(
                "text-slate-300 text-lg font-medium mt-2 cyber-font-head text-cyan-500/80"
            )
            active_box = ui.column().classes("w-full gap-3")

            async def rebuild_active() -> None:
                jobs = await scan_manager.list_jobs_ordered()
                active_box.clear()
                _fill_active_cards(active_box, jobs)

            with ui.card().classes(f"w-full {_C_CARD}"):
                ui.label("// Terminal en vivo").classes(
                    "text-lg font-medium text-slate-100 mb-1 cyber-font-head text-emerald-400/90"
                )
                ui.label(
                    "Salida en tiempo real de nmap y del import a SQLite. "
                    "Grafana desde el header."
                ).classes("text-slate-500 text-xs mb-3")

                term_log = (
                    ui.log(max_lines=2000)
                    .classes(
                        "w-full rounded-lg border border-emerald-500/25 bg-[#030708] p-2 "
                        "cyber-font-mono text-[13px] leading-snug shadow-[inset_0_0_32px_rgba(0,0,0,0.6)]"
                    )
                    .style("min-height: 52vh; max-height: 72vh; overflow-y: auto")
                )
                term_state: dict[str, dict[str, int]] = {"seen": {}}

                with ui.row().classes("gap-3 flex-wrap items-center mb-2"):
                    only_running = ui.checkbox("Solo scans en ejecución", value=False).classes(
                        "text-slate-300 text-sm cyber-font-mono"
                    )
                    ui.label(
                        "(Jobs terminados siguen mostrando IMPORT_OK si aplica.)"
                    ).classes("text-slate-500 text-xs max-w-md")
                    ui.button(
                        "Limpiar terminal",
                        icon="delete_sweep",
                        on_click=lambda: _clear_scan_terminal(term_log, term_state),
                    ).props("outline dense color=grey")
                    ui.link(
                        "Dashboard Grafana ↗",
                        _grafana_url(config.GRAFANA_MAIN_DASHBOARD_PATH),
                        new_tab=True,
                    ).classes("text-cyan-400 text-sm cyber-font-mono")
                    ui.button(
                        icon="open_in_browser",
                        on_click=lambda: webbrowser.open(_grafana_url(config.GRAFANA_MAIN_DASHBOARD_PATH)),
                    ).props("flat dense color=cyan")

                async def tail_verbose_terminal() -> None:
                    jobs = await scan_manager.list_jobs_ordered()
                    seen: dict[str, int] = term_state["seen"]
                    if only_running.value:
                        running = [j for j in jobs if j.status == ScanJobStatus.RUNNING]
                        pending_tail = [
                            j
                            for j in jobs
                            if j.status != ScanJobStatus.RUNNING
                            and len(j.logs) > seen.get(j.id, 0)
                        ]
                        jobs = running + pending_tail
                    jobs = sorted(
                        jobs,
                        key=lambda j: (0 if j.status == ScanJobStatus.RUNNING else 1, -(j.started_at or 0)),
                    )[:30]
                    for j in jobs:
                        lines = list(j.logs)
                        prev = seen.get(j.id, 0)
                        if prev > len(lines):
                            prev = 0
                        if prev == 0 and lines:
                            hdr = f"═══ {j.id}  [{j.status.value}]  {j.target} ═══"
                            _log_push(term_log, hdr, "text-cyan-400 cyber-font-mono")
                        for i in range(prev, len(lines)):
                            ln = lines[i]
                            cls = _terminal_line_classes(ln)
                            _log_push(term_log, ln, cls)
                        seen[j.id] = len(lines)

                ui.timer(0.35, lambda: asyncio.create_task(tail_verbose_terminal()))

            ui.timer(1.2, lambda: asyncio.create_task(refresh_summary()))
            ui.timer(2.0, lambda: asyncio.create_task(rebuild_active()))

            ui.label(
                "Solo redes autorizadas · Sin autenticación en la app · Aísla el servicio (VPN / proxy / firewall)."
            ).classes(
                "text-slate-600 text-[10px] sm:text-xs text-center mt-10 mb-2 cyber-font-mono "
                "uppercase tracking-widest max-w-3xl mx-auto leading-relaxed"
            )


def _fill_active_cards(container: ui.column, jobs: list) -> None:
    recent = sorted(jobs, key=lambda j: j.started_at or 0, reverse=True)[:12]
    with container:
        if not recent:
            ui.label("Sin jobs recientes en memoria.").classes("text-slate-500 cyber-font-mono text-sm")
            return
        for j in recent:
            with ui.card().classes(f"w-full {_C_CARD} border-cyan-500/10"):
                with ui.row().classes("w-full items-center justify-between gap-2 flex-wrap"):
                    ui.label(f"{j.id}  ·  {j.status.value}  ·  {getattr(j, 'preset_id', 'standard')}").classes(
                        "text-slate-200 cyber-font-mono text-sm"
                    )
                    ui.label(j.target[:80]).classes("text-slate-400 text-xs truncate flex-1 cyber-font-mono")
                    if j.status == ScanJobStatus.RUNNING:
                        ui.button(
                            "Detener",
                            icon="stop",
                            on_click=lambda jid=j.id: asyncio.create_task(_stop_job(jid)),
                        ).props("dense color=red flat")
                if j.status == ScanJobStatus.RUNNING:
                    ui.linear_progress().props("indeterminate color=cyan").classes("w-full mt-2")
                with ui.expansion("Logs", icon="terminal").classes("w-full text-slate-300"):
                    log_text = "\n".join(list(j.logs)[-400:])
                    ui.code(log_text or "(sin salida aún)").classes("w-full max-h-64 overflow-auto text-xs")


async def _run_now(target_in: Any, preset_sel: Any) -> None:
    raw = (target_in.value or "").strip()
    if not raw:
        ui.notify("Indica la red o IPs a escanear.", type="warning")
        return
    preset = (preset_sel.value or config.SCAN_PRESET_STANDARD).strip().lower()
    try:
        jid = await scan_manager.start_scan(raw, tag="webui", preset_id=preset)
        ui.notify(
            f"Scan {jid} en curso. En los logs verás el comando nmap, luego el de importación y la línea IMPORT_OK cuando se guarde en la DB.",
            type="positive",
            timeout=6000,
        )
        asyncio.create_task(_notify_when_scan_finishes(jid))
    except ValueError as e:
        ui.notify(str(e), type="warning")
    except Exception as e:
        ui.notify(str(e), type="negative")


async def _notify_when_scan_finishes(job_id: str, max_wait: int = 7200) -> None:
    """Avisa cuando el job termina y si los datos llegaron a nmap_scans.db."""
    for _ in range(max_wait):
        await asyncio.sleep(1.25)
        job = await scan_manager.get_job(job_id)
        if job is None:
            return
        if job.status == ScanJobStatus.COMPLETED:
            log_text = "\n".join(job.logs)
            last_imp = next(
                (ln for ln in reversed(job.logs) if "IMPORT_" in ln),
                None,
            )
            if "IMPORT_OK" in log_text:
                msg = "Importación OK — datos en nmap_scans.db."
                if last_imp:
                    msg += f" {last_imp[:220]}{'…' if len(last_imp) > 220 else ''}"
                ui.notify(msg, type="positive", timeout=10000)
            else:
                ui.notify("Scan marcado completado pero no hay línea IMPORT_OK en el log.", type="warning", timeout=8000)
            return
        if job.status in (ScanJobStatus.FAILED, ScanJobStatus.STOPPED):
            ui.notify(
                job.error_message or f"Estado: {job.status.value} — ver logs del job.",
                type="negative",
                timeout=8000,
            )
            return


async def _stop_job(job_id: str) -> None:
    ok = await scan_manager.stop_scan(job_id)
    ui.notify("Señal de parada enviada." if ok else "No se pudo detener.", type="info" if ok else "warning")


@ui.page("/history")
def page_history() -> None:
    _setup_theme()
    ui.dark_mode(True)

    with ui.column().classes("w-full min-h-screen cyber-grid-bg"):
        with ui.row().classes(_C_TOPBAR):
            ui.button(icon="arrow_back", on_click=lambda: ui.navigate.to("/")).props("flat color=grey")
            ui.label("// Historial SQLite").classes("text-xl font-semibold text-emerald-400 cyber-font-head")
            ui.button(icon="shield", on_click=lambda: ui.navigate.to("/blue-team")).props(
                "flat color=grey"
            ).tooltip("Blue Team")

        with ui.column().classes("w-full max-w-7xl mx-auto p-4 sm:p-6 gap-4"):
            dlg = ui.dialog()
            list_box = ui.column().classes("w-full gap-1 max-h-[70vh] overflow-y-auto")

            def load_list() -> None:
                list_box.clear()
                rows = db.fetch_scans(
                    limit=300,
                    date_from=(df.value or "").strip() or None,
                    date_to=(dt.value or "").strip() or None,
                    ip_search=(ipf.value or "").strip() or None,
                )
                with list_box:
                    if not rows:
                        ui.label("Sin resultados.").classes("text-slate-500 cyber-font-mono")
                        return
                    for r in rows:
                        with ui.row().classes(
                            "w-full items-center gap-2 py-2 border-b border-emerald-900/30 flex-wrap "
                            "hover:bg-emerald-950/20 rounded"
                        ):
                            ui.label(r.imported_at[:19] if r.imported_at else "—").classes(
                                "text-slate-400 text-xs w-40 cyber-font-mono"
                            )
                            ui.label(db.tags_pretty(r.tags)[:40]).classes(
                                "text-slate-300 text-xs flex-1 min-w-[120px]"
                            )
                            ui.label((r.command_line or "")[:60] + "…").classes(
                                "text-slate-500 text-xs flex-1 min-w-[200px] truncate cyber-font-mono"
                            )
                            ui.button(
                                "Detalle",
                                on_click=lambda h=r.scan_hash: _show_scan_dialog(dlg, h),
                            ).props("dense flat color=cyan")

            with ui.row().classes("gap-3 flex-wrap items-end"):
                df = ui.input("Desde (YYYY-MM-DD)").classes("w-48").props("outlined dense dark")
                dt = ui.input("Hasta (YYYY-MM-DD)").classes("w-48").props("outlined dense dark")
                ipf = ui.input("Filtrar IP / texto").classes("w-56").props("outlined dense dark")
                ui.button("Aplicar filtros", icon="filter_alt", on_click=load_list).props("color=cyan")

            load_list()


@ui.page("/blue-team")
def page_blue_team() -> None:
    _setup_theme()
    ui.dark_mode(True)
    body = _load_repo_markdown("docs/blue-team.md")

    with ui.column().classes("w-full min-h-screen cyber-grid-bg"):
        with ui.row().classes(_C_TOPBAR):
            ui.button(icon="arrow_back", on_click=lambda: ui.navigate.to("/")).props("flat color=grey")
            ui.label("// Blue Team").classes("text-xl font-semibold text-cyan-400 cyber-font-head")
            with ui.row().classes("gap-1"):
                ui.button(icon="history", on_click=lambda: ui.navigate.to("/history")).props(
                    "flat color=grey"
                ).tooltip("Historial")
                ui.link("Grafana ↗", _grafana_url(config.GRAFANA_MAIN_DASHBOARD_PATH), new_tab=True).classes(
                    "text-cyan-400 text-sm cyber-font-mono"
                )

        with ui.column().classes("w-full max-w-4xl mx-auto p-4 sm:p-6 gap-4 pb-16"):
            ui.label("Atomic Red Team · Wireshark · OpenVAS").classes(
                "text-slate-500 text-xs uppercase tracking-widest cyber-font-head"
            )
            with ui.card().classes(f"w-full {_C_CARD}"):
                ui.markdown(body).classes(
                    "text-slate-300 text-sm max-w-none leading-relaxed [&_a]:text-cyan-400 "
                    "[&_code]:text-amber-200/90 [&_h1]:text-emerald-400 [&_h2]:text-emerald-400/95 "
                    "[&_h3]:text-cyan-400/90 [&_pre]:bg-black/50 [&_pre]:p-3 [&_pre]:rounded-lg"
                )

            ui.label(
                "Fuente en el repo: docs/blue-team.md · Edita ese archivo para actualizar esta vista."
            ).classes("text-slate-600 text-xs cyber-font-mono text-center")


def _show_scan_dialog(dlg: ui.dialog, scan_hash: str) -> None:
    dlg.clear()
    meta = db.fetch_scan_meta(scan_hash)
    hosts = db.fetch_hosts_for_scan(scan_hash)
    ports = db.fetch_ports_for_scan(scan_hash)
    nse = db.fetch_nse_for_scan(scan_hash, vuln_only=False)
    vulns = [n for n in nse if "cve" in (n.script_id or "").lower() or (n.output and "CVE-" in n.output)]

    with dlg:
        with ui.card().classes(f"min-w-[85vw] max-w-[95vw] {_C_CARD}"):
            ui.label(f"// Scan {scan_hash[:24]}…").classes("text-lg text-emerald-400 cyber-font-head")
            if meta:
                ui.markdown(
                    f"**Importado:** {meta.get('imported_at')}  \n**Tags:** {db.tags_pretty(str(meta.get('tags', '')))}"
                ).classes("text-slate-300 text-sm")
            with ui.tabs().classes("text-slate-200") as tabs:
                t_hosts = ui.tab("Hosts")
                t_ports = ui.tab("Puertos")
                t_nse = ui.tab("NSE / CVE")
            with ui.tab_panels(tabs, value=t_hosts).classes("w-full bg-slate-800/50"):
                with ui.tab_panel(t_hosts):
                    ui.table(
                        columns=[
                            {"name": "addr", "label": "IP", "field": "addr"},
                            {"name": "mac", "label": "MAC", "field": "mac"},
                            {"name": "os_name", "label": "OS", "field": "os_name"},
                            {"name": "hostname", "label": "Hostname", "field": "hostname"},
                        ],
                        rows=hosts,
                        row_key="addr",
                    ).classes("w-full")
                with ui.tab_panel(t_ports):
                    prow = [
                        {
                            "_rid": f"{p.host_addr}-{p.protocol}-{p.portid}",
                            "host_addr": p.host_addr,
                            "portid": p.portid,
                            "protocol": p.protocol,
                            "service_name": p.service_name,
                            "version": p.version,
                        }
                        for p in ports
                    ]
                    ui.table(
                        columns=[
                            {"name": "host_addr", "label": "Host", "field": "host_addr"},
                            {"name": "portid", "label": "Puerto", "field": "portid"},
                            {"name": "protocol", "label": "Proto", "field": "protocol"},
                            {"name": "service_name", "label": "Servicio", "field": "service_name"},
                            {"name": "version", "label": "Versión", "field": "version"},
                        ],
                        rows=prow,
                        row_key="_rid",
                    ).classes("w-full")
                with ui.tab_panel(t_nse):
                    ui.label(f"Pistas CVE (scripts): {len(vulns)}").classes("text-amber-300 text-sm mb-2")
                    rows_nse = [
                        {
                            "_k": f"{n.script_id}-{n.host_addr}-{i}",
                            "script_id": n.script_id,
                            "host": n.host_addr,
                            "port": n.port_id,
                            "summary": (n.output_summary or "")[:200],
                        }
                        for i, n in enumerate(vulns if vulns else nse[:80])
                    ]
                    ui.table(
                        columns=[
                            {"name": "script_id", "label": "Script", "field": "script_id"},
                            {"name": "host", "label": "Host", "field": "host"},
                            {"name": "port", "label": "Puerto", "field": "port"},
                            {"name": "summary", "label": "Resumen", "field": "summary"},
                        ],
                        rows=rows_nse,
                        row_key="_k",
                    ).classes("w-full")
            ui.button("Cerrar", on_click=dlg.close).props("flat color=white").classes("mt-4")
    dlg.open()


@app.on_startup
def _startup() -> None:
    async def _scheduled_runner(target: str) -> str:
        return await scan_manager.start_scan(target, tag="scheduled")

    schedule_service.set_runner(_scheduled_runner)
    schedule_service.start()


@app.on_shutdown
def _shutdown() -> None:
    schedule_service.shutdown()


if __name__ in {"__main__", "__mp_main__"}:
    ui.run(
        host=config.HOST,
        port=config.PORT,
        title="SEC // Scan Console",
        dark=True,
        favicon="⬡",
    )
