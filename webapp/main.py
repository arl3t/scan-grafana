#!/usr/bin/env python3
"""
NiceGUI web UI: concurrent nmap scans, scheduling, SQLite history, Grafana embed.
Run: python main.py   (from the webapp/ directory)
"""

from __future__ import annotations

import asyncio
import time
import webbrowser

from nicegui import app, ui

import config
import database as db
from models import ScanJobStatus, ScheduleFrequency
from scanner import scan_manager
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


def _tailwind() -> None:
    try:
        ui.add_head_html(
            '<script src="https://cdn.tailwindcss.com"></script>',
            shared=True,
        )
    except TypeError:
        ui.add_head_html('<script src="https://cdn.tailwindcss.com"></script>')


@ui.page("/")
def page_dashboard() -> None:
    _tailwind()
    ui.dark_mode(True)

    with ui.header().classes("items-center justify-between bg-slate-900 border-b border-slate-700"):
        ui.label("Network Scan Console").classes("text-xl font-semibold tracking-tight text-slate-100")
        with ui.row().classes("gap-2 items-center"):
            ui.button(icon="history", on_click=lambda: ui.navigate.to("/history")).props("flat color=white")
            ui.link("Grafana ↗", _grafana_url(config.GRAFANA_MAIN_DASHBOARD_PATH), new_tab=True).classes(
                "text-cyan-400 text-sm"
            )

    with ui.column().classes("w-full max-w-7xl mx-auto p-4 gap-6"):
        with ui.card().classes("w-full bg-slate-800/90 border border-slate-600 shadow-lg"):
            ui.label("Nuevo escaneo").classes("text-lg font-medium text-slate-100 mb-2")
            target_in = ui.input(
                placeholder="IP, CIDR o lista separada por comas (ej. 10.0.0.1, 172.16.0.0/24)"
            ).classes("w-full").props("outlined dense dark")
            with ui.row().classes("w-full gap-3 flex-wrap items-end mt-3"):
                ui.button("Ejecutar scan ahora", icon="radar", color="cyan").classes(
                    "px-6 py-3 text-base font-medium"
                ).on_click(lambda: asyncio.create_task(_run_now(target_in)))

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

                ui.button("Añadir programación", icon="schedule", on_click=lambda: asyncio.create_task(_sched())).props(
                    "outline color=white"
                )

        with ui.row().classes("w-full gap-4 flex-wrap"):
            with ui.card().classes("bg-slate-800/80 border border-slate-600 p-4 min-w-[200px] flex-1"):
                ui.label("Scans en ejecución").classes("text-cyan-400 font-semibold text-sm uppercase tracking-wide")
                lbl_run = ui.label("…").classes("text-slate-200 text-sm whitespace-pre-wrap")
            with ui.card().classes("bg-slate-800/80 border border-slate-600 p-4 min-w-[200px] flex-1"):
                ui.label("Programados").classes("text-violet-400 font-semibold text-sm uppercase tracking-wide")
                lbl_sch = ui.label("…").classes("text-slate-200 text-sm whitespace-pre-wrap")
            with ui.card().classes("bg-slate-800/80 border border-amber-900/50 p-4 min-w-[200px] flex-1"):
                ui.label("Cambios 24h (MAC / puertos nuevos)").classes(
                    "text-amber-400 font-semibold text-sm uppercase tracking-wide"
                )
                lbl_chg = ui.label("…").classes("text-slate-200 text-sm whitespace-pre-wrap text-xs")
            with ui.card().classes("bg-slate-800/80 border border-slate-600 p-4 min-w-[200px] flex-1"):
                ui.label("Totales DB").classes("text-emerald-400 font-semibold text-sm uppercase tracking-wide")
                lbl_cnt = ui.label("…").classes("text-slate-200 text-sm whitespace-pre-wrap")

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

        ui.label("Scans activos / recientes").classes("text-slate-300 text-lg font-medium mt-2")
        active_box = ui.column().classes("w-full gap-3")

        async def rebuild_active() -> None:
            jobs = await scan_manager.list_jobs_ordered()
            active_box.clear()
            _fill_active_cards(active_box, jobs)

        with ui.card().classes("w-full bg-slate-800/90 border border-slate-600"):
            ui.label("Grafana").classes("text-lg font-medium text-slate-100 mb-2")
            with ui.row().classes("gap-2 flex-wrap"):
                ui.link("Dashboard principal", _grafana_url(config.GRAFANA_MAIN_DASHBOARD_PATH), new_tab=True).classes(
                    "text-cyan-400"
                )
                ui.link("Explore", _grafana_url(config.GRAFANA_EXPLORE_PATH), new_tab=True).classes("text-cyan-400")
                ui.button(
                    "Abrir Grafana en navegador",
                    icon="open_in_browser",
                    on_click=lambda: webbrowser.open(_grafana_url(config.GRAFANA_MAIN_DASHBOARD_PATH)),
                ).props("flat color=cyan")

            grafana_iframe_url = (
                _grafana_url(config.GRAFANA_MAIN_DASHBOARD_PATH) + f"?kiosk&refresh=30s&t={int(time.time())}"
            )
            iframe = (
                ui.element("iframe")
                .classes("w-full rounded border border-slate-600 bg-black")
                .style("height: min(70vh, 800px); min-height: 400px")
                .props(f'src="{grafana_iframe_url}" frameborder="0"')
            )

            def reload_frame() -> None:
                new_url = (
                    _grafana_url(config.GRAFANA_MAIN_DASHBOARD_PATH) + f"?kiosk&refresh=30s&t={int(time.time())}"
                )
                iframe.props(f'src="{new_url}"')
                iframe.update()

            ui.button("Refrescar iframe", icon="refresh", on_click=reload_frame).props("outline color=white dense").classes(
                "my-2"
            )

        ui.timer(1.2, lambda: asyncio.create_task(refresh_summary()))
        ui.timer(2.0, lambda: asyncio.create_task(rebuild_active()))


def _fill_active_cards(container: ui.column, jobs: list) -> None:
    recent = sorted(jobs, key=lambda j: j.started_at or 0, reverse=True)[:12]
    with container:
        if not recent:
            ui.label("No hay jobs recientes.").classes("text-slate-500")
            return
        for j in recent:
            with ui.card().classes("w-full bg-slate-900/80 border border-slate-700"):
                with ui.row().classes("w-full items-center justify-between gap-2 flex-wrap"):
                    ui.label(f"{j.id}  ·  {j.status.value}").classes("text-slate-200 font-mono text-sm")
                    ui.label(j.target[:80]).classes("text-slate-400 text-xs truncate flex-1")
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


async def _run_now(target_in: ui.input) -> None:
    try:
        jid = await scan_manager.start_scan(target_in.value or "", tag="webui")
        ui.notify(f"Scan iniciado: {jid}", type="positive")
    except Exception as e:
        ui.notify(str(e), type="negative")


async def _stop_job(job_id: str) -> None:
    ok = await scan_manager.stop_scan(job_id)
    ui.notify("Señal de parada enviada." if ok else "No se pudo detener.", type="info" if ok else "warning")


@ui.page("/history")
def page_history() -> None:
    _tailwind()
    ui.dark_mode(True)

    with ui.header().classes("items-center justify-between bg-slate-900 border-b border-slate-700"):
        ui.button(icon="arrow_back", on_click=lambda: ui.navigate.to("/")).props("flat color=white")
        ui.label("Historial de scans").classes("text-xl font-semibold text-slate-100")

    with ui.column().classes("w-full max-w-7xl mx-auto p-4 gap-4"):
        df = ui.input("Desde (YYYY-MM-DD)").classes("w-48").props("outlined dense dark")
        dt = ui.input("Hasta (YYYY-MM-DD)").classes("w-48").props("outlined dense dark")
        ipf = ui.input("Filtrar IP / texto").classes("w-56").props("outlined dense dark")
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
                    ui.label("Sin resultados.").classes("text-slate-500")
                    return
                for r in rows:
                    with ui.row().classes(
                        "w-full items-center gap-2 py-2 border-b border-slate-700 flex-wrap hover:bg-slate-800/50"
                    ):
                        ui.label(r.imported_at[:19] if r.imported_at else "—").classes(
                            "text-slate-400 text-xs w-40"
                        )
                        ui.label(db.tags_pretty(r.tags)[:40]).classes("text-slate-300 text-xs flex-1 min-w-[120px]")
                        ui.label((r.command_line or "")[:60] + "…").classes(
                            "text-slate-500 text-xs flex-1 min-w-[200px] truncate"
                        )
                        ui.button(
                            "Detalle",
                            on_click=lambda h=r.scan_hash: _show_scan_dialog(dlg, h),
                        ).props("dense flat color=cyan")

        ui.button("Aplicar filtros", icon="filter_alt", on_click=load_list).props("color=cyan")
        load_list()


def _show_scan_dialog(dlg: ui.dialog, scan_hash: str) -> None:
    dlg.clear()
    meta = db.fetch_scan_meta(scan_hash)
    hosts = db.fetch_hosts_for_scan(scan_hash)
    ports = db.fetch_ports_for_scan(scan_hash)
    nse = db.fetch_nse_for_scan(scan_hash, vuln_only=False)
    vulns = [n for n in nse if "cve" in (n.script_id or "").lower() or (n.output and "CVE-" in n.output)]

    with dlg:
        with ui.card().classes("min-w-[85vw] max-w-[95vw] bg-slate-900 border border-slate-600"):
            ui.label(f"Scan {scan_hash[:24]}…").classes("text-lg text-slate-100")
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
        title="Scan Console",
        dark=True,
        favicon="🛰️",
    )
