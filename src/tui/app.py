"""app.py — Interfaz TUI interactiva con Textual."""

from __future__ import annotations
from pathlib import Path

import pyfiglet

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.reactive import reactive
from textual.screen import Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    ProgressBar,
    Static,
)

from ..analyzers import SastAnalyzer, ScaAnalyzer, SecretsAnalyzer
from ..domain import Finding, Severity
from ..engine import Engine
from ..utils.config_loader import load_config

_SEVERITY_COLORS = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFO: "info",
}


class SplashScreen(Screen):
    """Pantalla de bienvenida con logo generado por pyfiglet."""

    def compose(self) -> ComposeResult:
        art = pyfiglet.figlet_format("VEXCORE", font="standard")
        yield Container(
            Static(f"[bold #ff6b6b]{art}[/]", id="logo"),
            Static("[dim]Escáner Estático de Seguridad Modular[/]", id="tagline"),
            Static("[dim]v0.1.0[/]", id="version"),
            Static("[dim]Presiona cualquier tecla o espera 3 segundos...[/]", id="prompt"),
            id="splash",
        )

    def on_mount(self) -> None:
        self.set_interval(3, self._go_to_main)

    def _go_to_main(self) -> None:
        self.app.push_screen("main")

    def on_key(self) -> None:
        self._go_to_main()


class MainScreen(Screen):
    """Pantalla principal: ingreso de ruta, escaneo y resultados."""

    findings: reactive[list[Finding]] = reactive([])

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        art = pyfiglet.figlet_format("VEXCORE", font="standard")
        yield Container(
            Static(art, id="logo-small"),
            Horizontal(
                Input(placeholder="Ruta del directorio a escanear...", id="path-input"),
                Button("🔍 Escanear", id="scan-btn", variant="primary"),
                id="input-row",
            ),
            ProgressBar(id="progress", total=100, show_eta=False),
            DataTable(id="results-table"),
            Static(id="detail-panel"),
            id="main-container",
        )
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#results-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Severidad", "ID", "Título", "Archivo", "Línea")
        self.query_one("#path-input", Input).focus()

    def watch_findings(self, findings: list[Finding]) -> None:
        table = self.query_one("#results-table", DataTable)
        table.clear()
        for f in findings:
            color = _SEVERITY_COLORS.get(f.severity, "info")
            table.add_row(
                f"[{color}]{f.severity.upper()}[/]",
                f.rule_id,
                f.title,
                str(f.file.relative),
                str(f.line),
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "scan-btn":
            path = self.query_one("#path-input", Input).value
            if path:
                self.run_scan(path)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "path-input" and event.value:
            self.run_scan(event.value)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        panel = self.query_one("#detail-panel", Static)
        if event.row_key.value is None:
            panel.remove_class("visible")
            panel.update("")
            return
        idx = int(event.row_key.value)
        if 0 <= idx < len(self.findings):
            f = self.findings[idx]
            color = _SEVERITY_COLORS.get(f.severity, "info")
            panel.add_class("visible")
            panel.update(
                f"[{color}][bold]{f.rule_id}[/] — {f.title}[/]\n"
                f"[dim]{f.file.relative}:{f.line}[/]\n"
                f"[{color}]{f.severity.upper()}[/]  {f.snippet}"
            )

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key.value is None:
            return
        idx = int(event.row_key.value)
        if 0 <= idx < len(self.findings):
            f = self.findings[idx]
            color = _SEVERITY_COLORS.get(f.severity, "info")
            panel = self.query_one("#detail-panel", Static)
            panel.add_class("visible")
            panel.update(
                f"[{color}][bold]{f.rule_id}[/] — {f.title}[/]\n"
                f"[dim]{f.file.relative}:{f.line}[/]\n"
                f"[{color}]{f.severity.upper()}[/]  {f.snippet}"
            )

    def _run_scan_impl(self, path: str) -> None:
        path_obj = Path(path)
        if not path_obj.is_dir():
            self.query_one("#path-input", Input).value = ""
            self.notify("Directorio inválido", severity="error")
            return

        bar = self.query_one("#progress", ProgressBar)
        bar.update(total=100, advance=0)
        bar.visible = True

        try:
            config = load_config()
        except FileNotFoundError:
            self.notify("config.yaml no encontrado", severity="error")
            bar.visible = False
            return

        analyzers: list = []
        if config.sast.enabled:
            analyzers.append(SastAnalyzer(config.sast.rules_path))
        if config.secrets.enabled:
            analyzers.append(SecretsAnalyzer(config.secrets.rules_path))
        if config.sca.enabled:
            analyzers.append(ScaAnalyzer(config.sca.rules_path))

        engine = Engine(config, analyzers)
        report = engine.run(path_obj)

        self.findings = report.findings
        self.notify(
            f"Escaneo completado: {report.total} hallazgos en {report.elapsed_secs}s",
            severity="information",
        )
        bar.visible = False

    def run_scan(self, path: str) -> None:
        self._run_scan_impl(path)


class VexCoreTUI(App):
    """Aplicación TUI de VexCore."""

    CSS_PATH = "styles.tcss"
    SCREENS = {"splash": SplashScreen, "main": MainScreen}
    BINDINGS = [
        Binding("q", "quit", "Salir"),
        Binding("d", "toggle_dark", "Modo oscuro"),
        Binding("escape", "back_to_input", "Volver al input"),
    ]

    def on_mount(self) -> None:
        self.push_screen("splash")

    def action_back_to_input(self) -> None:
        try:
            main = self.get_screen("main")
            main.query_one("#path-input", Input).focus()
        except Exception:
            pass
