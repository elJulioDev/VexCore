"""app.py — Interfaz TUI tipo terminal (lazygit/htop style)."""

from __future__ import annotations
import time
from pathlib import Path

from textual import work
from textual.app import App, ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Header, Static

from ..analyzers import SastAnalyzer, ScaAnalyzer, SecretsAnalyzer
from ..domain import Finding, Severity
from ..engine import Engine
from ..utils.config_loader import load_config

_SEVERITY_COLORS = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "yellow",
    Severity.MEDIUM: "blue",
    Severity.LOW: "green",
    Severity.INFO: "white",
}

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


class MainScreen(Screen):
    """Pantalla principal con findings agrupados por archivo y navegación por teclado."""

    PAGE_SIZE = 10

    def __init__(self, scan_target: Path | None = None) -> None:
        super().__init__()
        self._target = scan_target
        self._findings: list[Finding] = []
        self._filtered: list[Finding] = []
        self._selected = 0
        self._filter_level = 0  # 0 = todos, 1-5 = crítico→info
        self._scanned_files = 0
        self._elapsed = 0.0
        self._show_detail = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield Static(id="header-bar")
        yield VerticalScroll(Static(id="findings-list", markup=True), id="scroll")
        yield Static(id="footer-bar", markup=True)

    def on_mount(self) -> None:
        self._update_header("Presiona [bold]s[/] para escanear  |  [bold]q[/] para salir")
        self._render_findings()
        if self._target:
            self._do_scan()

    def _update_header(self, status: str = "") -> None:
        parts = ["[bold]VEXCORE[/] [dim]v0.1.0[/]"]
        if self._target:
            parts.append(f"[dim]{self._target}[/]")
        if self._scanned_files:
            parts.append(f"[dim]{len(self._filtered)} findings  {self._scanned_files} archivos  {self._elapsed}s[/]")
        parts.append(f"[dim]{status}[/]" if status else "")
        self.query_one("#header-bar", Static).update("  ".join(parts))

    def _render_findings(self, detail_idx: int | None = None) -> None:
        if not self._filtered:
            if self._scanned_files:
                self.query_one("#findings-list", Static).update(
                    "[green]✅[/] No se encontraron hallazgos para este filtro.\n"
                    "  [dim]Presiona [bold]s[/] para re-escanear  |  [bold]Esc[/] para limpiar filtro[/]"
                )
            else:
                self.query_one("#findings-list", Static).update(
                    "[dim]  Presiona [bold]s[/] para escanear[/]"
                )
            self._update_footer()
            return

        groups: dict[str, list[Finding]] = {}
        for f in self._filtered:
            groups.setdefault(str(f.file.relative), []).append(f)

        lines: list[str] = []
        idx = 0
        for file_path in sorted(groups):
            g = groups[file_path]
            n = len(g)
            lines.append(f"\n[bold]{file_path}[/]  [dim]({n} hallazgo{'s' if n != 1 else ''})[/]")
            for f in g:
                color = _SEVERITY_COLORS.get(f.severity, "white")
                badge = f"[{color}]{f.severity.upper()[:5]:>5}[/]"
                marker = "[bold #ff6b6f]▸[/]" if idx == self._selected else " "
                lines.append(
                    f"  {marker}  [dim]:{f.line:<4}[/]  {badge}  "
                    f"[bold]{f.rule_id:<8}[/]  {f.title}"
                )
                if self._show_detail and idx == self._selected:
                    lines.append(f"       [dim]{f.snippet[:120]}[/]")
                idx += 1

        self.query_one("#findings-list", Static).update("\n".join(lines))
        self._update_footer()

    def _update_footer(self) -> None:
        parts = [
            "[bold]q[/] salir",
            "[bold]s[/] escanear",
            "[bold]↑↓[/] navegar",
            "[bold]↵[/] detalle",
        ]
        severity_labels = ["todos", "crítico", "alto", "medio", "bajo", "info"]
        flt = severity_labels[self._filter_level]
        parts.append(f"[bold]1-5[/] filtro: [italic]{flt}[/]")
        parts.append("[bold]Esc[/] limpiar filtro")
        self.query_one("#footer-bar", Static).update("  ".join(f"[dim]{p}[/]" for p in parts))

    def _filter_findings(self) -> None:
        if self._filter_level == 0:
            self._filtered = list(self._findings)
        else:
            threshold = _SEVERITY_ORDER[self._filter_level - 1]
            self._filtered = [f for f in self._findings
                              if _SEVERITY_ORDER.index(f.severity) <= self._filter_level - 1]
        self._selected = min(self._selected, max(len(self._filtered) - 1, 0))
        self._render_findings()

    @work(exclusive=True, thread=True)
    def _do_scan(self) -> None:
        target = self._target or Path.cwd()
        if not target.is_dir():
            self._update_header(f"[red]Directorio inválido: {target}[/]")
            return

        self._update_header("⏳ Escaneando...")
        self.query_one("#findings-list", Static).update("[yellow]⏳ Escaneando...[/]")

        try:
            config = load_config()
        except FileNotFoundError:
            self._update_header("[red]config.yaml no encontrado[/]")
            return

        analyzers = []
        for cfg, cls in [(config.sast, SastAnalyzer), (config.secrets, SecretsAnalyzer),
                         (config.sca, ScaAnalyzer)]:
            if cfg.enabled:
                analyzers.append(cls(cfg.rules_path))

        start = time.perf_counter()
        report = Engine(config, analyzers).run(target)
        self._elapsed = round(time.perf_counter() - start, 2)
        self._scanned_files = report.scanned_files
        self._findings = report.findings
        self._filter_level = 0
        self._show_detail = False
        self._filtered = list(self._findings)
        self._selected = 0

        self._render_findings()
        total = len(self._findings)
        self._update_header(f"[bold]{total}[/] hallazgos  [dim]{self._scanned_files} archivos  {self._elapsed}s[/]")

    def on_key(self, event) -> None:
        key = event.key
        if key == "q":
            self.app.exit()
        elif key == "s":
            self._do_scan()
        elif key == "up" or key == "k":
            if self._filtered:
                self._selected = max(0, self._selected - 1)
                self._show_detail = False
                self._render_findings()
        elif key == "down" or key == "j":
            if self._filtered:
                self._selected = min(len(self._filtered) - 1, self._selected + 1)
                self._show_detail = False
                self._render_findings()
        elif key == "enter":
            if self._filtered:
                self._show_detail = not self._show_detail
                self._render_findings()
        elif key == "escape":
            if self._show_detail:
                self._show_detail = False
                self._render_findings()
            elif self._filter_level != 0:
                self._filter_level = 0
                self._filter_findings()
        elif key in ("1", "2", "3", "4", "5"):
            self._filter_level = int(key)
            self._show_detail = False
            self._filter_findings()
        elif key == "pageup":
            if self._filtered:
                self._selected = max(0, self._selected - self.PAGE_SIZE)
                self._render_findings()
        elif key == "pagedown":
            if self._filtered:
                self._selected = min(len(self._filtered) - 1, self._selected + self.PAGE_SIZE)
                self._render_findings()


class VexCoreTUI(App):
    """Aplicación TUI de VexCore — estilo terminal (lazygit/htop)."""

    CSS_PATH = "styles.tcss"
    BINDINGS = []  # todo es manejado por on_key en MainScreen

    def __init__(self, target: Path | None = None) -> None:
        super().__init__()
        self._target = target

    def on_mount(self) -> None:
        self.push_screen(MainScreen(scan_target=self._target))
