"""app.py — Interfaz TUI profesional de VexCore."""

from __future__ import annotations
import time
from pathlib import Path

from textual import work, on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Input,
    Static,
)

from ..analyzers import AstAnalyzer, SastAnalyzer, ScaAnalyzer, SecretsAnalyzer
from ..domain import Category, Finding, Severity, SEVERITY_ORDER
from ..engine import Engine
from ..utils.config_loader import load_config

_SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "bold yellow",
    Severity.MEDIUM:   "bold blue",
    Severity.LOW:      "bold cyan",
    Severity.INFO:     "bold white",
}

_CATEGORY_LABELS = {
    Category.SAST:   "SAST",
    Category.SECRET: "Secrets",
    Category.SCA:    "SCA",
    Category.CONFIG: "Config",
}

_SEV_SHORT = {
    Severity.CRITICAL: "CRIT",
    Severity.HIGH:     "HIGH",
    Severity.MEDIUM:   "MED",
    Severity.LOW:      "LOW",
    Severity.INFO:     "INFO",
}


class Dashboard(Static):
    """Panel lateral con estadísticas de severidad."""

    def __init__(self, **kwargs) -> None:
        super().__init__("Cargando...", **kwargs)
        self._counts: dict[Severity, int] = {}
        self._total_files = 0
        self._elapsed = 0.0

    def update_stats(self, findings: list[Finding], files: int, elapsed: float) -> None:
        self._counts = {s: 0 for s in SEVERITY_ORDER}
        for f in findings:
            self._counts[f.severity] = self._counts.get(f.severity, 0) + 1
        self._total_files = files
        self._elapsed = elapsed
        self._refresh_content()

    def _refresh_content(self) -> None:
        total = sum(self._counts.values())
        lines = [
            "[bold]SEVERITY[/]",
            "",
        ]
        max_count = max(self._counts.values()) if self._counts else 1
        for sev in SEVERITY_ORDER:
            count = self._counts.get(sev, 0)
            color = _SEVERITY_COLORS.get(sev, "white")
            bar_len = int((count / max(max_count, 1)) * 12) if count else 0
            bar = "█" * bar_len + "░" * (12 - bar_len)
            label = _SEV_SHORT[sev]
            lines.append(f"  [{color}]{label:>4}[/]  {bar}  {count}")

        lines.extend([
            "",
            "[bold]SUMMARY[/]",
            f"  Files   [dim]{self._total_files}[/]",
            f"  Findings[dim] {total}[/]",
            f"  Time    [dim]{self._elapsed}s[/]",
        ])
        self.update("\n".join(lines))


class DetailPanel(Static):
    """Panel de detalle del finding seleccionado."""

    def __init__(self, **kwargs) -> None:
        super().__init__("[dim]Selecciona un finding para ver detalles[/]", **kwargs)

    def show(self, f: Finding) -> None:
        color = _SEVERITY_COLORS.get(f.severity, "white")
        cat = _CATEGORY_LABELS.get(f.category, f.category.value)
        self.update(
            f"[bold]{f.rule_id}[/]  —  {f.title}\n"
            f"[{color}]{f.severity.upper()}[/]  |  {cat}  |  "
            f"[dim]{f.file.relative}:{f.line}[/]\n"
            f"\n"
            f"[dim]{f.snippet}[/]"
        )

    def clear(self) -> None:
        self.update("[dim]Selecciona un finding para ver detalles[/]")


class MainScreen(Screen):
    """Pantalla principal con layout de 3 paneles."""

    CSS = """
    #body {
        height: 1fr;
    }
    #sidebar {
        width: 22;
        min-width: 22;
        padding: 1 0 1 1;
        background: $panel;
        border-right: tall $primary;
    }
    #main-col {
        width: 1fr;
    }
    #search-bar {
        height: 3;
        padding: 0 1;
    }
    #findings-table {
        height: 1fr;
    }
    #detail {
        height: 5;
        min-height: 5;
        padding: 0 1;
        background: $panel;
        border-top: tall $primary;
    }
    #scan-status {
        height: 3;
        padding: 0 1;
        display: none;
    }
    #scan-status.visible {
        display: block;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Salir"),
        Binding("s", "scan", "Escanear"),
        Binding("j", "cursor_down", "Abajo", show=False),
        Binding("k", "cursor_up", "Arriba", show=False),
        Binding("enter", "toggle_detail", "Detalle"),
        Binding("escape", "go_back", "Volver"),
        Binding("1", "filter_severity(0)", "Todo", show=False),
        Binding("2", "filter_severity(1)", "CRIT", show=False),
        Binding("3", "filter_severity(2)", "HIGH", show=False),
        Binding("4", "filter_severity(3)", "MED", show=False),
        Binding("5", "filter_severity(4)", "LOW", show=False),
        Binding("6", "filter_severity(5)", "INFO", show=False),
        Binding("f", "focus_search", "Buscar", show=False),
        Binding("c", "filter_category", "Categoría", show=False),
    ]

    def __init__(self, target: Path | None = None) -> None:
        super().__init__()
        self._target = target
        self._findings: list[Finding] = []
        self._filtered: list[Finding] = []
        self._filter_sev: int = 0  # 0 = todos
        self._filter_cat: Category | None = None
        self._search_query = ""
        self._show_detail = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Horizontal(id="body"):
            yield Dashboard(id="sidebar")
            with Vertical(id="main-col"):
                with Horizontal(id="search-bar"):
                    yield Input(placeholder="Buscar por rule_id, título o archivo...", id="search-input")
                yield DataTable(id="findings-table", cursor_type="row", zebra_stripes=True)
                yield DetailPanel(id="detail")
                yield Static(id="scan-status")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.add_columns("Sev", "Rule", "Title", "File", "Line")
        if self._target:
            self.action_scan()

    # --- Actions ---

    def action_quit(self) -> None:
        self.app.exit()

    def action_scan(self) -> None:
        self._do_scan()

    def action_toggle_detail(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        if not self._filtered or table.cursor_row is None:
            return
        self._show_detail = not self._show_detail
        if self._show_detail:
            idx = table.cursor_row
            if idx < len(self._filtered):
                self.query_one("#detail", DetailPanel).show(self._filtered[idx])
        else:
            self.query_one("#detail", DetailPanel).clear()

    def action_go_back(self) -> None:
        if self._show_detail:
            self._show_detail = False
            self.query_one("#detail", DetailPanel).clear()
        elif self._filter_sev != 0 or self._filter_cat is not None:
            self._filter_sev = 0
            self._filter_cat = None
            self.query_one("#search-input", Input).value = ""
            self._search_query = ""
            self._apply_filters()

    def action_filter_severity(self, level: int) -> None:
        self._filter_sev = level
        self._apply_filters()

    def action_filter_category(self) -> None:
        cats = [None, Category.SAST, Category.SECRET, Category.SCA, Category.CONFIG]
        if self._filter_cat in cats:
            idx = cats.index(self._filter_cat)
            self._filter_cat = cats[(idx + 1) % len(cats)]
        else:
            self._filter_cat = None
        self._apply_filters()

    def action_focus_search(self) -> None:
        self.query_one("#search-input", Input).focus()

    # --- Scan ---

    @work(exclusive=True, thread=True)
    def _do_scan(self) -> None:
        target = self._target or Path.cwd()
        if not target.is_dir():
            return

        status = self.query_one("#scan-status", Static)
        status.add_class("visible")
        status.update("[yellow]⏳ Escaneando...[/]")

        try:
            config = load_config()
        except FileNotFoundError:
            status.update("[red]config.yaml no encontrado[/]")
            return

        analyzers = []
        if config.sast.enabled:
            analyzers.append(SastAnalyzer(config.sast.rules_path))
        if config.secrets.enabled:
            analyzers.append(SecretsAnalyzer(config.secrets.rules_path))
        if config.sca.enabled:
            analyzers.append(ScaAnalyzer(config.sca.rules_path, source=config.sca.source))
        if config.config.enabled:
            from ..analyzers import ConfigAnalyzer
            analyzers.append(ConfigAnalyzer(config.config.rules_path))
        analyzers.append(AstAnalyzer())

        start = time.perf_counter()
        report = Engine(config, analyzers).run(target)
        elapsed = round(time.perf_counter() - start, 2)

        self._findings = report.findings
        self._apply_filters()

        self.query_one("#sidebar", Dashboard).update_stats(
            self._findings, report.scanned_files, elapsed
        )
        status.remove_class("visible")
        status.update("")

    # --- Filtering ---

    def _apply_filters(self) -> None:
        findings = list(self._findings)

        if self._filter_sev > 0:
            threshold = SEVERITY_ORDER[self._filter_sev - 1]
            findings = [f for f in findings if f.severity == threshold]

        if self._filter_cat is not None:
            findings = [f for f in findings if f.category == self._filter_cat]

        if self._search_query:
            q = self._search_query.lower()
            findings = [
                f for f in findings
                if q in f.rule_id.lower()
                or q in f.title.lower()
                or q in str(f.file.relative).lower()
            ]

        self._filtered = findings
        self._render_table()
        self.query_one("#sidebar", Dashboard).update_stats(
            self._findings,
            self.query_one("#sidebar", Dashboard)._total_files,
            self.query_one("#sidebar", Dashboard)._elapsed,
        )

    def _render_table(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.clear()
        for f in self._filtered:
            color = _SEVERITY_COLORS.get(f.severity, "white")
            sev_label = _SEV_SHORT.get(f.severity, "???")
            table.add_row(
                f"[{color}]{sev_label}[/]",
                f.rule_id,
                f.title[:60],
                str(f.file.relative)[:40],
                str(f.line),
            )

    # --- Events ---

    @on(Input.Changed, "#search-input")
    def on_search_changed(self, event: Input.Changed) -> None:
        self._search_query = event.value
        self._apply_filters()

    @on(DataTable.RowSelected, "#findings-table")
    def on_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.cursor_row < len(self._filtered):
            self._show_detail = True
            self.query_one("#detail", DetailPanel).show(self._filtered[event.cursor_row])


class VexCoreTUI(App):
    """VexCore TUI — interfaz profesional de seguridad."""

    TITLE = "VexCore"
    SUB_TITLE = "Escáner estático de seguridad"
    CSS_PATH = "styles.tcss"

    def __init__(self, target: Path | None = None) -> None:
        super().__init__()
        self._target = target

    def on_mount(self) -> None:
        self.push_screen(MainScreen(target=self._target))
