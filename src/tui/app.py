"""app.py — Interfaz TUI interactiva con Textual.

Flujo de la aplicación:
  1. SplashScreen: muestra logo ASCII de VEXCORE generado con pyfiglet.
     Transición automática a los 3s o al presionar cualquier tecla.
  2. MainScreen: input para ruta del directorio + botón "Escanear".
     Ejecuta el mismo Engine que el CLI y muestra resultados en tabla.
  3. Los findings se renderizan con colores según severidad (definidos
     en styles.tcss). Al navegar con flechas o seleccionar una fila
     se muestra el detalle completo del finding en un panel inferior.

Conceptos de Textual usados:
  - compose() → declara los widgets; Textual los monta automáticamente.
  - reactive → observable; al cambiar su valor, la watch_* se dispara sola.
  - on_*() → event handlers de widgets (on_button_pressed, etc.).
  - @work → decorator para tareas async sin bloquear la UI.
"""

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

# Mapea cada Severity del dominio a una clase CSS (styles.tcss).
# Textual usa estas clases para colorear las filas de la tabla
# y el panel de detalle. Los colores se definen en un solo lugar (TCSS).
_SEVERITY_COLORS = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFO: "info",
}


class SplashScreen(Screen):
    """Pantalla de bienvenida con el logo de VEXCORE en ASCII art.

    Textual construye la UI en dos fases:
      1. compose() → declara los widgets que la pantalla contiene.
         Textual los monta y los muestra automáticamente.
      2. on_mount() → se ejecuta DESPUÉS de que compose() termina.
         Aquí se configuran timers, focus inicial, etc.

    Esta pantalla se auto-destruye después de 3 segundos o al presionar
    cualquier tecla, y hace push de MainScreen.
    """

    def compose(self) -> ComposeResult:
        # pyfiglet convierte "VEXCORE" en ASCII art con la fuente standard.
        # El tag [bold #ff6b6b] es sintaxis de Textual para aplicar color
        # y estilo inline (similar a BBCode). Static renderiza el texto.
        art = pyfiglet.figlet_format("VEXCORE", font="standard")
        yield Container(
            Static(f"[bold #ff6b6b]{art}[/]", id="logo"),
            Static("[dim]Escáner Estático de Seguridad Modular[/]", id="tagline"),
            Static("[dim]v0.1.0[/]", id="version"),
            Static("[dim]Presiona cualquier tecla o espera 3 segundos...[/]", id="prompt"),
            id="splash",
        )

    def on_mount(self) -> None:
        # set_interval llama a _go_to_main cada 3 segundos. Si el usuario
        # presiona una tecla antes, la screen se reemplaza antes del timer.
        self.set_interval(3, self._go_to_main)

    def _go_to_main(self) -> None:
        # push_screen("main") monta MainScreen y la muestra.
        # El nombre "main" debe coincidir con SCREENS en VexCoreTUI.
        self.app.push_screen("main")

    def on_key(self) -> None:
        # Cualquier tecla → pasar a MainScreen inmediatamente.
        self._go_to_main()


class MainScreen(Screen):
    """Pantalla principal: ingreso de ruta, escaneo y resultados.

    findings es un reactive (observable). Cuando cambia su valor,
    Textual llama automáticamente al método watch_findings(new_value).
    Así no necesitamos actualizar la tabla manualmente después del
    escaneo — solo asignamos self.findings = report.findings y la UI
    se refresca automáticamente.
    """

    findings: reactive[list[Finding]] = reactive([])

    def compose(self) -> ComposeResult:
        # Header de Textual: barra superior con reloj y breadcrumbs.
        yield Header(show_clock=True)
        # Logo pequeño arriba del input (versión reducida del splash).
        art = pyfiglet.figlet_format("VEXCORE", font="standard")
        yield Container(
            Static(art, id="logo-small"),
            # Horizontal pone el Input y el Button en la misma fila.
            Horizontal(
                Input(placeholder="Ruta del directorio a escanear...", id="path-input"),
                Button("🔍 Escanear", id="scan-btn", variant="primary"),
                id="input-row",
            ),
            # ProgressBar visible solo durante el escaneo (total=100
            # con modo indeterminado porque el Engine no reporta progreso).
            ProgressBar(id="progress", total=100, show_eta=False),
            # DataTable: tabla interactiva con soporte de cursor y selección.
            DataTable(id="results-table"),
            # Static para el detalle del finding seleccionado.
            Static(id="detail-panel"),
            id="main-container",
        )
        yield Footer()

    def on_mount(self) -> None:
        # Configura la tabla: cursor_type = "row" permite navegar
        # con ↑↓ y seleccionar filas con Enter o click.
        table = self.query_one("#results-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Severidad", "ID", "Título", "Archivo", "Línea")
        # Enfoque inicial en el input para escribir la ruta directo.
        self.query_one("#path-input", Input).focus()

    def watch_findings(self, findings: list[Finding]) -> None:
        """Se llama automáticamente cuando findings cambia.

        El nombre sigue la convención de Textual: watch_<nombre_del_reactive>.
        Limpia la tabla y la vuelve a llenar con los nuevos findings.
        Cada fila usa un row_key = índice numérico para referenciarlo
        después en los eventos de selección (on_data_table_row_selected).
        """
        table = self.query_one("#results-table", DataTable)
        table.clear()
        for i, f in enumerate(findings):
            color = _SEVERITY_COLORS.get(f.severity, "info")
            table.add_row(
                f"[{color}]{f.severity.upper()}[/]",
                f.rule_id,
                f.title,
                str(f.file.relative),
                str(f.line),
                key=str(i),
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        # Click en el botón "Escanear".
        if event.button.id == "scan-btn":
            path = self.query_one("#path-input", Input).value
            if path:
                self.run_scan(path)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        # Enter en el input también inicia el escaneo.
        if event.input.id == "path-input" and event.value:
            self.run_scan(event.value)

    def _update_detail_panel(self, idx: int) -> None:
        """Muestra el detalle de un finding en el panel inferior."""
        if idx < 0 or idx >= len(self.findings):
            return
        f = self.findings[idx]
        color = _SEVERITY_COLORS.get(f.severity, "info")
        panel = self.query_one("#detail-panel", Static)
        panel.add_class("visible")
        panel.update(
            f"[{color}][bold]{f.rule_id}[/] — {f.title}[/]\n"
            f"[dim]{f.file.relative}:{f.line}[/]\n"
            f"[{color}]{f.severity.upper()}[/]  {f.snippet}"
        )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Enter o click en una fila → mostrar detalle completo.

        El row_key es el índice que asignamos en watch_findings.
        Con él recuperamos el Finding original de self.findings.
        """
        if event.row_key.value is None:
            return
        self._update_detail_panel(int(event.row_key.value))

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        """Navegación con flechas → previsualizar detalle.

        Sin necesidad de Enter/click, el panel se actualiza al pasar
        el cursor sobre cada fila (hover-like).
        """
        if event.row_key.value is None:
            return
        self._update_detail_panel(int(event.row_key.value))

    def _run_scan_impl(self, path: str) -> None:
        """Ejecuta el engine de VexCore y actualiza los resultados.

        Flujo:
          1. Valida que la ruta exista y sea un directorio.
          2. Muestra la barra de progreso (indeterminada: el Engine
             no reporta progreso parcial, solo el resultado final).
          3. Carga config.yaml y construye los analyzers habilitados
             (SAST, Secrets, SCA según lo que diga la config).
          4. Instancia Engine con los analyzers y llama engine.run().
          5. Asigna report.findings a self.findings → el reactive
             dispara watch_findings → la tabla se actualiza automágicamente.
          6. Oculta la barra de progreso y muestra notificación.
        """
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
        """Punto de entrada para iniciar el escaneo desde la UI."""
        self._run_scan_impl(path)


class VexCoreTUI(App):
    """Aplicación TUI de VexCore.

    Textual App es el punto de entrada de la interfaz. Define:
      - CSS_PATH: ruta al archivo de estilos TCSS (relativo a este .py).
      - SCREENS: registro de pantallas por nombre para navegación.
      - BINDINGS: atajos de teclado globales.

    Al hacer push_screen("splash"), Textual monta SplashScreen
    y la muestra. Cuando SplashScreen hace push_screen("main"),
    MainScreen toma el control. Ambas pantallas comparten el mismo
    Engine y analizadores que el CLI.
    """

    CSS_PATH = "styles.tcss"
    SCREENS = {"splash": SplashScreen, "main": MainScreen}
    BINDINGS = [
        Binding("q", "quit", "Salir"),
        Binding("d", "toggle_dark", "Modo oscuro"),
        Binding("escape", "back_to_input", "Volver al input"),
    ]

    def on_mount(self) -> None:
        # Pantalla inicial: el splash con el logo ASCII.
        self.push_screen("splash")

    def action_back_to_input(self) -> None:
        """Vuelve el foco al input de ruta (atajo: Escape)."""
        try:
            main = self.get_screen("main")
            main.query_one("#path-input", Input).focus()
        except Exception:
            pass
