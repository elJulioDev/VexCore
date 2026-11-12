"""main.py — Punto de entrada CLI de VexCore."""

from __future__ import annotations
import argparse
import sys
from pathlib import Path
from .analyzers import SastAnalyzer, ScaAnalyzer, SecretsAnalyzer, ConfigAnalyzer, AstAnalyzer
from .domain import Severity, meets_threshold
from .engine import Engine
from .plugins import load_plugins
from .reporters.console import ConsoleReporter
from .reporters.json import JsonReporter
from .reporters.sarif import SarifReporter
from .utils.config_loader import load_config

_REPORTERS = {
    "console": ConsoleReporter,
    "json":    JsonReporter,
    "sarif":   SarifReporter,
}

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vexcore", description="Escáner estático de seguridad.")
    p.add_argument("target", nargs="?", type=Path, default=None, help="Directorio a escanear.")
    p.add_argument("-c", "--config", type=Path, default=None, help="Ruta a config.yaml (default: busca en CWD, luego ~/.vexcore/).")
    p.add_argument(
        "--severity",
        choices=[s.value for s in Severity],
        default=None,
        help="Threshold mínimo a reportar (default: valor en config.yaml).",
    )
    p.add_argument(
        "--output",
        choices=list(_REPORTERS),
        default="console",
        help="Formato de salida (default: console).",
    )
    p.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        default=None,
        help="Exit code 1 si hay findings de esta severidad o superior (default: igual a --severity/config).",
    )
    p.add_argument(
        "--no-color",
        action="store_true",
        help="Desactivar colores ANSI en salida de consola.",
    )
    p.add_argument(
        "--tui",
        action="store_true",
        help="Iniciar interfaz TUI interactiva.",
    )
    p.add_argument(
        "--incremental",
        action="store_true",
        help="Solo re-escanear archivos modificados (usa caché de hashes).",
    )
    return p

def main() -> None:
    args = _build_parser().parse_args()

    if args.tui:
        from .tui import VexCoreTUI
        VexCoreTUI(target=args.target).run()
        return

    if args.target is None:
        print("[ERROR] Se requiere un directorio objetivo. Usa --tui para la interfaz interactiva.", file=sys.stderr)
        sys.exit(1)

    try:
        config = load_config(args.config)
    except FileNotFoundError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)

    if not args.target.is_dir():
        print(f"[ERROR] Directorio inválido: {args.target}", file=sys.stderr)
        sys.exit(1)

    analyzers = []
    if config.sast.enabled:
        analyzers.append(SastAnalyzer(config.sast.rules_path))
    if config.secrets.enabled:
        analyzers.append(SecretsAnalyzer(config.secrets.rules_path))
    # SCA: análisis de composición de dependencias.
    # Deshabilitado por defecto en config.yaml (enabled: false).
    # A diferencia de SAST/secrets que buscan en cada línea con regex,
    # SCA parsea manifests (requirements.txt, pyproject.toml) y compara
    # versiones contra una base de vulnerabilidades conocidas.
    if config.sca.enabled:
        analyzers.append(ScaAnalyzer(config.sca.rules_path, source=config.sca.source))
    if config.config.enabled:
        analyzers.append(ConfigAnalyzer(config.config.rules_path))

    analyzers.append(AstAnalyzer())

    if config.plugins_dir:
        analyzers.extend(load_plugins(config.plugins_dir))

    threshold = Severity(args.severity) if args.severity else config.severity_threshold
    if args.incremental:
        config.incremental = True
    report    = Engine(config, analyzers).run(args.target)

    reporter_cls = _REPORTERS[args.output]
    if args.output == "console":
        # None lets the reporter auto-detect: no color when piped or NO_COLOR is set.
        reporter = reporter_cls(severity_threshold=threshold, color=False if args.no_color else None)
    else:
        reporter = reporter_cls(severity_threshold=threshold)
    reporter.report(report)

    fail_on = Severity(args.fail_on) if args.fail_on else threshold
    if any(meets_threshold(f.severity, fail_on) for f in report.findings):
        sys.exit(1)

if __name__ == "__main__":
    main()
