"""main.py — Punto de entrada CLI de VexCore."""

from __future__ import annotations
import argparse
import sys
from pathlib import Path
from .analyzers import SastAnalyzer, ScaAnalyzer, SecretsAnalyzer
from .domain import Severity
from .engine import Engine
from .reporters.console import ConsoleReporter
from .utils.config_loader import load_config

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vexcore", description="Escáner estático de seguridad.")
    p.add_argument("target", type=Path, help="Directorio a escanear.")
    p.add_argument("-c", "--config", type=Path, default=Path("config.yaml"))
    p.add_argument(
        "--severity",
        choices=[s.value for s in Severity],
        default=None,
        help="Threshold mínimo a reportar (default: valor en config.yaml).",
    )
    return p

def main() -> None:
    args = _build_parser().parse_args()

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

    threshold = Severity(args.severity) if args.severity else config.severity_threshold
    report    = Engine(config, analyzers).run(args.target)

    ConsoleReporter(severity_threshold=threshold).report(report)

if __name__ == "__main__":
    main()