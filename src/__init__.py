"""vexcore — Escáner estático de seguridad.

Uso como librería:
    from src import scan
    report = scan("./myproject")
    print(report.total)
"""

from __future__ import annotations
from pathlib import Path
from .analyzers import AstAnalyzer, SastAnalyzer, SecretsAnalyzer
from .domain import Report
from .engine import Engine
from .utils.config_loader import load_config


def scan(
    target: str | Path,
    config: str | Path | None = None,
) -> Report:
    """Escanea un directorio y retorna un Report con los findings.

    Args:
        target: Directorio a escanear.
        config: Ruta a config.yaml (None = resolución en cascada).
    """
    cfg = load_config(config)
    analyzers = []
    if cfg.sast.enabled:
        analyzers.append(SastAnalyzer(cfg.sast.rules_path))
    if cfg.secrets.enabled:
        analyzers.append(SecretsAnalyzer(cfg.secrets.rules_path))
    analyzers.append(AstAnalyzer())
    return Engine(cfg, analyzers).run(Path(target))
