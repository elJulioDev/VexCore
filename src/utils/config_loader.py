"""config_loader.py — Carga config.yaml en estructuras tipadas."""

from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import yaml
from ..crawler import DEFAULT_IGNORE_DIRS, DEFAULT_SCAN_EXTENSIONS, MAX_FILE_SIZE_BYTES
from ..domain import Severity

_MB = 1024 * 1024

@dataclass
class CrawlerConfig:
    ignore_dirs:         set[str]
    scan_extensions:     set[str]
    max_file_size_bytes: int
    follow_symlinks:     bool = False

@dataclass
class AnalyzerConfig:
    enabled:    bool
    rules_path: Path
    source:     str = "both"

@dataclass
class AppConfig:
    crawler:            CrawlerConfig
    sast:               AnalyzerConfig
    secrets:            AnalyzerConfig
    sca:                AnalyzerConfig
    severity_threshold: Severity = Severity.LOW

def load_config(path: str | Path = "config.yaml") -> AppConfig:
    """Carga config.yaml; usa defaults si faltan claves."""
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"No se encontró config en: {config_path}")

    with config_path.open(encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    return _parse(raw)

def _parse(raw: dict) -> AppConfig:
    c = raw.get("crawler", {})
    a = raw.get("analyzers", {})

    crawler = CrawlerConfig(
        ignore_dirs=set(c.get("ignore_dirs", DEFAULT_IGNORE_DIRS)),
        scan_extensions=set(c.get("scan_extensions", DEFAULT_SCAN_EXTENSIONS)),
        max_file_size_bytes=c.get("max_file_size_mb", MAX_FILE_SIZE_BYTES // _MB) * _MB,
        follow_symlinks=c.get("follow_symlinks", False),
    )

    return AppConfig(
        crawler=crawler,
        sast=_parse_analyzer(a.get("sast", {}), default_path="rules/sast"),
        secrets=_parse_analyzer(a.get("secrets", {}), default_path="rules/secrets"),
        sca=_parse_analyzer(a.get("sca", {}), default_path="rules/sca", default_enabled=False),
        severity_threshold=Severity(raw.get("output", {}).get("severity_threshold", "low")),
    )

def _parse_analyzer(
    section: dict,
    *,
    default_path: str,
    default_enabled: bool = True,
) -> AnalyzerConfig:
    return AnalyzerConfig(
        enabled=section.get("enabled", default_enabled),
        rules_path=Path(section.get("rules_path", default_path)),
        source=section.get("source", "both"),
    )