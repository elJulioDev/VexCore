"""config_loader.py — Carga config.yaml en estructuras tipadas."""

from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import yaml
from ..crawler import DEFAULT_IGNORE_DIRS, DEFAULT_SCAN_EXTENSIONS, MAX_FILE_SIZE_BYTES
from ..domain import Severity

_MB = 1024 * 1024
_GLOBAL_CONFIG = Path("~/.vexcore/config.yaml").expanduser()

# Rules ship inside the package, so the defaults work from any working directory
# and in an installed wheel.
BUILTIN_RULES_DIR = Path(__file__).resolve().parent.parent / "rules"

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
    config:             AnalyzerConfig
    plugins_dir:        Path | None = None
    incremental:        bool = False
    severity_threshold: Severity = Severity.LOW

def load_config(path: str | Path | None = None) -> AppConfig:
    """Carga config.yaml con resolución en cascada:
      1. path explícito (flag -c)
      2. config.yaml en CWD
      3. ~/.vexcore/config.yaml (global)
      4. defaults
    """
    config_path = _resolve_config_path(path)
    if config_path is None:
        return _validate(_parse({}, base_dir=Path.cwd()))

    with config_path.open(encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    # Relative paths in a config file are relative to that file, not to the CWD.
    return _validate(_parse(raw, base_dir=config_path.resolve().parent))


def _resolve_config_path(explicit: str | Path | None) -> Path | None:
    if explicit is not None:
        p = Path(explicit)
        if p.exists():
            return p
        raise FileNotFoundError(f"No se encontró config en: {p}")

    local = Path("config.yaml")
    if local.exists():
        return local

    if _GLOBAL_CONFIG.exists():
        return _GLOBAL_CONFIG

    return None

def _parse(raw: dict, base_dir: Path) -> AppConfig:
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
        sast=_parse_analyzer(a.get("sast", {}), "sast", base_dir),
        secrets=_parse_analyzer(a.get("secrets", {}), "secrets", base_dir),
        sca=_parse_analyzer(a.get("sca", {}), "sca", base_dir, default_enabled=False),
        config=_parse_analyzer(a.get("config", {}), "config", base_dir, default_enabled=False),
        plugins_dir=_resolve(p, base_dir) if (p := raw.get("plugins_dir")) else None,
        incremental=raw.get("incremental", False),
        severity_threshold=Severity(raw.get("output", {}).get("severity_threshold", "low")),
    )

def _parse_analyzer(
    section: dict,
    name: str,
    base_dir: Path,
    *,
    default_enabled: bool = True,
) -> AnalyzerConfig:
    custom = section.get("rules_path")
    return AnalyzerConfig(
        enabled=section.get("enabled", default_enabled),
        rules_path=_resolve(custom, base_dir) if custom else BUILTIN_RULES_DIR / name,
        source=section.get("source", "both"),
    )

def _resolve(path: str | Path, base_dir: Path) -> Path:
    """Expand ~ and anchor a relative path at base_dir."""
    p = Path(path).expanduser()
    return p if p.is_absolute() else base_dir / p

def _validate(cfg: AppConfig) -> AppConfig:
    """Fail loudly if an enabled analyzer has no rules directory.

    Otherwise the analyzer would load zero rules and the scan would silently
    report a clean result.
    """
    for name in ("sast", "secrets", "sca", "config"):
        analyzer: AnalyzerConfig = getattr(cfg, name)
        if analyzer.enabled and not analyzer.rules_path.is_dir():
            raise FileNotFoundError(
                f"No se encontró el directorio de reglas de '{name}': {analyzer.rules_path}"
            )
    return cfg