# VexCore — AGENTS.md

## Stack

- Python ≥3.11 (`.python-version` = 3.14), **`uv`** as package manager, **hatchling** build backend
- Only runtime dependency: `PyYAML >= 6.0.3`

## Commands

```sh
uv sync                    # install deps from uv.lock
uv run vexcore <target>    # scan a directory (entry: src.main:main)
uv run python -m src.main <target>   # same, without installed script
uv add <pkg>               # add a dependency
```

No tests, linters, formatters, type checkers, or CI exist yet.

## Architecture (hexagonal / ports-and-adapters)

| Layer | Key files |
|-------|-----------|
| Domain | `src/domain.py` — `FileInfo`, `Finding`, `Report`, `Severity`, `Category` |
| Ports | `src/ports.py` — `IAnalyzer`, `IReporter` |
| Crawler | `src/crawler.py` — lazy filesystem walk, filters by extension/size/ignored dirs |
| Analyzers | `src/analyzers/_base.py` — shared regex engine (`RegexAnalyzer`, `load_rules`); `sast.py`, `secrets.py` adapters |
| Engine | `src/engine.py` — orchestrates Crawler + Analyzers |
| Config | `src/utils/config_loader.py` — YAML → typed `AppConfig`; defaults from `crawler` module constants |
| Reporter | `src/reporters/console.py` — ANSI-colored terminal output; `logger.py` is a stub |
| TUI | `src/tui/` — all stubs (Textual-based, not implemented yet) |
| Rules | `rules/` — JSON rule files (sast/django.json, secrets/generic.json); SCA rules in `rules/sca/` (empty) |

## Key details

- **Root `main.py` is a placeholder.** Real entry is `src/main.py` with argparse CLI (`vexcore <target>`).
- Config is loaded from `config.yaml` (default) or `-c/--config` flag. CLI `--severity` overrides the YAML threshold.
- **Crawler** skips dirs in `.git`, `__pycache__`, `venv`, `node_modules`, etc. by default. Respects `config.yaml` overrides.
- **SCA analyzer** is disabled by default (`enabled: false` in config.yaml). TUI and `logger.py` reporter are unimplemented stubs.
- Rules are JSON arrays with `id`, `title`, `severity`, `extensions` (empty = all files), and `pattern` (Python regex). Rules with invalid JSON or bad regexes are silently skipped.

## Conventions

- Imports use `from __future__ import annotations` for PEP 604 syntax.
- Dataclasses use `frozen=True, slots=True` for value objects (`FileInfo`, `Finding`, `Rule`).
- Enums extend `StrEnum`.
- Abstractions use `ABC` + `@abstractmethod`.
- Docstrings are in Spanish (project description) or English (code comments). Prefer English for new code.
- Snake_case for modules, PascalCase for classes, UPPER_CASE for constants.
