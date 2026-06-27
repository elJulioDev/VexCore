# VexCore — AGENTS.md

## Stack

- Python ≥3.11 (`.python-version` = 3.14), **`uv`** as package manager, **hatchling** build backend
- Runtime dependencies: `PyYAML >= 6.0.3`, `textual >= 1.0.0`

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
| Analyzers | `src/analyzers/_base.py` — shared regex engine (`RegexAnalyzer`, `load_rules`); `sast.py`, `secrets.py`, `sca.py` adapters |
| Engine | `src/engine.py` — orchestrates Crawler + Analyzers |
| Config | `src/utils/config_loader.py` — YAML → typed `AppConfig`; defaults from `crawler` module constants |
| Reporter | `src/reporters/console.py` — ANSI-colored terminal output; `logger.py` is a stub |
| TUI | `src/tui/` — Textual-based TUI in separate branch (`feat/tui-terminal`) |
| Rules | `rules/` — JSON rule files: sast/django.json, sast/js.json, sast/php.json, secrets/generic.json, sca/pypi.json |

## Key details

- **Root `main.py` is a placeholder.** Real entry is `src/main.py` with argparse CLI (`vexcore <target>`).
- Config is loaded from `config.yaml` (default) or `-c/--config` flag. CLI `--severity` overrides the YAML threshold.
- **Crawler** skips dirs in `.git`, `__pycache__`, `venv`, `node_modules`, etc. by default. Respects `config.yaml` overrides.
- **SCA analyzer** is implemented and functional but **disabled by default** (`enabled: false` in config.yaml). Enable it to scan `requirements.txt` and `pyproject.toml` for vulnerable dependency versions.
- **SCA** uses semantic version comparison (tuples) — NOT regex. It parses manifests and compares against vulnerability rules in `rules/sca/pypi.json`.
- **Rules** format differs by analyzer type. SAST/Secrets: `{id, title, severity, extensions, pattern}` (regex). SCA: `{id, title, severity, package, version_constraint}`.
- Rules with invalid JSON or bad patterns are silently skipped.
- `logger.py` reporter and `tui/widgets/*` are unimplemented stubs.
- TUI is under development in the `feat/tui-terminal` branch.

## Conventions

- Imports use `from __future__ import annotations` for PEP 604 syntax.
- Dataclasses use `frozen=True, slots=True` for value objects (`FileInfo`, `Finding`, `Rule`, `ScaRule`).
- Enums extend `StrEnum`.
- Abstractions use `ABC` + `@abstractmethod`.
- Docstrings in English for new code.
- Snake_case for modules, PascalCase for classes, UPPER_CASE for constants.
