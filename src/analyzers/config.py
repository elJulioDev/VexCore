"""config.py — Adaptador para reglas de configuración (.env, docker-compose, settings)."""

from __future__ import annotations
from pathlib import Path
from ..domain import Category, FileInfo, Finding
from ..ports import IAnalyzer
from ._base import RegexAnalyzer, load_rules

class ConfigAnalyzer(IAnalyzer):
    def __init__(self, rules_dir: str | Path) -> None:
        self._engine = RegexAnalyzer(load_rules(Path(rules_dir), Category.CONFIG))

    def analyze(self, file: FileInfo) -> list[Finding]:
        return self._engine.analyze(file)
