"""suppressions.py — Carga .vexcoreignore y filtra findings.

Formato del archivo (una regla por línea, # para comentarios):
  - DJG001            → suprime por rule_id
  - tests/*.py        → suprime por patrón de ruta relativa (fnmatch)
  - */generated/*     → comodín en cualquier nivel
"""

from __future__ import annotations
import fnmatch
from pathlib import Path
from .domain import Finding

class Suppressions:
    def __init__(self, target: Path) -> None:
        self._rules: set[str] = set()
        self._paths: list[str] = []
        self._load(target / ".vexcoreignore")

    def _load(self, path: Path) -> None:
        if not path.exists():
            return
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if _is_rule_id(line):
                self._rules.add(line)
            else:
                self._paths.append(line)

    def is_suppressed(self, finding: Finding) -> bool:
        if finding.rule_id in self._rules:
            return True
        rel = str(finding.file.relative)
        return any(fnmatch.fnmatch(rel, pat) for pat in self._paths)

    def filter(self, findings: list[Finding]) -> list[Finding]:
        return [f for f in findings if not self.is_suppressed(f)]


def _is_rule_id(token: str) -> bool:
    """Reconoce IDs tipo DJG001, SEC016, PYA010 (3 mayúsculas + 3 dígitos)."""
    return len(token) == 6 and token[:3].isupper() and token[3:].isdigit()
