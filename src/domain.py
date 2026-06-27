"""domain.py — Entidades núcleo de VexCore. Sin dependencias externas."""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"

class Category(StrEnum):
    SAST   = "sast"
    SECRET = "secret"
    SCA    = "sca"

@dataclass(frozen=True, slots=True)
class FileInfo:
    """Snapshot inmutable de un archivo listo para analizar."""
    absolute:   Path
    relative:   Path
    extension:  str
    size_bytes: int

@dataclass(frozen=True, slots=True)
class Finding:
    """Hallazgo detectado en un archivo."""
    rule_id:  str
    title:    str
    severity: Severity
    category: Category
    file:     FileInfo
    line:     int
    snippet:  str

@dataclass
class Report:
    """Resultado completo de un escaneo."""
    target:        Path
    findings:      list[Finding] = field(default_factory=list)
    scanned_files: int           = 0
    elapsed_secs:  float         = 0.0

    @property
    def total(self) -> int:
        return len(self.findings)

    def by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]