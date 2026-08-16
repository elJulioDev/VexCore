"""ports.py — Puertos que conectan el núcleo con los adaptadores."""

from __future__ import annotations
from abc import ABC, abstractmethod
from .domain import FileInfo, Finding, Report

class IAnalyzer(ABC):
    """Recibe un archivo y devuelve hallazgos."""

    @abstractmethod
    def analyze(self, file: FileInfo) -> list[Finding]: ...

class IReporter(ABC):
    """Consume un Report y lo emite al canal correspondiente."""

    @abstractmethod
    def report(self, report: Report) -> None: ...