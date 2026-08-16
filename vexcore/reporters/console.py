"""console.py — Imprime findings en terminal con colores ANSI."""

from __future__ import annotations
import os
import sys
from collections import Counter
from ..domain import (
    SEVERITY_ORDER,
    Finding,
    Report,
    Severity,
    meets_threshold,
    severity_index,
)
from ..ports import IReporter

_COLORS = {
    Severity.CRITICAL: "\033[91m",
    Severity.HIGH:     "\033[93m",
    Severity.MEDIUM:   "\033[94m",
    Severity.LOW:      "\033[96m",
    Severity.INFO:     "\033[37m",
}
_RESET = "\033[0m"
_BOLD  = "\033[1m"
_DIM   = "\033[2m"


class ConsoleReporter(IReporter):
    def __init__(
        self,
        severity_threshold: Severity = Severity.LOW,
        *,
        color: bool | None = None,
    ) -> None:
        self._threshold = severity_threshold
        # Auto-detecta: sin color si NO_COLOR está set o no es TTY.
        self._color = sys.stdout.isatty() if color is None else color
        self._color = self._color and not os.environ.get("NO_COLOR")

    def report(self, report: Report) -> None:
        visible = sorted(
            [f for f in report.findings if meets_threshold(f.severity, self._threshold)],
            key=lambda f: (severity_index(f.severity), str(f.file.relative), f.line),
        )

        for finding in visible:
            self._print_finding(finding)

        self._print_summary(report)

    def _print_finding(self, f: Finding) -> None:
        color = _COLORS[f.severity] if self._color else ""
        reset = _RESET if self._color else ""
        bold  = _BOLD if self._color else ""
        dim   = _DIM if self._color else ""
        tag   = f"[{f.severity.upper()}]"
        print(f"\n{color}{bold}{tag:<12}{reset} {f.rule_id} — {f.title}")
        print(f"  {dim}{f.file.relative}:{f.line}{reset}  {f.snippet}")

    def _print_summary(self, report: Report) -> None:
        print("\n" + "─" * 50)
        print(f"Archivos escaneados : {report.scanned_files}")
        print(f"Hallazgos           : {report.total}")
        print(f"Tiempo              : {report.elapsed_secs}s\n")

        counts = Counter(f.severity for f in report.findings)
        parts = [
            f"{_COLORS[s] if self._color else ''}{s.upper():<10}{_RESET if self._color else ''}{counts[s]}"
            for s in SEVERITY_ORDER
            if counts.get(s)
        ]
        print("  " + "   ".join(parts))
