"""console.py — Imprime findings en terminal con colores ANSI."""

from __future__ import annotations
from ..domain import Finding, Report, Severity
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

_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

def _rank(s: Severity) -> int:
    return _ORDER.index(s)

class ConsoleReporter(IReporter):
    def __init__(self, severity_threshold: Severity = Severity.LOW) -> None:
        self._threshold = severity_threshold

    def report(self, report: Report) -> None:
        visible = sorted(
            [f for f in report.findings if _rank(f.severity) <= _rank(self._threshold)],
            key=lambda f: (_rank(f.severity), str(f.file.relative), f.line),
        )

        for finding in visible:
            self._print_finding(finding)

        self._print_summary(report)

    def _print_finding(self, f: Finding) -> None:
        color = _COLORS[f.severity]
        tag   = f"[{f.severity.upper()}]"
        print(f"\n{color}{_BOLD}{tag:<12}{_RESET} {f.rule_id} — {f.title}")
        print(f"  {_DIM}{f.file.relative}:{f.line}{_RESET}  {f.snippet}")

    def _print_summary(self, report: Report) -> None:
        print("\n" + "─" * 50)
        print(f"Archivos escaneados : {report.scanned_files}")
        print(f"Hallazgos           : {report.total}")
        print(f"Tiempo              : {report.elapsed_secs}s\n")

        counts = {s: len(report.by_severity(s)) for s in _ORDER if report.by_severity(s)}
        parts  = [
            f"{_COLORS[s]}{s.upper():<10}{_RESET}{n}"
            for s, n in counts.items()
        ]
        print("  " + "   ".join(parts))