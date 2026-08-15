"""json.py — Emite el Report como JSON para CI/CD."""

from __future__ import annotations
import json
import sys
from ..domain import Finding, Report, Severity, meets_threshold
from ..ports import IReporter


def _finding_to_dict(f: Finding) -> dict:
    return {
        "rule_id": f.rule_id,
        "title": f.title,
        "severity": f.severity.value,
        "category": f.category.value,
        "file": str(f.file.relative),
        "line": f.line,
        "snippet": f.snippet,
    }


class JsonReporter(IReporter):
    def __init__(self, severity_threshold: Severity = Severity.LOW) -> None:
        self._threshold = severity_threshold

    def report(self, report: Report) -> None:
        findings = [
            _finding_to_dict(f)
            for f in report.findings
            if meets_threshold(f.severity, self._threshold)
        ]
        doc = {
            "target": str(report.target),
            "scanned_files": report.scanned_files,
            "elapsed_secs": report.elapsed_secs,
            "total_findings": len(findings),
            "findings": findings,
        }
        json.dump(doc, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
