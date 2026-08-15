"""sarif.py — Emite el Report en formato SARIF 2.1.0 (GitHub/GitLab Code Scanning)."""

from __future__ import annotations
import json
import sys
from ..domain import Finding, Report, Severity, meets_threshold
from ..ports import IReporter

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# Mapeo severidad VexCore -> nivel SARIF
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH:     "error",
    Severity.MEDIUM:   "warning",
    Severity.LOW:      "note",
    Severity.INFO:     "note",
}


class SarifReporter(IReporter):
    def __init__(self, severity_threshold: Severity = Severity.LOW) -> None:
        self._threshold = severity_threshold

    def report(self, report: Report) -> None:
        visible = [
            f for f in report.findings
            if meets_threshold(f.severity, self._threshold)
        ]

        rules_by_id: dict[str, str] = {}
        for f in visible:
            rules_by_id.setdefault(f.rule_id, f.title)

        rules = [
            {"id": rid, "shortDescription": {"text": title}}
            for rid, title in sorted(rules_by_id.items())
        ]

        results = [_result(f) for f in visible]

        doc = {
            "$schema": _SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "vexcore",
                        "informationUri": "https://github.com/elJulioDev/VexCore",
                        "rules": rules,
                    }
                },
                "results": results,
            }],
        }
        json.dump(doc, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")


def _result(f: Finding) -> dict:
    return {
        "ruleId": f.rule_id,
        "level": _LEVEL[f.severity],
        "message": {"text": f.title},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": str(f.file.relative)},
                "region": {"startLine": f.line},
            }
        }],
    }
