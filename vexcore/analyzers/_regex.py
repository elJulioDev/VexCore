"""_regex.py — Motor regex compartido entre analizadores."""

from __future__ import annotations
from ..domain import FileInfo, Finding, Rule


class RegexAnalyzer:
    def __init__(self, rules: list[Rule]) -> None:
        self._rules = rules

    def analyze(self, file: FileInfo) -> list[Finding]:
        applicable = [
            r for r in self._rules
            if not r.extensions or file.extension in r.extensions
        ]
        if not applicable:
            return []

        try:
            lines = file.absolute.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return []

        findings: list[Finding] = []
        for line_no, line in enumerate(lines, start=1):
            for rule in applicable:
                if rule.pattern.search(line):
                    findings.append(Finding(
                        rule_id=rule.id,
                        title=rule.title,
                        severity=rule.severity,
                        category=rule.category,
                        file=file,
                        line=line_no,
                        snippet=line.strip()[:200],
                    ))
        return findings
