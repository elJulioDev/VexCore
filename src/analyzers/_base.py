"""_base.py — Motor regex compartido entre analizadores."""

from __future__ import annotations
import json
import re
from dataclasses import dataclass
from pathlib import Path
from ..domain import Category, FileInfo, Finding, Severity

@dataclass(frozen=True, slots=True)
class Rule:
    id:         str
    title:      str
    severity:   Severity
    category:   Category
    extensions: frozenset[str]  # vacío = aplica a todos los archivos
    pattern:    re.Pattern

class RegexAnalyzer:
    """Escanea un archivo línea a línea contra un conjunto de reglas."""

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

def load_rules(rules_dir: Path, category: Category) -> list[Rule]:
    """Carga todos los .json del directorio y compila cada regla."""
    rules: list[Rule] = []

    for json_file in sorted(rules_dir.glob("*.json")):
        raw = json.loads(json_file.read_text(encoding="utf-8"))
        for r in raw:
            try:
                rules.append(Rule(
                    id=r["id"],
                    title=r["title"],
                    severity=Severity(r["severity"]),
                    category=category,
                    extensions=frozenset(r.get("extensions", [])),
                    pattern=re.compile(r["pattern"]),
                ))
            except (KeyError, re.error):
                # Regla malformada — se omite sin crashear
                continue

    return rules