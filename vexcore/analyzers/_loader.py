"""_loader.py — Carga reglas desde archivos JSON."""

from __future__ import annotations
import json
import re
from pathlib import Path
from ..domain import Category, Rule, Severity


def load_rules(rules_dir: Path, category: Category) -> list[Rule]:
    rules: list[Rule] = []

    for json_file in sorted(rules_dir.glob("*.json")):
        content = json_file.read_text(encoding="utf-8").strip()
        if not content:
            continue

        try:
            raw = json.loads(content)
        except json.JSONDecodeError:
            continue

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
                continue

    return rules
