"""Tests del motor regex y carga de reglas."""

from __future__ import annotations
import json
import re
from pathlib import Path
from vexcore.analyzers._base import RegexAnalyzer, load_rules
from vexcore.domain import Category, FileInfo, Severity
from vexcore.analyzers._base import Rule

def _file(tmp_path: Path, name: str, content: str) -> FileInfo:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return FileInfo(p, Path(name), p.suffix, p.stat().st_size)

def test_regex_finds_match_line(tmp_path):
    rule = Rule("TST001", "bad", Severity.HIGH, Category.SAST, frozenset(), re.compile(r"BAD"))
    findings = RegexAnalyzer([rule]).analyze(_file(tmp_path, "x.py", "ok\nBAD here\nok"))
    assert len(findings) == 1
    assert findings[0].line == 2
    assert findings[0].snippet == "BAD here"

def test_extension_filter(tmp_path):
    rule = Rule("TST001", "bad", Severity.HIGH, Category.SAST, frozenset({".py"}), re.compile(r"BAD"))
    findings = RegexAnalyzer([rule]).analyze(_file(tmp_path, "x.js", "BAD"))
    assert findings == []

def test_load_rules_skips_malformed(tmp_path):
    (tmp_path / "good.json").write_text(json.dumps([
        {"id": "T1", "title": "t", "severity": "high", "pattern": r"BAD"}
    ]))
    (tmp_path / "bad.json").write_text("{not json")
    rules = load_rules(tmp_path, Category.SAST)
    assert len(rules) == 1
    assert rules[0].id == "T1"
