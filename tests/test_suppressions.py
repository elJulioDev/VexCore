"""Tests de suppressions — .vexcoreignore filtra por rule_id y patrón de ruta."""

from __future__ import annotations
from pathlib import Path
from src.domain import Category, FileInfo, Finding, Severity
from src.suppressions import Suppressions

def _finding(rule_id: str, rel: str) -> Finding:
    return Finding(
        rule_id=rule_id, title="t", severity=Severity.HIGH, category=Category.SAST,
        file=FileInfo(Path("/abs") / rel, Path(rel), Path(rel).suffix, 1),
        line=1, snippet="x",
    )

def test_suppress_by_rule_and_path(tmp_path):
    (tmp_path / ".vexcoreignore").write_text(
        "DJG001\n# comentario\ntests/*.py\n", encoding="utf-8"
    )
    s = Suppressions(tmp_path)
    assert s.is_suppressed(_finding("DJG001", "app.py"))
    assert s.is_suppressed(_finding("DJG005", "tests/foo.py"))
    assert not s.is_suppressed(_finding("DJG005", "app.py"))
