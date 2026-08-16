"""Tests de domain.py — entidades y orden de severidad."""

from __future__ import annotations
from vexcore.domain import Category, FileInfo, Finding, Report, Severity, meets_threshold, severity_index
from pathlib import Path

def test_severity_order():
    assert severity_index(Severity.CRITICAL) < severity_index(Severity.INFO)
    assert [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

def test_meets_threshold():
    assert meets_threshold(Severity.HIGH, Severity.LOW)
    assert meets_threshold(Severity.CRITICAL, Severity.CRITICAL)
    assert not meets_threshold(Severity.LOW, Severity.HIGH)

def test_report_total_y_by_severity():
    f = Finding(
        rule_id="DJG001", title="t", severity=Severity.HIGH, category=Category.SAST,
        file=FileInfo(Path("/a/b.py"), Path("b.py"), ".py", 10),
        line=1, snippet="x",
    )
    report = Report(target=Path("."), findings=[f])
    assert report.total == 1
    assert len(report.by_severity(Severity.HIGH)) == 1
    assert report.by_severity(Severity.LOW) == []
