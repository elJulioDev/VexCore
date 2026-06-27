"""sca.py — Software Composition Analysis: detecta dependencias vulnerables."""

from __future__ import annotations
import json
import re
from dataclasses import dataclass
from pathlib import Path
from ..domain import Category, FileInfo, Finding, Severity
from ..ports import IAnalyzer

_MANIFEST_NAMES: frozenset[str] = frozenset({
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "Pipfile.lock",
    "setup.py",
    "setup.cfg",
})

_REQ_LINE = re.compile(r"^([a-zA-Z0-9_.-]+)\s*([><=!~]+)\s*([a-zA-Z0-9_.*]+)")
_TOML_DEP = re.compile(r'^([a-zA-Z0-9_.-]+)\s*=\s*"[><=!~]+\s*([a-zA-Z0-9_.*]+)"')


@dataclass(frozen=True, slots=True)
class ScaRule:
    id: str
    title: str
    severity: Severity
    package: str
    version_constraint: str


def _parse_version(v: str) -> tuple[int, ...]:
    parts = v.replace("-", ".").replace("_", ".").split(".")
    result: list[int] = []
    for p in parts:
        try:
            result.append(int(p))
        except ValueError:
            result.append(0)
    return tuple(result)


def _matches_constraint(version: str, constraint: str) -> bool:
    v = _parse_version(version)
    parts = [c.strip() for c in constraint.split(",")]
    for part in parts:
        m = re.match(r"^(>=|<=|!=|==|>|<)\s*([\w.*-]+)$", part)
        if not m:
            continue
        op, target_str = m.group(1), m.group(2)
        t = _parse_version(target_str)
        if op == "==" and v != t:
            return False
        if op == "!=" and v == t:
            return False
        if op == ">" and not (v > t):
            return False
        if op == ">=" and not (v >= t):
            return False
        if op == "<" and not (v < t):
            return False
        if op == "<=" and not (v <= t):
            return False
    return True


def _parse_requirements(text: str) -> list[tuple[str, str]]:
    pkgs: list[tuple[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = _REQ_LINE.match(line)
        if m:
            pkgs.append((m.group(1).lower(), m.group(3)))
    return pkgs


def _parse_pyproject_toml(text: str) -> list[tuple[str, str]]:
    pkgs: list[tuple[str, str]] = []
    in_deps = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and "dependencies" in stripped:
            in_deps = "project" in stripped and "dependencies" in stripped
            continue
        if stripped.startswith("["):
            in_deps = False
        if not in_deps:
            continue
        m = _TOML_DEP.match(stripped)
        if m:
            pkgs.append((m.group(1).lower(), m.group(2)))
    return pkgs


def _parse_manifest(file: FileInfo) -> list[tuple[str, str]]:
    try:
        text = file.absolute.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    name = file.absolute.name
    if name == "requirements.txt":
        return _parse_requirements(text)
    if name == "pyproject.toml":
        return _parse_pyproject_toml(text)
    return []


def _load_sca_rules(rules_dir: Path) -> list[ScaRule]:
    rules: list[ScaRule] = []
    for json_file in sorted(rules_dir.glob("*.json")):
        try:
            raw = json.loads(json_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        for r in raw:
            try:
                rules.append(
                    ScaRule(
                        id=r["id"],
                        title=r["title"],
                        severity=Severity(r["severity"]),
                        package=r["package"].lower(),
                        version_constraint=r["version_constraint"],
                    )
                )
            except (KeyError, ValueError):
                continue
    return rules


class ScaAnalyzer(IAnalyzer):
    def __init__(self, rules_dir: str | Path) -> None:
        self._rules = _load_sca_rules(Path(rules_dir))

    def analyze(self, file: FileInfo) -> list[Finding]:
        if file.absolute.name not in _MANIFEST_NAMES:
            return []
        pkgs = _parse_manifest(file)
        if not pkgs:
            return []
        findings: list[Finding] = []
        for pkg_name, pkg_version in pkgs:
            for rule in self._rules:
                if pkg_name != rule.package:
                    continue
                if _matches_constraint(pkg_version, rule.version_constraint):
                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            title=rule.title,
                            severity=rule.severity,
                            category=Category.SCA,
                            file=file,
                            line=1,
                            snippet=f"{pkg_name}=={pkg_version}",
                        )
                    )
        return findings
