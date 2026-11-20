"""Consistency checks between the bundled rules and what the crawler scans."""

from __future__ import annotations
import json
from pathlib import Path
import pytest
from vexcore.crawler import DEFAULT_SCAN_EXTENSIONS, Crawler
from vexcore.utils.config_loader import BUILTIN_RULES_DIR, load_config

REPO_CONFIG = Path(__file__).resolve().parent.parent / "config.yaml"


def _rule_extensions() -> set[str]:
    exts: set[str] = set()
    for f in BUILTIN_RULES_DIR.glob("*/*.json"):
        for rule in json.loads(f.read_text(encoding="utf-8")):
            exts.update(rule.get("extensions", []))
    return exts


def test_bundled_rules_are_valid_and_ids_unique():
    ids: list[str] = []
    for f in BUILTIN_RULES_DIR.glob("*/*.json"):
        rules = json.loads(f.read_text(encoding="utf-8"))
        assert rules, f"{f} is empty"
        ids.extend(r["id"] for r in rules)
    assert len(ids) == len(set(ids)), "duplicate rule IDs"


@pytest.mark.parametrize(
    "scanned",
    [
        pytest.param(DEFAULT_SCAN_EXTENSIONS, id="crawler-defaults"),
        pytest.param(load_config(REPO_CONFIG).crawler.scan_extensions, id="repo-config.yaml"),
    ],
)
def test_every_rule_extension_is_scanned(scanned):
    """A rule whose extension is never crawled can never fire."""
    missing = _rule_extensions() - set(scanned)
    assert not missing, f"rules target extensions the crawler skips: {sorted(missing)}"


@pytest.mark.parametrize("ext", sorted(_rule_extensions()))
def test_rule_extension_is_crawled_by_name_and_suffix(tmp_path, ext):
    """Set membership misses that Path('.env').suffix is empty."""
    (tmp_path / f"app{ext}").write_text("x", encoding="utf-8")
    (tmp_path / ext).write_text("x", encoding="utf-8")

    crawled = {str(f.relative) for f in Crawler(root=tmp_path).walk()}

    assert f"app{ext}" in crawled
    assert ext in crawled
