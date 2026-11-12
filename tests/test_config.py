"""Tests de config_loader — parseo de YAML con defaults."""

from __future__ import annotations
import json
import os
import subprocess
import sys
from pathlib import Path
import pytest
from vexcore.utils.config_loader import BUILTIN_RULES_DIR, load_config

def test_load_config_defaults(tmp_path):
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(
        "analyzers:\n  sca:\n    enabled: true\noutput:\n  severity_threshold: high\n",
        encoding="utf-8",
    )
    cfg = load_config(cfg_path)
    assert cfg.sca.enabled is True
    assert cfg.sast.enabled is True
    assert cfg.severity_threshold.value == "high"

def test_load_config_inexistente():
    try:
        load_config("no_existe.yaml")
        assert False, "debería lanzar FileNotFoundError"
    except FileNotFoundError:
        pass

def test_default_rules_are_bundled_in_package(tmp_path, monkeypatch):
    """Without a config file, rules resolve to the package, not the CWD."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("vexcore.utils.config_loader._GLOBAL_CONFIG", tmp_path / "none.yaml")
    cfg = load_config()
    assert cfg.sast.rules_path == BUILTIN_RULES_DIR / "sast"
    assert any(cfg.sast.rules_path.glob("*.json"))
    assert any(cfg.secrets.rules_path.glob("*.json"))

def test_relative_paths_resolve_from_config_dir(tmp_path, monkeypatch):
    (tmp_path / "custom").mkdir()
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(
        "analyzers:\n  sast:\n    rules_path: custom\nplugins_dir: plugins\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path.parent)
    cfg = load_config(cfg_path)
    assert cfg.sast.rules_path == tmp_path / "custom"
    assert cfg.plugins_dir == tmp_path / "plugins"
    assert cfg.secrets.rules_path == BUILTIN_RULES_DIR / "secrets"

def test_missing_rules_dir_for_enabled_analyzer_fails(tmp_path):
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text("analyzers:\n  sast:\n    rules_path: nope\n", encoding="utf-8")
    with pytest.raises(FileNotFoundError, match="sast"):
        load_config(cfg_path)

def test_missing_rules_dir_for_disabled_analyzer_is_ignored(tmp_path):
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(
        "analyzers:\n  sca:\n    enabled: false\n    rules_path: nope\n", encoding="utf-8",
    )
    assert load_config(cfg_path).sca.enabled is False

def test_cli_finds_rules_from_another_cwd(tmp_path):
    """Regression: running outside the repo used to load 0 rules and report 0 findings."""
    target = tmp_path / "proj"
    target.mkdir()
    # Split literal so this test file itself doesn't trip SEC003 when CI scans the repo.
    (target / "app.py").write_text("pass" 'word = "hunter2secret"\n', encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-m", "vexcore.main", str(target), "--output", "json", "--fail-on", "critical"],
        cwd=tmp_path, capture_output=True, text=True,
        env={**os.environ, "HOME": str(tmp_path)},
    )
    assert result.returncode in (0, 1), result.stderr
    assert json.loads(result.stdout)["findings"], result.stdout
