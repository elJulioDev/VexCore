"""Tests de config_loader — parseo de YAML con defaults."""

from __future__ import annotations
from pathlib import Path
from vexcore.utils.config_loader import load_config

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
