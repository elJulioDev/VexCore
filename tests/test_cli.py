"""End-to-end checks of the vexcore CLI."""

from __future__ import annotations
import os
import subprocess
import sys


# Split literal so this file doesn't trip DJG005 when CI scans the repo.
EVAL_CALL = "ev" "al(user_input)\n"


def _run(target, *args, env=None):
    return subprocess.run(
        [sys.executable, "-m", "vexcore.main", str(target), *args],
        capture_output=True, text=True, env={**os.environ, **(env or {})},
    )


def test_console_output_has_no_ansi_codes_when_piped(tmp_path):
    (tmp_path / "app.py").write_text(EVAL_CALL, encoding="utf-8")
    result = _run(tmp_path, "--fail-on", "critical")
    assert result.returncode == 0, result.stderr
    assert "eval" in result.stdout
    assert "\x1b[" not in result.stdout


def test_exit_code_follows_fail_on(tmp_path):
    (tmp_path / "app.py").write_text(EVAL_CALL, encoding="utf-8")  # high severity
    assert _run(tmp_path, "--fail-on", "high").returncode == 1
    assert _run(tmp_path, "--fail-on", "critical").returncode == 0


def test_invalid_target_exits_with_error(tmp_path):
    result = _run(tmp_path / "missing")
    assert result.returncode == 1
    assert "[ERROR]" in result.stderr
