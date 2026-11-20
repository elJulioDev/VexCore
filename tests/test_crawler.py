"""Tests del crawler — filtrado de archivos y directorios."""

from __future__ import annotations
from pathlib import Path
from vexcore.crawler import Crawler

def _make_tree(root: Path) -> None:
    (root / "src").mkdir()
    (root / "node_modules").mkdir()
    (root / "src" / "app.py").write_text("x = 1")
    (root / "node_modules" / "dep.js").write_text("x")
    (root / "src" / "not_text.bin").write_bytes(b"\x00\x01\x02" * 100)

def test_walk_filtra_dirs_y_extensiones(tmp_path):
    _make_tree(tmp_path)
    files = list(Crawler(root=tmp_path).walk())
    rel = {str(f.relative) for f in files}
    assert "src/app.py" in rel
    assert "node_modules/dep.js" not in rel
    assert "src/not_text.bin" not in rel

def test_walk_incluye_env_y_variantes(tmp_path):
    for name in (".env", ".env.local", ".env.production"):
        (tmp_path / name).write_text("x", encoding="utf-8")
    for name in (
        ".env.example", ".env.local.example", ".env.sample",
        ".env.template", ".env.dist", ".gitignore",
    ):
        (tmp_path / name).write_text("x", encoding="utf-8")

    files = {str(f.relative): f.extension for f in Crawler(root=tmp_path).walk()}

    assert files == {
        ".env": ".env",
        ".env.local": ".env",
        ".env.production": ".env",
    }


def test_walk_normaliza_tokens_configurados(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.12", encoding="utf-8")
    (tmp_path / ".ENV").write_text("x", encoding="utf-8")

    files = {
        str(f.relative): f.extension
        for f in Crawler(root=tmp_path, scan_extensions=["Dockerfile", ".ENV"]).walk()
    }

    assert files == {"Dockerfile": "dockerfile", ".ENV": ".env"}
