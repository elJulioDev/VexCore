"""Tests del crawler — filtrado de archivos y directorios."""

from __future__ import annotations
from pathlib import Path
from src.crawler import Crawler

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
