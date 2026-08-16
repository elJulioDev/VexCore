"""cache.py — Caché de hashes para incremental scanning.

Almacena SHA-256 de archivos en ~/.vexcore/cache/files.json.
Solo se re-escanean archivos cuyo hash cambió desde la última ejecución.
"""

from __future__ import annotations
import hashlib
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_DEFAULT_CACHE_DIR = Path("~/.vexcore/cache").expanduser()
_CACHE_FILE = "files.json"


class FileCache:
    """Caché de hashes SHA-256 por archivo."""

    def __init__(self, cache_dir: Path | None = None) -> None:
        self._dir = cache_dir or _DEFAULT_CACHE_DIR
        self._path = self._dir / _CACHE_FILE
        self._data: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            self._data = json.loads(self._path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            self._data = {}

    def save(self) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps(self._data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def get_changed(self, paths: list[Path]) -> list[Path]:
        """Retorna solo los archivos cuyo hash cambió o no están en cache."""
        changed: list[Path] = []
        for p in paths:
            h = _file_hash(p)
            key = str(p)
            if self._data.get(key) != h:
                changed.append(p)
        return changed

    def update(self, paths: list[Path]) -> None:
        """Actualiza los hashes de los archivos dados."""
        for p in paths:
            self._data[str(p)] = _file_hash(p)


def _file_hash(path: Path) -> str:
    """SHA-256 del contenido del archivo. Truncado a 16 hex chars (64 bits)."""
    h = hashlib.sha256()
    try:
        h.update(path.read_bytes())
    except OSError:
        return ""
    return h.hexdigest()[:16]
