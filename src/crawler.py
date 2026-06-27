"""crawler.py — Recorre el FileSystem y produce FileInfo de forma lazy."""

from __future__ import annotations
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Generator, Iterable, Set

# Sobreescribibles desde config.yaml
DEFAULT_IGNORE_DIRS: frozenset[str] = frozenset({
    ".git", ".hg", ".svn",                                # VCS
    "__pycache__", ".mypy_cache", ".pytest_cache", ".tox",
    "venv", ".venv", "env",                               # Python
    "node_modules", ".yarn", "dist", "build",             # Node
    "vendor",                                             # PHP
    ".idea", ".vscode",                                   # IDEs
    "migrations",                                         # Django
})

DEFAULT_SCAN_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".php",
    ".html", ".htm", ".js", ".ts", ".jsx", ".tsx",
    ".env", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".json",
    ".sh", ".bash",
    ".java", ".kt", ".rb", ".c", ".cpp", ".h", ".go",
    ".txt", ".lock", ".xml",
})

MAX_FILE_SIZE_BYTES: int = 5 * 1024 * 1024  # 5 MB — descarta binarios disfrazados

@dataclass(frozen=True, slots=True)
class FileInfo:
    """Snapshot inmutable de un archivo listo para analizar."""
    absolute: Path
    relative: Path
    extension: str
    size_bytes: int

class Crawler:
    """Recorre un directorio y emite FileInfo de forma lazy."""

    def __init__(
        self,
        root: str | Path,
        *,
        ignore_dirs: Iterable[str] | None = None,
        scan_extensions: Iterable[str] | None = None,
        max_file_size: int = MAX_FILE_SIZE_BYTES,
        follow_symlinks: bool = False,
    ) -> None:
        self.root: Path = Path(root).resolve()
        self.ignore_dirs: Set[str] = (
            set(ignore_dirs) if ignore_dirs is not None else set(DEFAULT_IGNORE_DIRS)
        )
        self.scan_extensions: Set[str] = (
            set(scan_extensions) if scan_extensions is not None else set(DEFAULT_SCAN_EXTENSIONS)
        )
        self.max_file_size: int = max_file_size
        self.follow_symlinks: bool = follow_symlinks
        self._visited: int = 0
        self._skipped: int = 0

    def walk(self) -> Generator[FileInfo, None, None]:
        """Genera FileInfo para cada archivo relevante bajo self.root."""
        if not self.root.is_dir():
            raise NotADirectoryError(f"Ruta inválida o no es directorio: {self.root}")

        self._visited = 0
        self._skipped = 0

        for dirpath, dirnames, filenames in os.walk(
            self.root, topdown=True, followlinks=self.follow_symlinks
        ):
            # Poda in-place: os.walk no desciende en dirs excluidos
            dirnames[:] = [
                d for d in dirnames
                if d not in self.ignore_dirs and not d.startswith(".")
            ]

            current_dir = Path(dirpath)

            for filename in filenames:
                file_path = current_dir / filename
                info = self._evaluate(file_path)
                if info is not None:
                    self._visited += 1
                    yield info
                else:
                    self._skipped += 1

    @property
    def stats(self) -> dict[str, int]:
        """Métricas del último walk: aceptados, omitidos y total."""
        return {
            "visited": self._visited,
            "skipped": self._skipped,
            "total":   self._visited + self._skipped,
        }

    def _evaluate(self, path: Path) -> FileInfo | None:
        """Retorna FileInfo si el archivo pasa todos los filtros, None si se descarta."""
        try:
            if path.is_symlink() and not self.follow_symlinks:
                return None

            ext = path.suffix.lower()
            if ext not in self.scan_extensions:
                return None

            size = path.stat().st_size
            if size == 0 or size > self.max_file_size:
                return None

            return FileInfo(
                absolute=path,
                relative=path.relative_to(self.root),
                extension=ext,
                size_bytes=size,
            )

        except (PermissionError, OSError):
            return None