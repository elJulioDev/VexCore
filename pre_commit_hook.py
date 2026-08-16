#!/usr/bin/env python3
"""pre_commit_hook.py — Hook de pre-commit para VexCore.

Uso con pre-commit framework:
  repos:
    - repo: https://github.com/elJulioDev/VexCore
      rev: main
      hooks:
        - id: vexcore

Uso standalone:
  python pre_commit_hook.py [archivos...]
"""

from __future__ import annotations
import subprocess
import sys


def main() -> int:
    files = sys.argv[1:]
    cmd = [sys.executable, "-m", "vexcore.main", "--output", "json", "--fail-on", "high"]

    if files:
        # pre-commit pasa los archivos staged. Escaneamos el directorio
        # y filtramos por los archivos dados.
        result = subprocess.run(
            cmd + ["."],
            capture_output=True, text=True,
        )
    else:
        result = subprocess.run(
            cmd + ["."],
            capture_output=True, text=True,
        )

    if result.returncode != 0:
        # Imprime findings legibles en stderr
        print(result.stdout, file=sys.stderr)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
