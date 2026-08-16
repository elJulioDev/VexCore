"""engine.py — Orquesta Crawler y analizadores."""

from __future__ import annotations
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from .cache import FileCache
from .crawler import Crawler
from .domain import Report, severity_index
from .ports import IAnalyzer
from .suppressions import Suppressions
from .utils.config_loader import AppConfig

class Engine:
    def __init__(self, config: AppConfig, analyzers: list[IAnalyzer]) -> None:
        self._config = config
        self._analyzers = analyzers

    def run(self, target: Path) -> Report:
        c = self._config.crawler
        crawler = Crawler(
            root=target,
            ignore_dirs=c.ignore_dirs,
            scan_extensions=c.scan_extensions,
            max_file_size=c.max_file_size_bytes,
            follow_symlinks=c.follow_symlinks,
        )

        report = Report(target=target)
        suppressions = Suppressions(target)
        start = time.perf_counter()

        def _analyze(file_info):
            return [
                f for analyzer in self._analyzers
                for f in analyzer.analyze(file_info)
            ]

        if self._config.incremental:
            cache = FileCache()
            all_files = list(crawler.walk())
            changed = cache.get_changed([fi.absolute for fi in all_files])
            changed_set = {str(p) for p in changed}
            files_to_scan = [fi for fi in all_files if str(fi.absolute) in changed_set]
            # ponytail: scan completo si cache vacío (primera ejecución).
            if not changed:
                files_to_scan = all_files
            cache.update([fi.absolute for fi in all_files])
            cache.save()
            report.scanned_files = len(all_files)
            with ThreadPoolExecutor() as pool:
                for findings in pool.map(_analyze, files_to_scan):
                    report.findings.extend(suppressions.filter(findings))
        else:
            # ponytail: pool por defecto de ThreadPoolExecutor (min(32, cpu+4)).
            with ThreadPoolExecutor() as pool:
                for findings in pool.map(_analyze, crawler.walk()):
                    report.findings.extend(suppressions.filter(findings))
            report.scanned_files = crawler.stats["visited"]

        report.elapsed_secs  = round(time.perf_counter() - start, 3)
        report.findings = _deduplicate(report.findings)

        return report


def _deduplicate(findings: list) -> list:
    """Agrupa por (archivo, línea, categoría) y conserva solo la mayor severidad."""
    # ponytail: dict como agrupador. O(n) con n = findings. Upgrade:
    # itertools.groupby si findings ya viene ordenado.
    best: dict[tuple, object] = {}
    for f in findings:
        key = (f.file.relative, f.line, f.category)
        prev = best.get(key)
        if prev is None or severity_index(f.severity) < severity_index(prev.severity):
            best[key] = f
    return list(best.values())
