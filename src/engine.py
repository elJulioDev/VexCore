"""engine.py — Orquesta Crawler y analizadores."""

from __future__ import annotations
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from .crawler import Crawler
from .domain import Report
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

        # ponytail: pool por defecto de ThreadPoolExecutor (min(32, cpu+4)).
        # Los analyzers son stateless por archivo; safe para threads.
        with ThreadPoolExecutor() as pool:
            for findings in pool.map(_analyze, crawler.walk()):
                report.findings.extend(suppressions.filter(findings))

        report.scanned_files = crawler.stats["visited"]
        report.elapsed_secs  = round(time.perf_counter() - start, 3)

        return report
