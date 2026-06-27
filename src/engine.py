"""engine.py — Orquesta Crawler y analizadores."""

from __future__ import annotations
import time
from pathlib import Path
from .crawler import Crawler
from .domain import Report
from .ports import IAnalyzer
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
        start  = time.perf_counter()

        for file_info in crawler.walk():
            for analyzer in self._analyzers:
                report.findings.extend(analyzer.analyze(file_info))

        report.scanned_files = crawler.stats["visited"]
        report.elapsed_secs  = round(time.perf_counter() - start, 3)

        return report