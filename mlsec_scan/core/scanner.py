"""
Оркестратор сканера.
"""

import time
from dataclasses import dataclass, field
from datetime import datetime

from mlsec_scan.config import ScanConfig
from mlsec_scan.core.dataset import TestDataset
from mlsec_scan.core.model_adapter import ModelAdapter
from mlsec_scan.modules.base import BaseModule, ModuleResult


@dataclass
class ScanReport:
    """Итог всего сканирования."""

    model_name: str
    timestamp: str
    results: list[ModuleResult] = field(default_factory=list)
    total_duration_sec: float = 0.0

    def add_result(self, result: ModuleResult) -> None:
        self.results.append(result)

    @property
    def critical_count(self) -> int:
        return sum(
            1 for r in self.results if any(f.severity == "critical" for f in r.findings)
        )

    @property
    def high_count(self) -> int:
        return sum(
            1 for r in self.results if any(f.severity == "high" for f in r.findings)
        )

    def summary(self) -> dict:
        return {
            "model": self.model_name,
            "timestamp": self.timestamp,
            "modules_run": len(self.results),
            "critical": self.critical_count,
            "high": self.high_count,
            "duration_sec": round(self.total_duration_sec, 2),
        }


class Scanner:
    """
    Запускает модули проверки против модели.
    """

    def __init__(self, modules: list[BaseModule], config: ScanConfig):
        self.modules = modules
        self.config = config

    def scan(self, model: ModelAdapter, dataset: TestDataset) -> ScanReport:
        report = ScanReport(
            model_name=model.name,
            timestamp=datetime.now().isoformat(timespec="seconds"),
        )

        t_start = time.time()

        for module in self.modules:
            print(f"\n[*] Запуск модуля: {module.name}")
            t_module = time.time()
            try:
                result = module.run(model=model, dataset=dataset, config=self.config)
                result.duration_sec = round(time.time() - t_module, 2)
                report.add_result(result)
                print(f"    Статус: {result.status}  ({result.duration_sec}s)")
            except Exception as e:
                print(f"    [ERROR] Модуль {module.name} упал: {type(e).__name__}: {e}")
                err_result = ModuleResult(
                    module_name=module.name,
                    status="error",
                    duration_sec=round(time.time() - t_module, 2),
                )
                err_result.add_finding(
                    title=f"Модуль {module.name} не смог завершиться",
                    severity="info",
                    description=f"{type(e).__name__}: {e}",
                )
                report.add_result(err_result)

        report.total_duration_sec = round(time.time() - t_start, 2)
        return report
