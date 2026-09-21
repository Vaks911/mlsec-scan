"""
Базовый класс модуля проверки + структуры данных для результатов.

Каждый модуль (adversarial, poisoning, extraction, backdoor) — наследник
BaseModule. У него одна точка входа: run(). Внутри — своя логика проверки.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import numpy as np


@dataclass
class Finding:
    """
    Одна уязвимость или наблюдение, найденное модулем.

    Пример:
        Finding(
            title="FGSM ломает модель при eps=0.03",
            severity="high",
            description="F1 падает с 0.99 до 0.75 при добавлении шума.",
            metric_value=0.75,
        )
    """

    title: str
    severity: str  # "critical" | "high" | "medium" | "low" | "info"
    description: str
    metric_value: Any = None
    plot_path: Optional[Path] = None


@dataclass
class ModuleResult:
    """
    Полный результат одного модуля.
    """

    module_name: str
    status: str  # "vulnerable" | "resistant" | "unknown"
    findings: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)
    duration_sec: float = 0.0
    raw_data: dict = field(default_factory=dict)

    def add_finding(
        self,
        title: str,
        severity: str,
        description: str,
        metric_value: Any = None,
    ) -> None:
        """Добавляет новое наблюдение."""
        self.findings.append(
            Finding(
                title=title,
                severity=severity,
                description=description,
                metric_value=metric_value,
            )
        )

    def add_recommendation(self, text: str) -> None:
        """Добавляет рекомендацию."""
        self.recommendations.append(text)


class BaseModule(ABC):
    """
    Базовый класс всех модулей сканера.

    Наследник должен:
      - задать name и description
      - реализовать метод run()
    """

    name: str = "unnamed"
    description: str = ""

    @abstractmethod
    def run(self, model, dataset, config) -> ModuleResult:
        """
        Запускает проверку.

        Args:
            model: ModelAdapter — обёртка над моделью.
            dataset: DatasetAdapter или путь к данным.
            config: ScanConfig — настройки.

        Returns:
            ModuleResult с findings и recommendations.
        """
        ...
