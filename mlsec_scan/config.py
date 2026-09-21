"""
Конфигурация mlsec-scan.

Все настройки собираются в один dataclass ScanConfig.
Его можно передать в Scanner.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ScanConfig:
    """
    Настройки сканирования ML-модели.

    Пример:
        config = ScanConfig(
            model_path=Path("model.ckpt"),
            model_type="patchcore",
            data_path=Path("test_data"),
            enabled_modules=["adversarial", "poisoning"],
        )
    """

    # --- Модель ---
    model_path: Optional[Path] = None
    model_type: str = "auto"  # "auto" | "patchcore" | "resnet" | "onnx"

    # --- Данные ---
    data_path: Optional[Path] = None
    train_data_path: Optional[Path] = None  # для проверки на poisoning
    image_size: tuple = (256, 256)

    # --- Модули (какие запускать) ---
    enabled_modules: list = field(default_factory=lambda: ["adversarial"])

    # --- Adversarial ---
    adversarial_eps: float = 0.05
    adversarial_steps: int = 20  # скольк шагов

    # --- Data Poisoning ---
    poisoning_rates: list = field(default_factory=lambda: [0.01, 0.05, 0.10])

    # --- Model Extraction ---
    extraction_n_queries: int = 1000

    # --- Backdoor Detection ---
    backdoor_patch_size: int = 16

    # --- Отчёт ---
    output_path: Optional[Path] = None
    output_format: str = "console"  # "console" | "json" | "html"

    # --- Прочее ---
    verbose: bool = False
    seed: int = 42

    def validate(self) -> None:
        """Проверяет корректность конфигурации."""
        if self.model_path is None:
            raise ValueError("model_path не задан")
        if not Path(self.model_path).exists():
            raise ValueError(f"Файл модели не найден: {self.model_path}")

        if self.data_path is None:
            raise ValueError("data_path не задан")
        if not Path(self.data_path).exists():
            raise ValueError(f"Папка с данными не найдена: {self.data_path}")

        valid_formats = ("console", "json", "html")
        if self.output_format not in valid_formats:
            raise ValueError(
                f"output_format должен быть одним из {valid_formats}, "
                f"получено: {self.output_format}"
            )

        if self.model_type not in ("auto", "patchcore", "resnet", "onnx"):
            raise ValueError(f"Неизвестный model_type: {self.model_type}")
