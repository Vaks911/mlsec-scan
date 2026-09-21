"""
Универсальный интерфейс для модели-жертвы.

Модули сканера работают только через ModelAdapter. Чтобы добавить
новую модель — наследуйся от ModelAdapter и реализуй predict().
"""

from abc import ABC, abstractmethod
from typing import Any, Optional

import numpy as np


class ModelAdapter(ABC):
    """
    Абстрактная обёртка над ML-моделью.

    Все модули (adversarial, poisoning, extraction, backdoor) вызывают
    только методы этого класса. Это позволяет одному и тому же модулю
    работать и с PatchCore, и с ResNet, и с ONNX-моделью.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Название модели. Появляется в отчёте."""
        ...

    @property
    @abstractmethod
    def task_type(self) -> str:
        """
        Тип задачи. Одно из:
          - "anomaly"      — anomaly detection (PatchCore)
          - "classification" — классификация (ResNet)
          - "detection"    — object detection (YOLO)
        """
        ...

    @abstractmethod
    def predict(self, images: list) -> np.ndarray:
        """
        Инференс для батча картинок.

        Args:
            images: список PIL.Image (RGB)

        Returns:
            np.ndarray формы (N,) — score для каждой картинки.
            Для anomaly detection — anomaly_score.
            Для классификации — вероятность дефектного класса.
        """
        ...

    def predict_with_grad(self, image_tensor) -> Optional[Any]:
        """
        Опционально. Возвращает forward-pass с градиентами.

        Используется в gradient-based атаках (FGSM, PGD).
        Если модель не поддерживает — возвращает None.

        Args:
            image_tensor: torch.Tensor (1, C, H, W), requires_grad=True

        Returns:
            (score_tensor, features_tensor) или None
        """
        return None

    def get_features(self, images: list) -> Optional[np.ndarray]:
        """
        Опционально. Промежуточные фичи backbone.

        Используется в feature-space атаках.
        Если модель не поддерживает — возвращает None.
        """
        return None

    def predict_from_array(self, images_array: np.ndarray) -> np.ndarray:
        """
        Инференс на numpy-массиве картинок (N, H, W, 3), uint8.

        По умолчанию конвертирует в PIL и вызывает predict().
        Можно переопределить для скорости.
        """
        from PIL import Image

        pil_images = [Image.fromarray(img) for img in images_array]
        return self.predict(pil_images)
