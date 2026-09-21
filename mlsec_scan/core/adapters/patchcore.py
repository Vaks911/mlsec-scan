"""
Адаптер для PatchCore (Anomalib).

Оборачивает класс DefectDetector из проекта-жертвы и приводит его
к общему интерфейсу ModelAdapter.
"""

from pathlib import Path
from typing import Optional

import numpy as np

from mlsec_scan.core.model_adapter import ModelAdapter


class PatchCoreAdapter(ModelAdapter):
    """
    Обёртка над PatchCore + DefectDetector.

    Использование:
        adapter = PatchCoreAdapter(
            model_path="model.ckpt",
            detector_path="C:/path/to/defect-detection",
        )
        scores = adapter.predict([img1, img2, img3])
    """

    def __init__(
        self,
        model_path: str,
        detector_path: str,
        device: str = "cpu",
    ):
        """
        Args:
            model_path: путь к .ckpt чекпоинту PatchCore.
            detector_path: путь к папке проекта defect-detection
                           (там лежит detector.py).
            device: "cpu" или "cuda".
        """
        import sys

        detector_path = Path(detector_path).resolve()
        if not detector_path.exists():
            raise FileNotFoundError(
                f"Папка defect-detection не найдена: {detector_path}"
            )
        sys.path.insert(0, str(detector_path))

        import torch
        _original_load = torch.load
        def _patched_load(*args, **kwargs):
            kwargs.setdefault("weights_only", False)
            return _original_load(*args, **kwargs)
        torch.load = _patched_load

        from detector import DefectDetector  # noqa: E402

        self._model_path = Path(model_path)
        if not self._model_path.exists():
            raise FileNotFoundError(f"Чекпоинт не найден: {self._model_path}")

        self._device = device
        self._detector = DefectDetector(
            model_path=str(self._model_path),
            device=device,
        )

    @property
    def name(self) -> str:
        return "PatchCore (WideResNet50)"

    @property
    def task_type(self) -> str:
        return "anomaly"

    def predict(self, images: list) -> np.ndarray:
        """
        Прогоняет картинки через PatchCore.

        Args:
            images: список PIL.Image или список путей к файлам.

        Returns:
            np.ndarray формы (N,) — anomaly_score для каждой картинки.
        """
        scores = []
        for img in images:
            if isinstance(img, (str, Path)):
                img_path = str(img)
            else:
                import tempfile
                with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
                    img.save(f.name, format="PNG")
                    img_path = f.name

            result = self._detector.predict(image_path=img_path)
            scores.append(float(result["anomaly_score"]))

        return np.array(scores, dtype=np.float32)

    def predict_with_grad(self, image_tensor) -> Optional[tuple]:
        """
        PatchCore поддерживает градиенты через FeatureListNet.
        Возвращает (score_tensor, features_tensor).
        """
        import torch

        inner = self._detector.model.model  # PatchcoreModel
        timm_model = inner.feature_extractor.feature_extractor

        if image_tensor.requires_grad is False:
            image_tensor = image_tensor.detach().requires_grad_(True)

        feats = timm_model(image_tensor)
        v2 = feats[0].mean(dim=(2, 3))
        v3 = feats[1].mean(dim=(2, 3))
        features = torch.cat([v2, v3], dim=1)

        return None, features

    def get_features(self, images: list) -> Optional[np.ndarray]:
        """Возвращает фичи layer2+layer3 для батча картинок."""
        import torch
        from PIL import Image

        inner = self._detector.model.model
        timm_model = inner.feature_extractor.feature_extractor

        IMAGENET_MEAN = np.array([0.485, 0.456, 0.406], dtype=np.float32)
        IMAGENET_STD = np.array([0.229, 0.224, 0.225], dtype=np.float32)

        all_features = []
        with torch.no_grad():
            for img in images:
                if not isinstance(img, Image.Image):
                    img = Image.open(img).convert("RGB")
                img = img.resize((256, 256))
                arr = np.asarray(img, dtype=np.float32) / 255.0
                arr = (arr - IMAGENET_MEAN) / IMAGENET_STD
                x = torch.from_numpy(arr).permute(2, 0, 1).unsqueeze(0)

                feats = timm_model(x)
                v2 = feats[0].mean(dim=(2, 3)).squeeze(0)
                v3 = feats[1].mean(dim=(2, 3)).squeeze(0)
                v = torch.cat([v2, v3]).numpy()
                all_features.append(v)

        return np.stack(all_features, axis=0)