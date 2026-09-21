"""
Загрузчик тестовых данных с метками.
"""

from pathlib import Path
from typing import Iterator, Optional

import numpy as np
from PIL import Image

DEFAULT_LABEL_MAP = {
    "good": 0,
    "normal": 0,
    "broken_large": 1,
    "broken_small": 1,
    "contamination": 1,
    "defect": 1,
    "anomaly": 1,
}


class TestDataset:
    """
    Загружает картинки из папки и присваивает им метки.
    """

    def __init__(
        self,
        root: Path,
        label_map: Optional[dict] = None,
        extensions: tuple = (".png", ".jpg", ".jpeg"),
    ):
        self.root = Path(root).resolve()
        if not self.root.exists():
            raise FileNotFoundError(f"Папка не найдена: {self.root}")

        self.label_map = label_map or DEFAULT_LABEL_MAP
        self.extensions = tuple(e.lower() for e in extensions)

        self.image_paths: list[Path] = []
        self.labels: list[int] = []
        self.class_names: list[str] = []

        self._scan()

        if len(self.image_paths) == 0:
            raise ValueError(f"Не найдено ни одной картинки в {self.root}")

    def _scan(self) -> None:
        for class_dir in sorted(self.root.iterdir()):
            if not class_dir.is_dir():
                continue
            class_name = class_dir.name.lower()
            if class_name not in self.label_map:
                continue
            label = self.label_map[class_name]
            for img_path in sorted(class_dir.iterdir()):
                if img_path.suffix.lower() in self.extensions:
                    self.image_paths.append(img_path)
                    self.labels.append(label)
                    self.class_names.append(class_name)

    def __len__(self) -> int:
        return len(self.image_paths)

    @property
    def images(self) -> list[Image.Image]:
        return [Image.open(p).convert("RGB") for p in self.image_paths]

    @property
    def labels_array(self) -> np.ndarray:
        return np.array(self.labels, dtype=np.int32)

    def iter_batches(self, batch_size: int = 8) -> Iterator[tuple]:
        n = len(self)
        for start in range(0, n, batch_size):
            end = min(start + batch_size, n)
            batch_paths = self.image_paths[start:end]
            batch_images = [Image.open(p).convert("RGB") for p in batch_paths]
            batch_labels = np.array(self.labels[start:end], dtype=np.int32)
            batch_names = [p.name for p in batch_paths]
            yield batch_images, batch_labels, batch_names

    def summary(self) -> dict:
        labels = np.array(self.labels)
        return {
            "total": len(self),
            "normal": int((labels == 0).sum()),
            "defect": int((labels == 1).sum()),
            "classes": sorted(set(self.class_names)),
        }
