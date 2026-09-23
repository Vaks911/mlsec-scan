"""
Модуль Model Extraction.

Проверяет, можно ли скопировать поведение модели через API:
атакующий делает N запросов к модели, обучает суррогатную сеть
на полученных ответах, и проверяет, воспроизводит ли она поведение
оригинала на новых данных.
"""

import time
from typing import Optional

import numpy as np
import torch
import torch.nn as nn
from PIL import Image

from mlsec_scan.core.registry import register
from mlsec_scan.modules.base import BaseModule, ModuleResult

IMAGENET_MEAN = np.array([0.485, 0.456, 0.406], dtype=np.float32)
IMAGENET_STD = np.array([0.229, 0.224, 0.225], dtype=np.float32)


class SurrogateNet(nn.Module):
    """
    Маленькая свёрточная сеть для имитации поведения жертвы.

    Вход: RGB-картинка, приведённая к размеру 64×64, нормализованная.
    Выход: скаляр (anomaly score).
    """

    def __init__(self):
        super().__init__()
        self.features = nn.Sequential(
            nn.Conv2d(3, 16, kernel_size=3, padding=1),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(2),  # 64 → 32
            nn.Conv2d(16, 32, kernel_size=3, padding=1),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(2),  # 32 → 16
            nn.Conv2d(32, 64, kernel_size=3, padding=1),
            nn.ReLU(inplace=True),
            nn.AdaptiveAvgPool2d(1),  # 16 → 1
        )
        self.head = nn.Sequential(
            nn.Flatten(),
            nn.Linear(64, 32),
            nn.ReLU(inplace=True),
            nn.Linear(32, 1),
            nn.Sigmoid(),  # score ∈ [0, 1]
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.head(self.features(x)).squeeze(-1)


@register("extraction")
class ExtractionModule(BaseModule):
    """
    Проверка извлекаемости модели через API.

    Делает N запросов к жертве, обучает суррогатную CNN на её ответах,
    затем проверяет agreement между суррогатом и жертвой на hold-out наборе.
    """

    name = "extraction"
    description = "Model extraction via query API (surrogate training)"

    SURROGATE_IMAGE_SIZE = 64
    SURROGATE_LR = 1e-3
    SURROGATE_BATCH = 16

    # Пороги для severity
    HIGH_MSE = 0.05
    HIGH_ACC = 0.90
    MEDIUM_MSE = 0.10
    MEDIUM_ACC = 0.80

    def run(self, model, dataset, config) -> ModuleResult:
        result = ModuleResult(module_name=self.name, status="unknown")

        # === 1. Собираем пул картинок ===
        print("    [1/4] Сбор картинок для запросов к API...")
        images = dataset.images
        labels = dataset.labels_array
        n_total = len(images)

        # Делим датасет: до 70% на запросы, остальное на hold-out
        max_queries = max(50, int(n_total * 0.7))
        n_queries = min(config.extraction_n_queries, max_queries)
        n_test = min(config.extraction_test_size, n_total - n_queries)

        if n_queries < 50 or n_test < 10:
            result.status = "unknown"
            result.add_finding(
                title="Недостаточно данных для extraction-проверки",
                severity="info",
                description=(
                    f"Нужно минимум 60 картинок (50 для запросов + 10 для теста). "
                    f"В датасете {n_total}."
                ),
            )
            return result

        # Детерминированно перемешиваем и делим
        rng = np.random.default_rng(config.seed)
        indices = rng.permutation(n_total)
        query_idx = indices[:n_queries]
        test_idx = indices[n_queries : n_queries + n_test]

        print(f"    Запросов к API: {n_queries}")
        print(f"    Hold-out для теста: {n_test}")

        # === 2. Делаем запросы к жертве ===
        print("    [2/4] Запросы к жертве (это медленно)...")
        t0 = time.time()

        query_images = [images[i] for i in query_idx]
        query_scores = model.predict(query_images)  # (N,)
        query_scores = np.clip(query_scores, 0.0, 1.0)

        test_images = [images[i] for i in test_idx]
        test_scores = model.predict(test_images)
        test_scores = np.clip(test_scores, 0.0, 1.0)

        print(f"    Готово за {time.time() - t0:.1f}s")

        # === 3. Обучаем суррогат ===
        print(
            f"    [3/4] Обучение суррогата " f"({config.extraction_max_epochs} эпох)..."
        )

        surrogate = SurrogateNet()
        optimizer = torch.optim.Adam(surrogate.parameters(), lr=self.SURROGATE_LR)
        criterion = nn.MSELoss()

        # Готовим тензоры
        X_train = self._images_to_tensor(query_images)
        y_train = torch.tensor(query_scores, dtype=torch.float32)
        X_test = self._images_to_tensor(test_images)
        y_test = torch.tensor(test_scores, dtype=torch.float32)

        n_train = X_train.shape[0]
        surrogate.train()
        for epoch in range(config.extraction_max_epochs):
            perm = torch.randperm(n_train)
            total_loss = 0.0
            for start in range(0, n_train, self.SURROGATE_BATCH):
                idx = perm[start : start + self.SURROGATE_BATCH]
                xb = X_train[idx]
                yb = y_train[idx]
                optimizer.zero_grad()
                pred = surrogate(xb)
                loss = criterion(pred, yb)
                loss.backward()
                optimizer.step()
                total_loss += loss.item() * len(idx)

            avg_loss = total_loss / n_train
            if (epoch + 1) % 10 == 0 or epoch == 0:
                print(
                    f"      Эпоха {epoch + 1:>2}/{config.extraction_max_epochs}, "
                    f"loss={avg_loss:.5f}"
                )

        # === 4. Проверяем agreement ===
        print("    [4/4] Проверка agreement на hold-out...")
        surrogate.eval()
        with torch.no_grad():
            pred_test = surrogate(X_test).numpy()
        pred_test = np.clip(pred_test, 0.0, 1.0)

        # Метрики
        mse = float(np.mean((pred_test - test_scores) ** 2))
        mae = float(np.mean(np.abs(pred_test - test_scores)))

        # Accuracy по бинарной классификации (DEFECT/NORMAL)
        threshold = float((test_scores.min() + test_scores.max()) / 2)
        true_bin = (test_scores >= threshold).astype(int)
        pred_bin = (pred_test >= threshold).astype(int)
        accuracy = float((true_bin == pred_bin).mean())

        # Корреляция Пирсона
        if len(test_scores) > 1 and test_scores.std() > 0 and pred_test.std() > 0:
            correlation = float(np.corrcoef(test_scores, pred_test)[0, 1])
        else:
            correlation = 0.0

        print(f"    MSE:         {mse:.5f}")
        print(f"    MAE:         {mae:.5f}")
        print(f"    Accuracy:    {accuracy:.2%}")
        print(f"    Correlation: {correlation:.3f}")

        # === Записываем данные ===
        result.raw_data["extraction"] = {
            "n_queries": int(n_queries),
            "n_test": int(n_test),
            "epochs": int(config.extraction_max_epochs),
            "mse": round(mse, 5),
            "mae": round(mae, 5),
            "accuracy": round(accuracy, 4),
            "correlation": round(correlation, 4),
            "test_scores_min": round(float(test_scores.min()), 4),
            "test_scores_max": round(float(test_scores.max()), 4),
        }

        # === Severity ===
        if mse <= self.HIGH_MSE and accuracy >= self.HIGH_ACC:
            result.status = "vulnerable"
            result.add_finding(
                title=(
                    f"Модель высоко извлекаема "
                    f"(accuracy {accuracy:.0%}, MSE {mse:.4f})"
                ),
                severity="high",
                description=(
                    f"Суррогат обучен на {n_queries} запросах. "
                    f"На {n_test} hold-out примерах он воспроизводит "
                    f"поведение жертвы с accuracy {accuracy:.1%} и MSE {mse:.4f}. "
                    f"Это значит: конкурент может скопировать функциональность "
                    f"модели без доступа к весам и данным."
                ),
                metric_value=accuracy,
            )
            result.add_recommendation(
                "Ограничить частоту запросов к API (rate limiting)"
            )
            result.add_recommendation(
                "Добавить шум к возвращаемым score (defensive distillation)"
            )
            result.add_recommendation(
                "Убрать публичный API или добавить аутентификацию"
            )
        elif mse <= self.MEDIUM_MSE and accuracy >= self.MEDIUM_ACC:
            result.status = "vulnerable"
            result.add_finding(
                title=(
                    f"Модель извлекаема частично "
                    f"(accuracy {accuracy:.0%}, MSE {mse:.4f})"
                ),
                severity="medium",
                description=(
                    f"Суррогат воспроизводит поведение жертвы с accuracy "
                    f"{accuracy:.1%} при {n_queries} запросах. "
                    f"Увеличив число запросов, атакующий может добиться лучшего копирования."
                ),
                metric_value=accuracy,
            )
            result.add_recommendation("Рассмотреть rate limiting на API")
        else:
            result.status = "resistant"
            result.add_finding(
                title=(
                    f"Модель слабо извлекаема "
                    f"(accuracy {accuracy:.0%}, MSE {mse:.4f})"
                ),
                severity="info",
                description=(
                    f"На {n_queries} запросах суррогат достиг accuracy {accuracy:.1%}. "
                    f"Поведение модели воспроизводится недостаточно хорошо "
                    f"для практической кражи."
                ),
                metric_value=accuracy,
            )

        return result

    # === Вспомогательные методы ===

    def _image_to_tensor(self, image: Image.Image) -> torch.Tensor:
        """PIL.Image → torch.Tensor (3, 64, 64) в нормализованном виде."""
        img = image.convert("RGB").resize(
            (self.SURROGATE_IMAGE_SIZE, self.SURROGATE_IMAGE_SIZE)
        )
        arr = np.asarray(img, dtype=np.float32) / 255.0
        arr = (arr - IMAGENET_MEAN) / IMAGENET_STD
        return torch.from_numpy(arr).permute(2, 0, 1)

    def _images_to_tensor(self, images: list) -> torch.Tensor:
        """Список PIL.Image → батч-тензор (N, 3, 64, 64)."""
        return torch.stack([self._image_to_tensor(img) for img in images])
