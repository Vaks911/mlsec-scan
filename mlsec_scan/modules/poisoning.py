"""
Модуль Data Poisoning detection.

Проверяет train/good/ на отравленные примеры. Использует reference-модель:
прогоняет все картинки из train_data_path через чистый baseline и смотрит
anomaly score. Файлы с score выше порога — подозрительные.

Идея: модель училась только на нормах, поэтому её представление о норме
эталонное. Дефект, подложенный с меткой «норма», она честно видит как дефект.
"""

from pathlib import Path

import numpy as np
from PIL import Image

from mlsec_scan.core.registry import register
from mlsec_scan.modules.base import BaseModule, ModuleResult


@register("poisoning")
class PoisoningModule(BaseModule):
    """
    Проверка обучающей выборки на отравленные примеры.
    """

    name = "poisoning"
    description = "Детекция отравленных примеров в train/good/ (reference-model)"

    # Порог: score > max(normal) + MARGIN → подозрительный
    THRESHOLD_MARGIN = 0.15

    # Расширения картинок
    IMAGE_EXTENSIONS = (".png", ".jpg", ".jpeg")

    def run(self, model, dataset, config) -> ModuleResult:
        result = ModuleResult(module_name=self.name, status="unknown")

        # === 0. Проверяем, задан ли train_data_path ===
        if config.train_data_path is None:
            result.status = "unknown"
            result.add_finding(
                title="Не задан --train-data",
                severity="info",
                description="Для проверки на poisoning укажите путь к train/good/ "
                "через флаг --train-data.",
            )
            return result

        train_path = Path(config.train_data_path)
        if not train_path.exists():
            result.status = "unknown"
            result.add_finding(
                title="Папка train-data не найдена",
                severity="info",
                description=f"Путь не существует: {train_path}",
            )
            return result

        # === 1. Считаем порог из test/good ===
        print("    [1/3] Считаем порог из нормальных тестовых картинок...")
        labels = dataset.labels_array
        test_scores = model.predict(dataset.images)

        normal_scores = test_scores[labels == 0]
        if len(normal_scores) == 0:
            result.status = "unknown"
            result.add_finding(
                title="Нет норм в тестовом наборе",
                severity="info",
                description="Не из чего определить порог.",
            )
            return result

        max_normal = float(normal_scores.max())
        threshold = max_normal + self.THRESHOLD_MARGIN
        print(f"    max(normal) = {max_normal:.4f}")
        print(f"    Порог = {threshold:.4f}")

        # === 2. Собираем все картинки из train_data_path ===
        print(f"    [2/3] Сбор файлов из {train_path}...")
        train_files = []
        for f in sorted(train_path.iterdir()):
            if f.is_file() and f.suffix.lower() in self.IMAGE_EXTENSIONS:
                train_files.append(f)

        if not train_files:
            result.status = "unknown"
            result.add_finding(
                title="В train-data нет картинок",
                severity="info",
                description=f"Папка {train_path} пуста или содержит файлы других форматов.",
            )
            return result

        print(f"    Найдено файлов: {len(train_files)}")

        # === 3. Прогоняем каждую через модель ===
        print(f"    [3/3] Прогон через reference-модель...")
        suspicious = []
        all_scores = []

        for i, f in enumerate(train_files, 1):
            try:
                img = Image.open(f).convert("RGB")
                score = float(model.predict([img])[0])
                all_scores.append(score)
                if score > threshold:
                    suspicious.append({"file": f.name, "score": round(score, 4)})
                if i % 25 == 0 or i == len(train_files):
                    print(
                        f"      {i}/{len(train_files)}, "
                        f"подозрительных: {len(suspicious)}"
                    )
            except Exception as e:
                print(f"      [warn] {f.name}: {type(e).__name__}: {e}")
                continue

        # === Формируем отчёт ===
        n_total = len(train_files)
        n_suspicious = len(suspicious)
        ratio = n_suspicious / n_total if n_total else 0.0

        all_scores = np.array(all_scores) if all_scores else np.array([0.0])
        clean_scores = all_scores[all_scores <= threshold]
        susp_scores = all_scores[all_scores > threshold]

        result.raw_data["detection"] = {
            "train_path": str(train_path),
            "n_total": n_total,
            "n_suspicious": n_suspicious,
            "ratio": round(ratio, 4),
            "threshold": round(threshold, 4),
            "max_normal_test": round(max_normal, 4),
            "clean_mean": (
                round(float(clean_scores.mean()), 4) if len(clean_scores) else 0.0
            ),
            "suspicious_mean": (
                round(float(susp_scores.mean()), 4) if len(susp_scores) else 0.0
            ),
            "suspicious_top5": sorted(suspicious, key=lambda x: -x["score"])[:5],
        }

        # === Severity ===
        if ratio >= 0.10:
            # Больше 10% файлов подозрительны — серьёзная атака
            result.status = "vulnerable"
            result.add_finding(
                title=f"Обнаружено {n_suspicious} подозрительных файлов "
                f"({ratio:.0%} от train)",
                severity="high" if ratio >= 0.20 else "medium",
                description=(
                    f"Из {n_total} файлов в {train_path.name} "
                    f"{n_suspicious} имеют anomaly score выше порога "
                    f"({threshold:.4f}). Это похоже на Data Poisoning."
                ),
                metric_value=ratio,
            )
            result.add_recommendation(
                "Удалить подозрительные файлы и переобучить модель"
            )
            result.add_recommendation(
                "Проверить источник данных: откуда попали подозрительные примеры"
            )
        elif ratio > 0:
            result.status = "vulnerable"
            result.add_finding(
                title=f"Найдено {n_suspicious} подозрительных файлов "
                f"({ratio:.1%} от train)",
                severity="low",
                description=(
                    f"Возможно, это шум в данных, а не атака. "
                    f"Стоит проверить вручную."
                ),
                metric_value=ratio,
            )
        else:
            result.status = "resistant"
            result.add_finding(
                title="Отравленных примеров не обнаружено",
                severity="info",
                description=(
                    f"Все {n_total} файлов из train/good/ имеют score "
                    f"ниже порога {threshold:.4f}."
                ),
                metric_value=0.0,
            )

        return result
