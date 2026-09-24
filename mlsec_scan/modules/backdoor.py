"""
Модуль Backdoor Detection.

Проверяет ML-модель на наличие backdoor через анализ разделимости классов.

Идея: backdoored-модель хуже различает норму и дефект, потому что при
обучении видела дефекты (с триггером) как норму. Memory bank размывается,
и anomaly score дефектов и норм сближаются.

Метрика: gap = mean_score(defect) - mean_score(normal).
Для чистой модели gap большой (> 0.35), для backdoored — маленький (< 0.25).
"""

import numpy as np

from mlsec_scan.core.registry import register
from mlsec_scan.modules.base import BaseModule, ModuleResult


@register("backdoor")
class BackdoorModule(BaseModule):
    """
    Проверка модели на backdoor через разделимость нормы и дефектов.

    Считает mean anomaly score для норм и для дефектов. Если разрыв мал —
    модель могла быть обучена на данных с backdoor-триггером.
    """

    name = "backdoor"
    description = "Backdoor detection via class separability analysis"

    # Пороги для severity
    HEALTHY_GAP = 0.35
    SUSPICIOUS_GAP = 0.25
    INFECTED_GAP = 0.15

    def run(self, model, dataset, config) -> ModuleResult:
        result = ModuleResult(module_name=self.name, status="unknown")

        # === 1. Собираем нормы и дефекты ===
        print("    [1/4] Собираем нормы и дефекты из test set...")
        images = dataset.images
        labels = dataset.labels_array

        normal_indices = np.where(labels == 0)[0]
        defect_indices = np.where(labels == 1)[0]

        if len(normal_indices) < 5 or len(defect_indices) < 10:
            result.status = "unknown"
            result.add_finding(
                title="Недостаточно данных для backdoor-проверки",
                severity="info",
                description=(
                    f"Нужно минимум 5 норм и 10 дефектов. "
                    f"Есть: {len(normal_indices)} норм, {len(defect_indices)} дефектов."
                ),
            )
            return result

        print(f"    Норм: {len(normal_indices)}, дефектов: {len(defect_indices)}")

        # === 2. Прогон нормы ===
        print("    [2/4] Прогон норм...")
        normal_images = [images[i] for i in normal_indices]
        normal_scores = model.predict(normal_images)

        print(f"    mean score (нормы):  {normal_scores.mean():.4f}")
        print(f"    max score (нормы):   {normal_scores.max():.4f}")
        print(f"    std score (нормы):   {normal_scores.std():.4f}")

        # === 3. Прогон дефектов ===
        print("    [3/4] Прогон дефектов...")
        defect_images = [images[i] for i in defect_indices]
        defect_scores = model.predict(defect_images)

        print(f"    mean score (дефекты): {defect_scores.mean():.4f}")
        print(f"    min score (дефекты):  {defect_scores.min():.4f}")
        print(f"    std score (дефекты):  {defect_scores.std():.4f}")

        # === 4. Считаем gap ===
        print("    [4/4] Считаем разделимость...")
        gap = float(defect_scores.mean() - normal_scores.mean())

        # Дополнительная метрика: пересечение распределений
        # Если max(normal) > min(defect) — распределения пересекаются
        overlap = float(normal_scores.max() - defect_scores.min())
        overlap_pct = max(0.0, overlap)

        # Простой адаптивный порог: max(normal) + (mean(defect) - max(normal)) / 2
        if defect_scores.mean() > normal_scores.max():
            threshold = float(
                normal_scores.max() + (defect_scores.mean() - normal_scores.max()) / 2
            )
        else:
            threshold = float(normal_scores.max() + 0.02)

        # Recall при этом пороге
        recall_at_threshold = float((defect_scores > threshold).mean())

        print(f"    Gap (defect - normal): {gap:.4f}")
        print(f"    Порог:                 {threshold:.4f}")
        print(f"    Recall при пороге:     {recall_at_threshold:.2%}")

        # === Записываем данные ===
        result.raw_data["backdoor"] = {
            "n_normal": int(len(normal_indices)),
            "n_defect": int(len(defect_indices)),
            "mean_score_normal": round(float(normal_scores.mean()), 4),
            "mean_score_defect": round(float(defect_scores.mean()), 4),
            "max_score_normal": round(float(normal_scores.max()), 4),
            "min_score_defect": round(float(defect_scores.min()), 4),
            "gap": round(gap, 4),
            "overlap": round(overlap_pct, 4),
            "threshold": round(threshold, 4),
            "recall_at_threshold": round(recall_at_threshold, 4),
        }

        # === Severity ===
        if gap < self.INFECTED_GAP:
            result.status = "vulnerable"
            result.add_finding(
                title=f"Модель заражена backdoor (разрыв классов {gap:.3f})",
                severity="high",
                description=(
                    f"Anomaly score нормы (mean {normal_scores.mean():.3f}) и дефектов "
                    f"(mean {defect_scores.mean():.3f}) почти не различаются — "
                    f"разрыв всего {gap:.3f}. Это типичный признак backdoored-модели: "
                    f"при обучении она видела дефекты (с триггером) как норму, "
                    f"и memory bank размылся."
                ),
                metric_value=gap,
            )
            result.add_recommendation(
                "Проверить источник обучающих данных на подозрительные примеры"
            )
            result.add_recommendation("Переобучить модель на очищенном датасете")
            result.add_recommendation(
                "Применить фильтрацию входных данных (input sanitization)"
            )
        elif gap < self.SUSPICIOUS_GAP:
            result.status = "vulnerable"
            result.add_finding(
                title=f"Разделимость классов ослаблена (разрыв {gap:.3f})",
                severity="medium",
                description=(
                    f"Разрыв между mean score нормы ({normal_scores.mean():.3f}) "
                    f"и дефектов ({defect_scores.mean():.3f}) — {gap:.3f}. "
                    f"Это ниже типичного для чистой модели (0.35+). "
                    f"Возможен backdoor или общая деградация."
                ),
                metric_value=gap,
            )
            result.add_recommendation("Проверить качество обучающих данных")
        elif gap < self.HEALTHY_GAP:
            result.status = "vulnerable"
            result.add_finding(
                title=f"Умеренная разделимость (разрыв {gap:.3f})",
                severity="low",
                description=(
                    f"Разрыв mean score между нормой и дефектами — {gap:.3f}. "
                    f"Ниже идеала (0.35+), но не критично. Рекомендуется "
                    f"проверить обучающий датасет вручную."
                ),
                metric_value=gap,
            )
        else:
            result.status = "resistant"
            result.add_finding(
                title=f"Модель устойчива к backdoor (разрыв {gap:.3f})",
                severity="info",
                description=(
                    f"Anomaly score нормы (mean {normal_scores.mean():.3f}) и "
                    f"дефектов (mean {defect_scores.mean():.3f}) хорошо разделены — "
                    f"разрыв {gap:.3f}. Это нормальное поведение чистой модели."
                ),
                metric_value=gap,
            )

        return result
