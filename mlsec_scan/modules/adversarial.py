"""
Модуль Adversarial Robustness.

Проверяет устойчивость модели к gradient-based атакам (FGSM/PGD).
Атака идёт через feature-space: цель — сдвинуть фичи дефекта к среднему нормы.
"""

import time
from pathlib import Path

import numpy as np
import torch

from mlsec_scan.core.registry import register
from mlsec_scan.modules.base import BaseModule, ModuleResult
from mlsec_scan.utils.metrics import f1_score, precision, recall, scores_to_labels

IMAGENET_MEAN = np.array([0.485, 0.456, 0.406], dtype=np.float32)
IMAGENET_STD = np.array([0.229, 0.224, 0.225], dtype=np.float32)


@register("adversarial")
class AdversarialModule(BaseModule):
    """
    Проверка устойчивости к gradient-based adversarial атакам.

    Feature-space PGD: сдвигаем фичи дефекта к среднему нормы.
    Атакуем только «пограничные» дефекты — те, что модель ловит неуверенно.
    """

    name = "adversarial"
    description = "FGSM/PGD атаки на входные изображения (feature-space)"

    # Порог для классификации: score > max(normal) + MARGIN → DEFECT
    THRESHOLD_MARGIN = 0.15
    # Ширина «пограничной зоны» вокруг порога
    BORDERLINE_WIDTH = 0.10

    def run(self, model, dataset, config) -> ModuleResult:
        result = ModuleResult(module_name=self.name, status="unknown")

        # === 1. Baseline ===
        print("    [1/5] Baseline: прогон всех картинок...")
        images = dataset.images
        labels = dataset.labels_array

        baseline_scores = model.predict(images)

        normal_scores = baseline_scores[labels == 0]
        defect_scores = baseline_scores[labels == 1]

        if len(normal_scores) == 0 or len(defect_scores) == 0:
            result.status = "unknown"
            result.add_finding(
                title="Недостаточно данных для анализа",
                severity="info",
                description="В датасете нет одного из классов (норма/дефект).",
            )
            return result

        # Порог: score выше max(нормы) + запас → DEFECT
        threshold = float(normal_scores.max() + self.THRESHOLD_MARGIN)

        baseline_labels = scores_to_labels(baseline_scores, threshold)
        baseline_f1 = f1_score(labels, baseline_labels)
        baseline_recall = recall(labels, baseline_labels)
        baseline_precision = precision(labels, baseline_labels)

        print(f"    Baseline F1: {baseline_f1:.4f}, recall: {baseline_recall:.4f}")
        print(f"    max(normal)={normal_scores.max():.4f}")
        print(f"    Порог: {threshold:.4f}")

        result.raw_data["baseline"] = {
            "f1": round(baseline_f1, 4),
            "recall": round(baseline_recall, 4),
            "precision": round(baseline_precision, 4),
            "threshold": round(threshold, 4),
        }

        # === 2. Среднее фич нормы ===
        print("    [2/5] Среднее фич нормы...")
        normal_indices = np.where(labels == 0)[0]
        normal_feats = []
        for idx in normal_indices:
            try:
                sample_tensor = self._image_to_tensor(images[idx], config.image_size)
                _, feats = model.predict_with_grad(sample_tensor)
                if feats is not None:
                    normal_feats.append(feats.detach().squeeze(0).numpy())
            except Exception:
                continue

        if not normal_feats:
            result.status = "unknown"
            result.add_finding(
                title="Не удалось получить фичи нормы",
                severity="info",
                description="predict_with_grad() вернул None для нормальных картинок.",
            )
            return result

        mean_normal_features = torch.tensor(
            np.mean(normal_feats, axis=0), dtype=torch.float32
        )
        print(f"    mean_normal shape: {tuple(mean_normal_features.shape)}")

        # === 3. Отбор кандидатов ===
        print("    [3/5] Отбор кандидатов на атаку...")
        borderline_threshold = float(threshold + self.BORDERLINE_WIDTH)
        defect_indices = np.where(
            (labels == 1) & (baseline_scores < borderline_threshold)
        )[0]
        n_defects_total = int((labels == 1).sum())
        print(f"    Кандидатов: {len(defect_indices)} из {n_defects_total}")
        print(f"    Порог отбора: score < {borderline_threshold:.4f}")

        if len(defect_indices) == 0:
            result.status = "resistant"
            result.add_finding(
                title="Нет пограничных дефектов для атаки",
                severity="info",
                description=f"Все {n_defects_total} дефектов имеют score "
                f"> {borderline_threshold:.4f}.",
            )
            return result

        # === 4. PGD-атака ===
        print(
            f"    [4/5] PGD-атака (eps={config.adversarial_eps}, "
            f"steps={config.adversarial_steps})..."
        )
        n_attacked = 0
        n_flipped = 0
        adv_scores = baseline_scores.copy()

        for i, idx in enumerate(defect_indices, 1):
            img = images[idx]
            try:
                adv_img = self._pgd_attack(
                    model=model,
                    image=img,
                    eps=config.adversarial_eps,
                    n_steps=config.adversarial_steps,
                    image_size=config.image_size,
                    mean_normal=mean_normal_features,
                )
                adv_score = float(model.predict([adv_img])[0])
                adv_scores[idx] = adv_score
                n_attacked += 1

                if adv_score < threshold:
                    n_flipped += 1

                print(
                    f"      [{i}/{len(defect_indices)}] "
                    f"orig={baseline_scores[idx]:.4f} → adv={adv_score:.4f}  "
                    f"flip={n_flipped}"
                )

            except Exception as e:
                print(f"      [warn] idx={idx}: {type(e).__name__}: {e}")
                continue

        # === 5. Метрики после атаки ===
        print("    [5/5] Подсчёт метрик после атаки...")
        adv_labels = scores_to_labels(adv_scores, threshold)
        adv_f1 = f1_score(labels, adv_labels)
        adv_recall = recall(labels, adv_labels)
        adv_precision = precision(labels, adv_labels)

        f1_drop = baseline_f1 - adv_f1
        flip_rate = n_flipped / n_attacked if n_attacked > 0 else 0.0

        result.raw_data["attack"] = {
            "eps": config.adversarial_eps,
            "steps": config.adversarial_steps,
            "n_candidates": int(len(defect_indices)),
            "n_attacked": n_attacked,
            "n_flipped": n_flipped,
            "flip_rate": round(flip_rate, 4),
            "f1_after": round(adv_f1, 4),
            "f1_drop": round(f1_drop, 4),
            "recall_after": round(adv_recall, 4),
        }

        # === Оценка серьёзности ===
        if flip_rate >= 0.3 or f1_drop >= 0.05:
            result.status = "vulnerable"
            severity = "high" if flip_rate >= 0.5 else "medium"
            result.add_finding(
                title=f"Модель уязвима к adversarial атаке (flip rate {flip_rate:.0%})",
                severity=severity,
                description=(
                    f"При eps={config.adversarial_eps} атака переключила "
                    f"{n_flipped} из {n_attacked} пограничных дефектов в NORMAL. "
                    f"F1 упал с {baseline_f1:.4f} до {adv_f1:.4f}."
                ),
                metric_value=flip_rate,
            )
            result.add_recommendation("Применить JPEG-препроцессинг перед инференсом")
            result.add_recommendation(
                "Рассмотреть adversarial training на граничных примерах"
            )
        elif flip_rate > 0:
            result.status = "vulnerable"
            result.add_finding(
                title=f"Слабая уязвимость (flip rate {flip_rate:.0%})",
                severity="low",
                description=(
                    f"Атака переключила {n_flipped} из {n_attacked} пограничных дефектов. "
                    f"F1 упал с {baseline_f1:.4f} до {adv_f1:.4f}."
                ),
                metric_value=flip_rate,
            )
        else:
            result.status = "resistant"
            result.add_finding(
                title="Модель устойчива к adversarial атаке",
                severity="info",
                description=(
                    f"При eps={config.adversarial_eps} ни один из {n_attacked} "
                    f"пограничных дефектов не был переключён в NORMAL."
                ),
                metric_value=0.0,
            )

        return result

    # === Вспомогательные методы ===

    def _image_to_tensor(self, image, image_size):
        """PIL.Image → torch.Tensor (1, 3, H, W) в нормализованном виде."""
        img = image.convert("RGB").resize(image_size)
        arr = np.asarray(img, dtype=np.float32) / 255.0
        arr = (arr - IMAGENET_MEAN) / IMAGENET_STD
        return torch.from_numpy(arr).permute(2, 0, 1).unsqueeze(0)

    def _tensor_to_image(self, tensor):
        """torch.Tensor (1, 3, H, W) → PIL.Image."""
        from PIL import Image

        arr = tensor.squeeze(0).permute(1, 2, 0).cpu().numpy()
        arr = arr * IMAGENET_STD + IMAGENET_MEAN
        arr = np.clip(arr, 0.0, 1.0)
        return Image.fromarray((arr * 255).astype(np.uint8))

    def _pgd_attack(self, model, image, eps, n_steps, image_size, mean_normal):
        """
        Feature-space PGD.

        Сдвигаем пиксели так, чтобы фичи дефекта стали ближе к среднему нормы.
        """
        x_orig = self._image_to_tensor(image, image_size)
        x_min = torch.tensor((0.0 - IMAGENET_MEAN) / IMAGENET_STD).view(1, 3, 1, 1)
        x_max = torch.tensor((1.0 - IMAGENET_MEAN) / IMAGENET_STD).view(1, 3, 1, 1)

        alpha = eps / n_steps * 1.5
        x_adv = x_orig.clone().detach().requires_grad_(True)

        for _ in range(n_steps):
            if x_adv.grad is not None:
                x_adv.grad.zero_()
            _, features = model.predict_with_grad(x_adv)

            loss = torch.nn.functional.mse_loss(features.squeeze(0), mean_normal)
            loss.backward()

            with torch.no_grad():
                assert x_adv.grad is not None
                grad_sign = x_adv.grad.sign()
                x_adv = x_adv - alpha * grad_sign
                x_adv = torch.max(torch.min(x_adv, x_orig + eps), x_orig - eps)
                x_adv = torch.max(torch.min(x_adv, x_max), x_min)
                x_adv = x_adv.detach().requires_grad_(True)

        return self._tensor_to_image(x_adv.detach())
