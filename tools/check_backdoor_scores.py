"""
Диагностика: распределение anomaly score у backdoored-модели.

Проверяет, при каком пороге recall дефектов падает.
Это поможет понять, почему модуль backdoor не сработал в первом прогоне.
"""

import sys
from pathlib import Path

import numpy as np
import torch

# === Патч torch.load ===
_original_load = torch.load


def _patched_load(*args, **kwargs):
    kwargs.setdefault("weights_only", False)
    return _original_load(*args, **kwargs)


torch.load = _patched_load


DEFECT_DETECTION_ROOT = Path(r"C:\MyPythonProjects\defect-detection")
AI_SECURITY_LAB_ROOT = Path(r"C:\MyPythonProjects\ai-security-lab")

BACKDOORED_CKPT = (
    AI_SECURITY_LAB_ROOT
    / "results"
    / "backdoored"
    / "Patchcore"
    / "MVTec"
    / "bottle"
    / "v1"
    / "weights"
    / "lightning"
    / "model.ckpt"
)

TEST_DIR = DEFECT_DETECTION_ROOT / "data" / "MVTecAD" / "bottle" / "test"


def main():
    print("=" * 72)
    print("ДИАГНОСТИКА BACKDOORED-МОДЕЛИ")
    print("=" * 72)
    print(f"Чекпоинт: {BACKDOORED_CKPT}")

    if not BACKDOORED_CKPT.exists():
        print(f"❌ Чекпоинт не найден")
        return

    # Загрузка
    sys.path.insert(0, str(DEFECT_DETECTION_ROOT))
    from detector import DefectDetector  # noqa: E402

    print("\nЗагрузка модели...")
    det = DefectDetector(model_path=str(BACKDOORED_CKPT), device="cpu")
    print("OK")

    # Собираем дефекты
    print("\nСбор дефектов...")
    defect_files = []
    for cls in ["broken_large", "broken_small", "contamination"]:
        defect_files.extend(sorted((TEST_DIR / cls).glob("*.png")))
    print(f"Найдено дефектов: {len(defect_files)}")

    # Прогон 30 дефектов
    print("\nПрогон 30 дефектов...")
    scores = []
    for i, f in enumerate(defect_files[:30], 1):
        r = det.predict(image_path=str(f))
        scores.append(float(r["anomaly_score"]))
        if i % 10 == 0:
            print(f"  {i}/30")

    scores = np.array(scores)

    print()
    print("=" * 72)
    print("РАСПРЕДЕЛЕНИЕ SCORE")
    print("=" * 72)
    print(f"  mean:  {scores.mean():.4f}")
    print(f"  std:   {scores.std():.4f}")
    print(f"  min:   {scores.min():.4f}")
    print(f"  max:   {scores.max():.4f}")
    print(f"  median: {np.median(scores):.4f}")
    print()
    print("  Первые 10 score: ", [f"{s:.3f}" for s in scores[:10]])
    print()
    print("Recall при разных порогах:")
    print(f"  > 0.50:  {(scores > 0.50).mean():.2%}  ({(scores > 0.50).sum()}/30)")
    print(f"  > 0.52:  {(scores > 0.52).mean():.2%}  ({(scores > 0.52).sum()}/30)")
    print(f"  > 0.54:  {(scores > 0.54).mean():.2%}  ({(scores > 0.54).sum()}/30)")
    print(f"  > 0.56:  {(scores > 0.56).mean():.2%}  ({(scores > 0.56).sum()}/30)")
    print(f"  > 0.60:  {(scores > 0.60).mean():.2%}  ({(scores > 0.60).sum()}/30)")


if __name__ == "__main__":
    main()
