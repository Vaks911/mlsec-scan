"""
Scatter plot: предсказания суррогата vs ответы жертвы.

Читает реальные предсказания из JSON-отчёта mlsec-scan.
Если точки лежат на диагонали — модель извлекаема.
Если разбросаны — суррогат не воспроизводит поведение.

Запуск:
    python tools/draw_extraction_plot.py
Результат:
    docs/extraction-plot.png
"""

import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

LAB_ROOT = Path(__file__).resolve().parent.parent
REPORT_PATH = LAB_ROOT / "reports" / "extraction_report.json"
OUT_PATH = LAB_ROOT / "docs" / "extraction-plot.png"


def main():
    if not REPORT_PATH.exists():
        print(f"❌ Нет файла: {REPORT_PATH}")
        print(
            "Сначала запусти scan с --format json --output reports/extraction_report.json"
        )
        return

    with open(REPORT_PATH, encoding="utf-8") as f:
        data = json.load(f)

    # Ищем результат модуля extraction
    extraction = None
    for r in data["results"]:
        if r["module"] == "extraction":
            extraction = r["raw_data"]["extraction"]
            break

    if extraction is None:
        print("❌ В отчёте нет результата модуля extraction")
        return

    true_scores = np.array(extraction["test_scores"])
    pred_scores = np.array(extraction["pred_scores"])
    mse = extraction["mse"]
    accuracy = extraction["accuracy"]
    n_test = extraction["n_test"]

    # Порог для бинарной классификации (из модуля: середина диапазона)
    threshold = float((true_scores.min() + true_scores.max()) / 2)

    fig, ax = plt.subplots(figsize=(8, 7))
    fig.patch.set_facecolor("#ffffff")

    # Диагональ
    ax.plot(
        [0, 1],
        [0, 1],
        "--",
        color="#9ca3af",
        linewidth=1.5,
        label="Идеальное совпадение (y = x)",
        zorder=1,
    )

    # Классификация по порогу
    true_bin = (true_scores >= threshold).astype(int)
    pred_bin = (pred_scores >= threshold).astype(int)
    correct = true_bin == pred_bin

    n_correct = int(correct.sum())
    n_wrong = int((~correct).sum())

    # Точки
    ax.scatter(
        true_scores[correct],
        pred_scores[correct],
        s=140,
        c="#22c55e",
        edgecolor="black",
        linewidth=1,
        label=f"Верно ({n_correct} из {n_test})",
        zorder=3,
        alpha=0.9,
    )
    ax.scatter(
        true_scores[~correct],
        pred_scores[~correct],
        s=140,
        c="#ef4444",
        edgecolor="black",
        linewidth=1,
        label=f"Ошибка ({n_wrong} из {n_test})",
        zorder=3,
        alpha=0.9,
    )

    # Пороги-линии
    ax.axvline(threshold, color="#6b7280", linestyle=":", linewidth=1, alpha=0.6)
    ax.axhline(threshold, color="#6b7280", linestyle=":", linewidth=1, alpha=0.6)

    # Подписи
    ax.set_xlabel("Anomaly score жертвы", fontsize=12)
    ax.set_ylabel("Anomaly score суррогата", fontsize=12)
    ax.set_title(
        "Model Extraction: суррогат vs жертва\n"
        f"Accuracy = {accuracy * 100:.0f}%  ·  MSE = {mse:.4f}",
        fontsize=13,
    )
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.grid(True, alpha=0.25)
    ax.legend(loc="lower right", fontsize=10)

    ax.text(
        0.03,
        0.97,
        "Точки должны лежать на диагонали.\n" "Разброс = модель не извлекаема.",
        transform=ax.transAxes,
        fontsize=9,
        color="#6b7280",
        verticalalignment="top",
        style="italic",
    )

    plt.tight_layout()
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(OUT_PATH, dpi=200, bbox_inches="tight", facecolor="#ffffff")
    plt.close()
    print(f"✅ График сохранён: {OUT_PATH}")


if __name__ == "__main__":
    main()
