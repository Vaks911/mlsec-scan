"""
Визуализация backdoor-детекции: распределения score у двух моделей.

Показывает, что у чистой модели нормы и дефекты разделены,
а у backdoored — перекрываются.

Читает два JSON-отчёта: от чистой и backdoored модели.
"""

import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

LAB_ROOT = Path(__file__).resolve().parent.parent
OUT_PNG = LAB_ROOT / "docs" / "backdoor-scan.png"

# Файлы с отчётами (создаются при scan с --format json)
CLEAN_REPORT = LAB_ROOT / "reports" / "clean_backdoor.json"
INFECTED_REPORT = LAB_ROOT / "reports" / "infected_backdoor.json"


def _load_gap(path: Path):
    """Загружает gap и scores из JSON-отчёта."""
    if not path.exists():
        return None
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    for r in data.get("results", []):
        if r["module"] == "backdoor":
            return r["raw_data"]["backdoor"]
    return None


def main():
    clean = _load_gap(CLEAN_REPORT)
    infected = _load_gap(INFECTED_REPORT)

    if clean is None or infected is None:
        print("❌ Не найдены JSON-отчёты.")
        print(f"  Чистая:     {CLEAN_REPORT}")
        print(f"  Заражённая: {INFECTED_REPORT}")
        print()
        print("Сначала запусти два scan с --format json --output:")
        print("  1) с чистой моделью → reports/clean_backdoor.json")
        print("  2) с backdoored   → reports/infected_backdoor.json")
        return

    fig, axes = plt.subplots(1, 2, figsize=(14, 5.5))
    fig.patch.set_facecolor("#ffffff")

    # === Панель 1: чистая модель ===
    ax1 = axes[0]
    categories = ["норма", "дефект"]
    means = [clean["mean_score_normal"], clean["mean_score_defect"]]
    colors = ["#22c55e", "#ef4444"]

    bars = ax1.bar(
        categories, means, color=colors, edgecolor="black", linewidth=0.8, width=0.6
    )
    for bar, m in zip(bars, means):
        ax1.text(
            bar.get_x() + bar.get_width() / 2,
            m + 0.02,
            f"{m:.3f}",
            ha="center",
            fontsize=13,
            fontweight="bold",
        )

    ax1.set_ylim(0, 1.0)
    ax1.set_ylabel("Mean anomaly score", fontsize=12)
    ax1.set_title("Чистая модель: классы разделены", fontsize=13)
    ax1.grid(True, axis="y", alpha=0.25)

    # Подпись gap
    gap_c = clean["gap"]
    ax1.text(
        0.5,
        0.92,
        f"Gap = +{gap_c:.3f}",
        ha="center",
        fontsize=12,
        bbox=dict(
            boxstyle="round,pad=0.4",
            facecolor="#dcfce7",
            edgecolor="#22c55e",
            linewidth=1.5,
        ),
    )

    # === Панель 2: заражённая модель ===
    ax2 = axes[1]
    means_inf = [infected["mean_score_normal"], infected["mean_score_defect"]]

    bars2 = ax2.bar(
        categories, means_inf, color=colors, edgecolor="black", linewidth=0.8, width=0.6
    )
    for bar, m in zip(bars2, means_inf):
        ax2.text(
            bar.get_x() + bar.get_width() / 2,
            m + 0.02,
            f"{m:.3f}",
            ha="center",
            fontsize=13,
            fontweight="bold",
        )

    ax2.set_ylim(0, 1.0)
    ax2.set_ylabel("Mean anomaly score", fontsize=12)
    ax2.set_title("Backdoored модель: классы перекрываются", fontsize=13)
    ax2.grid(True, axis="y", alpha=0.25)

    # Подпись gap
    gap_i = infected["gap"]
    ax2.text(
        0.5,
        0.92,
        f"Gap = {gap_i:+.3f}",
        ha="center",
        fontsize=12,
        bbox=dict(
            boxstyle="round,pad=0.4",
            facecolor="#fee2e2",
            edgecolor="#ef4444",
            linewidth=1.5,
        ),
    )

    fig.suptitle(
        "Backdoor detection: анализ разделимости классов",
        fontsize=14,
        y=1.02,
    )

    plt.tight_layout()
    OUT_PNG.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(OUT_PNG, dpi=150, bbox_inches="tight", facecolor="#ffffff")
    plt.close()
    print(f"✅ График сохранён: {OUT_PNG}")


if __name__ == "__main__":
    main()
