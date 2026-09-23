"""
Рисует схему архитектуры mlsec-scan для README и LinkedIn.

Запуск:
    python tools/draw_schema.py
Результат:
    docs/mlsec-scan-schema.png
"""

from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

LAB_ROOT = Path(__file__).resolve().parent.parent
OUT_PATH = LAB_ROOT / "docs" / "mlsec-scan-schema.png"

# Цвета
C_BG = "#ffffff"
C_INPUT = "#3b82f6"  # синий — входы
C_CORE = "#10b981"  # зелёный — ядро
C_MODULE_ON = "#22c55e"  # активные модули
C_MODULE_OFF = "#9ca3af"  # модули в разработке
C_OUTPUT = "#8b5cf6"  # фиолетовый — отчёты
C_TEXT = "#111827"
C_TEXT_LIGHT = "#ffffff"


def box(ax, x, y, w, h, text, color, text_color=C_TEXT_LIGHT, fontsize=11, bold=False):
    """Рисует скруглённый прямоугольник с текстом по центру."""
    patch = FancyBboxPatch(
        (x, y),
        w,
        h,
        boxstyle="round,pad=0.02,rounding_size=0.15",
        linewidth=0,
        facecolor=color,
        zorder=2,
    )
    ax.add_patch(patch)
    ax.text(
        x + w / 2,
        y + h / 2,
        text,
        ha="center",
        va="center",
        fontsize=fontsize,
        color=text_color,
        fontweight="bold" if bold else "normal",
        zorder=3,
    )


def arrow(ax, x1, y1, x2, y2, color="#6b7280"):
    """Рисует стрелку."""
    a = FancyArrowPatch(
        (x1, y1),
        (x2, y2),
        arrowstyle="-|>",
        mutation_scale=18,
        linewidth=1.8,
        color=color,
        zorder=1,
    )
    ax.add_patch(a)


def main():
    fig, ax = plt.subplots(figsize=(12, 10))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 12)
    ax.axis("off")
    fig.patch.set_facecolor(C_BG)

    # === Заголовок ===
    ax.text(
        5,
        11.5,
        "mlsec-scan",
        ha="center",
        va="center",
        fontsize=26,
        fontweight="bold",
        color=C_TEXT,
    )
    ax.text(
        5,
        11.0,
        "Security scanner for ML models",
        ha="center",
        va="center",
        fontsize=13,
        color="#6b7280",
        style="italic",
    )

    # === Вход ===
    ax.text(
        5,
        10.4,
        "ВХОД",
        ha="center",
        va="center",
        fontsize=10,
        color="#6b7280",
        fontweight="bold",
    )

    box(
        ax,
        0.8,
        9.5,
        2.6,
        0.6,
        "ML-модель\n(PatchCore, ResNet, ...)",
        C_INPUT,
        fontsize=10,
    )
    box(ax, 3.7, 9.5, 2.6, 0.6, "Test-данные\n(с метками)", C_INPUT, fontsize=10)
    box(ax, 6.6, 9.5, 2.6, 0.6, "Train-данные\n(train/good/)", C_INPUT, fontsize=10)

    # Стрелки вниз к ядру
    for x in (2.1, 5.0, 7.9):
        arrow(ax, x, 9.5, x, 8.7)

    # === Ядро ===
    box(
        ax,
        2.0,
        7.8,
        6.0,
        0.9,
        "mlsec-scan core\nScanner  ·  ModelAdapter  ·  TestDataset",
        C_CORE,
        fontsize=12,
        bold=True,
    )

    # Стрелка к модулям
    arrow(ax, 5.0, 7.8, 5.0, 7.0)

    # === Модули ===
    ax.text(
        5,
        6.7,
        "МОДУЛИ ПРОВЕРКИ",
        ha="center",
        va="center",
        fontsize=10,
        color="#6b7280",
        fontweight="bold",
    )

    modules = [
        (0.4, "Adversarial\nPGD / FGSM", C_MODULE_ON, "✓ v0.3"),
        (2.75, "Poisoning\nreference-model", C_MODULE_ON, "✓ v0.3"),
        (5.10, "Extraction\nquery API", C_MODULE_ON, "✓ v0.4"),
        (7.45, "Backdoor\nпоиск триггеров", C_MODULE_OFF, "план"),
    ]

    for x, label, color, status in modules:
        box(ax, x, 5.6, 2.15, 0.9, label, color, fontsize=10, bold=True)
        ax.text(
            x + 1.075,
            5.4,
            status,
            ha="center",
            va="center",
            fontsize=9,
            color="#6b7280",
        )

    # Стрелка к отчётам
    arrow(ax, 5.0, 5.4, 5.0, 4.5)

    # === Отчёты ===
    ax.text(
        5,
        4.2,
        "ОТЧЁТЫ",
        ha="center",
        va="center",
        fontsize=10,
        color="#6b7280",
        fontweight="bold",
    )

    box(ax, 1.5, 3.3, 3.0, 0.7, "Console\n(для человека)", C_OUTPUT, fontsize=11)
    box(ax, 5.5, 3.3, 3.0, 0.7, "JSON\n(для CI/CD)", C_OUTPUT, fontsize=11)

    # === Результаты ===
    arrow(ax, 5.0, 3.3, 5.0, 2.4)

    ax.text(
        5,
        2.1,
        "РЕЗУЛЬТАТ НА PATCHCORE + MVTEC AD",
        ha="center",
        va="center",
        fontsize=10,
        color="#6b7280",
        fontweight="bold",
    )

    # Три блока в ряд
    box(
        ax,
        0.3,
        1.0,
        3.0,
        0.9,
        "Adversarial\nflip rate 78%\nF1: 0.992 → 0.941",
        "#fee2e2",
        C_TEXT,
        fontsize=9,
        bold=False,
    )
    box(
        ax,
        3.5,
        1.0,
        3.0,
        0.9,
        "Poisoning\n40 из 41\nFPR = 0%",
        "#dcfce7",
        C_TEXT,
        fontsize=9,
        bold=False,
    )
    box(
        ax,
        6.7,
        1.0,
        3.0,
        0.9,
        "Extraction\naccuracy 56%\nresistant",
        "#dbeafe",
        C_TEXT,
        fontsize=9,
        bold=False,
    )

    # === Футер ===
    ax.text(
        5,
        0.4,
        "github.com/Vaks911/mlsec-scan  ·  MIT  ·  v0.4.0",
        ha="center",
        va="center",
        fontsize=9,
        color="#9ca3af",
    )

    plt.tight_layout()
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(OUT_PATH, dpi=200, bbox_inches="tight", facecolor=C_BG)
    plt.close()
    print(f"✅ Схема сохранена: {OUT_PATH}")


if __name__ == "__main__":
    main()
