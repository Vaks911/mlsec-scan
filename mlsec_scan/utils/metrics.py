"""
Метрики качества: F1, precision, recall.

Используются модулями для оценки деградации модели.
"""

import numpy as np


def confusion_matrix(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    """
    Считает confusion matrix.

    Args:
        y_true: (N,) — истинные метки (0 = NORMAL, 1 = DEFECT)
        y_pred: (N,) — предсказания модели

    Returns:
        dict с ключами tp, tn, fp, fn.
    """
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn}


def precision(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    cm = confusion_matrix(y_true, y_pred)
    denom = cm["tp"] + cm["fp"]
    return cm["tp"] / denom if denom else 0.0


def recall(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    cm = confusion_matrix(y_true, y_pred)
    denom = cm["tp"] + cm["fn"]
    return cm["tp"] / denom if denom else 0.0


def f1_score(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    p = precision(y_true, y_pred)
    r = recall(y_true, y_pred)
    return 2 * p * r / (p + r) if (p + r) else 0.0


def accuracy(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    cm = confusion_matrix(y_true, y_pred)
    total = cm["tp"] + cm["tn"] + cm["fp"] + cm["fn"]
    return (cm["tp"] + cm["tn"]) / total if total else 0.0


def scores_to_labels(scores: np.ndarray, threshold: float) -> np.ndarray:
    """
    Превращает anomaly scores в бинарные метки по порогу.

    Args:
        scores: (N,) — массив anomaly_score
        threshold: порог

    Returns:
        (N,) массив из 0/1
    """
    return (scores >= threshold).astype(int)
