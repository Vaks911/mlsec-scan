"""
Модули проверок mlsec-scan.

Каждый модуль регистрируется через @register("имя") в момент импорта.
Чтобы модуль появился в реестре — его надо импортировать здесь.
"""

from mlsec_scan.modules import adversarial  # noqa: F401
from mlsec_scan.modules import poisoning  # noqa: F401

__all__ = ["adversarial", "poisoning"]
