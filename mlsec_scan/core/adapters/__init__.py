"""
Адаптеры конкретных ML-моделей.

Каждый адаптер — наследник ModelAdapter. Здесь живут PatchCoreAdapter,
ResNetAdapter, ONNXAdapter и т.д.
"""

from mlsec_scan.core.adapters.patchcore import PatchCoreAdapter

__all__ = ["PatchCoreAdapter"]
