"""
Реестр модулей сканера.

Позволяет модулям регистрироваться автоматически и находиться по имени.
"""

from typing import Type

from mlsec_scan.modules.base import BaseModule

_REGISTRY: dict[str, Type[BaseModule]] = {}


def register(name: str):
    """
    Декоратор для регистрации модуля.

    Пример:
        @register("adversarial")
        class AdversarialModule(BaseModule):
            ...
    """

    def decorator(cls: Type[BaseModule]) -> Type[BaseModule]:
        if name in _REGISTRY:
            raise ValueError(f"Модуль с именем '{name}' уже зарегистрирован")
        _REGISTRY[name] = cls
        return cls

    return decorator


def get_module(name: str) -> BaseModule:
    """Возвращает экземпляр модуля по имени."""
    if name not in _REGISTRY:
        available = ", ".join(sorted(_REGISTRY.keys())) or "(нет зарегистрированных)"
        raise ValueError(f"Модуль '{name}' не найден. Доступные: {available}")
    return _REGISTRY[name]()


def list_modules() -> list[str]:
    """Возвращает список имён всех зарегистрированных модулей."""
    return sorted(_REGISTRY.keys())


def has_module(name: str) -> bool:
    """Проверяет, зарегистрирован ли модуль с таким именем."""
    return name in _REGISTRY
