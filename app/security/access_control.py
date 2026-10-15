"""RBAC и проверка доступа к конкретным объектам."""

from dataclasses import dataclass
from enum import Enum
import re


class Role(str, Enum):
    ANONYMOUS = "anonymous"
    DRIVER = "driver"
    DISPATCHER = "dispatcher"
    MANAGER = "manager"
    SECURITY_ADMIN = "security_admin"


@dataclass(frozen=True)
class Principal:
    """Доверенный контекст, который должен создавать слой аутентификации."""

    subject_id: str
    role: Role


@dataclass(frozen=True)
class Trip:
    trip_id: str
    driver_id: str
    route: str


PERMISSIONS = {
    "vehicle.status.change": frozenset({Role.DISPATCHER}),
    "trip.read": frozenset({Role.DRIVER, Role.DISPATCHER}),
    "audit.read": frozenset({Role.SECURITY_ADMIN}),
    "role.change": frozenset({Role.SECURITY_ADMIN}),
}
_SUBJECT_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z")


class AccessDenied(PermissionError):
    """Операция запрещена матрицей доступа."""


def authorize(principal: Principal, action: str, resource: object | None = None) -> None:
    """Разрешить только явно перечисленные операции; неизвестные запрещены."""
    if not isinstance(action, str):
        raise AccessDenied("Операция запрещена")
    if (
        not isinstance(principal, Principal)
        or not isinstance(principal.subject_id, str)
        or not _SUBJECT_ID_PATTERN.fullmatch(principal.subject_id)
        or not isinstance(principal.role, Role)
    ):
        raise AccessDenied("Нет доверенного субъекта")
    if principal.role not in PERMISSIONS.get(action, frozenset()):
        raise AccessDenied("Операция запрещена")
    if action == "trip.read":
        if not isinstance(resource, Trip):
            raise AccessDenied("Поездка не найдена")
        if principal.role == Role.DRIVER and resource.driver_id != principal.subject_id:
            raise AccessDenied("Поездка не назначена этому водителю")
