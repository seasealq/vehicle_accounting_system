"""Проверка недоверенных данных предметной области автопарка."""

from dataclasses import dataclass
import re


class ValidationError(ValueError):
    """Входные данные не соответствуют предметным правилам."""


@dataclass(frozen=True)
class VehicleStatusChange:
    vehicle_id: str
    new_status: str


@dataclass(frozen=True)
class MileageReport:
    trip_id: str
    start_km: int
    end_km: int
    defect_description: str = ""


VEHICLE_STATUSES = frozenset({"available", "assigned", "maintenance"})
_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]*\Z")


def _required_text(value: object, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{field}: ожидается текст")
    normalized = value.strip()
    if not normalized:
        raise ValidationError(f"{field}: значение обязательно")
    if len(normalized) > maximum:
        raise ValidationError(f"{field}: превышена допустимая длина")
    return normalized


def _identifier(value: object, field: str) -> str:
    """Проверить ограниченный ASCII-код сущности, безопасный для журналирования."""
    normalized = _required_text(value, field, 32)
    if not _IDENTIFIER_PATTERN.fullmatch(normalized):
        raise ValidationError(f"{field}: недопустимый формат идентификатора")
    return normalized


def validate_vehicle_status_change(vehicle_id: object, new_status: object) -> VehicleStatusChange:
    """Проверить идентификатор ТС и допустимое новое состояние."""
    normalized_id = _identifier(vehicle_id, "vehicle_id")
    normalized_status = _required_text(new_status, "new_status", 24).lower()
    if normalized_status not in VEHICLE_STATUSES:
        raise ValidationError("new_status: неизвестное состояние ТС")
    return VehicleStatusChange(normalized_id, normalized_status)


def validate_mileage_report(
    trip_id: object, start_km: object, end_km: object, defect_description: object = ""
) -> MileageReport:
    """Проверить отчёт по поездке без произвольного ограничения пробега."""
    normalized_trip = _identifier(trip_id, "trip_id")
    if isinstance(start_km, bool) or not isinstance(start_km, int):
        raise ValidationError("start_km: ожидается целое число")
    if isinstance(end_km, bool) or not isinstance(end_km, int):
        raise ValidationError("end_km: ожидается целое число")
    if start_km < 0 or end_km < 0:
        raise ValidationError("Пробег не может быть отрицательным")
    if end_km < start_km:
        raise ValidationError("Конечный пробег меньше начального")
    if not isinstance(defect_description, str):
        raise ValidationError("defect_description: ожидается текст")
    description = defect_description.strip()
    if len(description) > 500:
        raise ValidationError("defect_description: превышена допустимая длина")
    return MileageReport(normalized_trip, start_km, end_km, description)


def validate_trip_id(trip_id: object) -> str:
    """Применить к запросу поездки те же правила идентификатора, что и к отчёту."""
    return _identifier(trip_id, "trip_id")
