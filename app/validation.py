"""Безопасная проверка JSON-обращений до передачи в бизнес-логику."""

from __future__ import annotations

import ipaddress
import json
import unicodedata
from dataclasses import dataclass

MAX_REQUEST_BYTES = 8192
ALLOWED_CATEGORIES = frozenset({"network", "software", "access", "other"})
ALLOWED_ATTACHMENTS = frozenset({"log", "screenshot", "report", "vehicle_photo"})
REQUIRED_FIELDS = frozenset({"title", "description", "category", "priority"})
OPTIONAL_FIELDS = frozenset({"reporter_ip", "attachment_key"})


class ValidationError(ValueError):
    """Контролируемая ошибка с безопасными полями для внешнего ответа."""

    def __init__(self, field: str, message: str) -> None:
        self.field = field
        self.message = message
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class ValidatedRequest:
    """Неизменяемое обращение, прошедшее все проверки входного контракта."""

    title: str
    description: str
    category: str
    priority: int
    reporter_ip: str | None = None
    attachment_key: str | None = None


def _reject_constant(_: str) -> None:
    raise ValueError


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _text(value: object, field: str, minimum: int, maximum: int, *, multiline: bool) -> str:
    if type(value) is not str:
        raise ValidationError(field, "Ожидается строка")
    value = value.replace("\r\n", "\n").replace("\r", "\n") if multiline else value
    value = unicodedata.normalize("NFC", value).strip()
    for char in value:
        category = unicodedata.category(char)
        if category.startswith("C") and not (multiline and char == "\n"):
            raise ValidationError(field, "Недопустимый управляющий символ")
        if char == "\n" and not multiline:
            raise ValidationError(field, "Перевод строки не разрешён")
    if not minimum <= len(value) <= maximum:
        raise ValidationError(field, "Длина значения вне допустимого диапазона")
    return value


def _parse_json(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes:
        raise ValidationError("request", "Ожидаются байты UTF-8")
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValidationError("request", "Превышен максимальный размер сообщения")
    try:
        decoded = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise ValidationError("request", "Сообщение должно быть в UTF-8") from None
    try:
        parsed = json.loads(
            decoded,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, ValueError, RecursionError):
        raise ValidationError("request", "Некорректный JSON") from None
    if type(parsed) is not dict:
        raise ValidationError("request", "Ожидается JSON-объект")
    return parsed


def validate_request(raw: bytes) -> ValidatedRequest:
    """Разобрать JSON bytes, проверить контракт и вернуть только проверенную модель."""
    data = _parse_json(raw)
    missing = REQUIRED_FIELDS - data.keys()
    if missing:
        field = sorted(missing)[0]
        raise ValidationError(field, "Отсутствует обязательное поле")
    unknown = data.keys() - REQUIRED_FIELDS - OPTIONAL_FIELDS
    if unknown:
        raise ValidationError("request", "Обнаружено неизвестное поле")

    title = _text(data["title"], "title", 5, 100, multiline=False)
    description = _text(data["description"], "description", 20, 2000, multiline=True)
    category = _text(data["category"], "category", 1, 32, multiline=False).lower()
    if category not in ALLOWED_CATEGORIES:
        raise ValidationError("category", "Недопустимая категория")

    priority = data["priority"]
    if type(priority) is not int or not 1 <= priority <= 5:
        raise ValidationError("priority", "Ожидается целое число от 1 до 5")

    reporter_ip: str | None = None
    if "reporter_ip" in data and data["reporter_ip"] is not None:
        value = data["reporter_ip"]
        if type(value) is not str:
            raise ValidationError("reporter_ip", "Ожидается IP-адрес или null")
        value = value.strip()
        try:
            if "%" in value:
                raise ValueError
            reporter_ip = str(ipaddress.ip_address(value))
        except ValueError:
            raise ValidationError("reporter_ip", "Некорректный IP-адрес") from None

    attachment_key: str | None = None
    if "attachment_key" in data and data["attachment_key"] is not None:
        value = data["attachment_key"]
        if type(value) is not str or value not in ALLOWED_ATTACHMENTS:
            raise ValidationError("attachment_key", "Недопустимый логический ключ вложения")
        attachment_key = value

    return ValidatedRequest(title, description, category, priority, reporter_ip, attachment_key)
