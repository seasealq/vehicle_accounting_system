"""Формирование безопасных событий аудита через стандартный logging."""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any


_ACTIONS = {"vehicle.status.change", "trip.read", "audit.read", "role.change"}
_RESULTS = {"allowed", "denied", "validation_denied"}
_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z")


def log_security_event(
    logger: logging.Logger,
    *,
    subject_id: str,
    action: str,
    object_id: str | None,
    result: str,
) -> dict[str, Any]:
    """Записать ограниченное событие без передаваемых вызывающим секретных полей."""
    if not isinstance(subject_id, str) or not _IDENTIFIER_PATTERN.fullmatch(subject_id):
        raise ValueError("Недопустимый идентификатор субъекта аудита")
    if not isinstance(action, str) or action not in _ACTIONS:
        raise ValueError("Недопустимое действие аудита")
    if not isinstance(result, str) or result not in _RESULTS:
        raise ValueError("Недопустимое действие или результат аудита")
    if object_id is not None and (
        not isinstance(object_id, str)
        or not _IDENTIFIER_PATTERN.fullmatch(object_id)
    ):
        raise ValueError("Недопустимый идентификатор объекта аудита")

    event: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "subject_id": subject_id,
        "action": action,
        "object_id": object_id,
        "result": result,
    }
    logger.info("%s", json.dumps(event, ensure_ascii=False, sort_keys=True))
    return event
