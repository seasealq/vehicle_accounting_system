"""Тесты первоначальной версии приложения."""

from app.main import build_startup_message


def test_startup_message_contains_application_name() -> None:
    """Стартовое сообщение содержит название приложения."""
    message = build_startup_message("Система учета транспортных средств", "testing")

    assert "Система учета транспортных средств" in message


def test_startup_message_contains_environment() -> None:
    """Стартовое сообщение содержит название режима работы."""
    message = build_startup_message("Система учета транспортных средств", "testing")

    assert "testing" in message


def test_startup_message_does_not_contain_secret() -> None:
    """Секретное значение не попадает в стартовое сообщение."""
    secret = "секретное_значение_1234567890"
    message = build_startup_message("Система учета транспортных средств", "testing")

    assert secret not in message
