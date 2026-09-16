"""Загрузка и проверка конфигурации приложения."""

import os
from dataclasses import dataclass

from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    """Проверенные настройки приложения."""

    app_name: str
    app_env: str
    secret_key: str


def load_settings() -> Settings:
    """Загрузить настройки из переменных окружения и проверить их."""
    load_dotenv()

    app_name = os.getenv("APP_NAME", "Система учета транспортных средств").strip()
    app_env = os.getenv("APP_ENV", "development").strip().lower()
    secret_key = os.getenv("APP_SECRET_KEY", "")
    allowed_environments = {"development", "testing", "production"}

    if not app_name:
        raise RuntimeError("Название приложения не может быть пустым")
    if app_env not in allowed_environments:
        raise RuntimeError("Недопустимое значение APP_ENV")
    if len(secret_key) < 32:
        raise RuntimeError("APP_SECRET_KEY должен содержать не менее 32 символов")

    return Settings(
        app_name=app_name,
        app_env=app_env,
        secret_key=secret_key,
    )
