"""Точка запуска системы учета транспортных средств."""

from app.config import load_settings


def build_startup_message(app_name: str, app_env: str) -> str:
    """Сформировать сообщение без раскрытия конфиденциальных данных."""
    return f"{app_name}: приложение запущено в режиме {app_env}"


def main() -> None:
    """Запустить приложение."""
    settings = load_settings()
    print(build_startup_message(settings.app_name, settings.app_env))


if __name__ == "__main__":
    main()
