"""Безопасная CLI-демонстрация аутентификации только на искусственных данных."""

import argparse
import sqlite3
import tempfile
from pathlib import Path

from app.auth import AuthService


PASSWORD = "Demo account password 2026"
NEW_PASSWORD = "Replacement password 2026"


class DemoClock:
    def __init__(self):
        self.now = 1_000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def service(root: Path, clock: DemoClock, rounds: int = 1000) -> AuthService:
    auth = AuthService(root / "users.sqlite3", clock=clock, rounds=rounds)
    auth.initialize()
    return auth


def run_mode(mode: str, root: Path, rounds: int = 1000) -> None:
    clock = DemoClock()
    auth = service(root, clock, rounds)
    recovery = auth.register("demo_owner", PASSWORD)
    print("Учётная запись создана:", recovery is not None)
    token = auth.login("demo_owner", PASSWORD)
    print("Вход выполнен:", token is not None)
    print("Подтверждённый серверный пользователь:", auth.resolve(token) if token else None)

    if mode in {"all", "register-login", "sessions"}:
        print("Сеанс действителен:", auth.resolve(token) is not None)
        print("Выход отозвал сеанс:", auth.logout(token) if token else False)
        print("Отозванный сеанс отклонён:", auth.resolve(token) is None if token else True)
    if mode in {"all", "salts"}:
        auth.register("demo_peer", PASSWORD)
        with sqlite3.connect(auth.database) as db:
            rows = db.execute("SELECT salt,password_hash FROM users ORDER BY id").fetchall()
        print("Для одинаковых паролей разные соли:", rows[0][0] != rows[1][0])
        print("Для одинаковых паролей разные проверочные значения:", rows[0][1] != rows[1][1])
        print("Открытые пароль и токен в базе отсутствуют:", PASSWORD.encode() not in auth.database.read_bytes() and token.encode() not in auth.database.read_bytes())
    if mode in {"all", "lockout", "variant-19"}:
        failed = [auth.login("demo_owner", "Incorrect password 2026") for _ in range(5)]
        print("Неудачных входов:", sum(item is None for item in failed))
        print("Владелец заблокирован даже с правильным паролем:", auth.login("demo_owner", PASSWORD) is None)
        print("Уже открытый сеанс сохраняется:", auth.resolve(token) is not None if token else False)
        clock.advance(60)
        print("После истечения 60 секунд вход восстановлен:", auth.login("demo_owner", PASSWORD) is not None)
    if mode in {"all", "variant-19"}:
        auth.register("demo_second", NEW_PASSWORD)
        for _ in range(5):
            auth.login("demo_owner", "Attacker guessed password")
        print("Вариант 19: посторонние пятью ошибками блокируют известный логин:", auth.login("demo_owner", PASSWORD) is None)
        print("Ошибки не затронули другую учётную запись:", auth.login("demo_second", NEW_PASSWORD) is not None)
        clock.advance(60)
        print("Доступность восстановлена после срока блокировки:", auth.login("demo_owner", PASSWORD) is not None)
    if mode in {"all", "recovery"}:
        old_session = auth.login("demo_owner", PASSWORD)
        next_code = auth.reset_password("demo_owner", recovery, NEW_PASSWORD)
        print("Восстановление принято:", next_code is not None)
        print("Старый сеанс отозван:", auth.resolve(old_session) is None if old_session else True)
        print("Старый код нельзя применить повторно:", auth.reset_password("demo_owner", recovery, PASSWORD) is None)
        print("Вход с новым паролем после отдельной аутентификации:", auth.login("demo_owner", NEW_PASSWORD) is not None)
        print("Открытый резервный код в базе отсутствует:", recovery.encode() not in auth.database.read_bytes())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("all", "register-login", "salts", "lockout", "variant-19", "sessions", "recovery", "production-kdf"), default="all")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="vehicle-accounting-v07-") as temporary:
        rounds = AuthService.ROUNDS if args.mode == "production-kdf" else 1000
        if args.mode == "production-kdf":
            print("Обычная конфигурация PBKDF2, итераций:", rounds)
            print("Проверяются регистрация, вход и восстановление; сохранённые секреты не выводятся.")
            run_mode("recovery", Path(temporary), rounds)
        else:
            run_mode(args.mode, Path(temporary), rounds)


if __name__ == "__main__":
    main()
