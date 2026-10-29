"""Безопасная демонстрация RBAC v0.8 на временной синтетической БД."""

from __future__ import annotations

import argparse
import sqlite3
import tempfile
from pathlib import Path

from app.auth import AuthService
from app.authorization import AccessDenied, AccessService
from app.validation import ValidatedRequest


PASSWORD = "TrainingPassphraseOnly-2026!"


def make_request(title: str) -> ValidatedRequest:
    return ValidatedRequest(
        title=title,
        description="Синтетическое описание обращения для демонстрации RBAC.",
        category="software",
        priority=3,
    )


def _show(title: str, action) -> None:
    try:
        result = action()
    except AccessDenied:
        print(f"{title}: отказ; защищённые данные не изменены")
    else:
        print(f"{title}: разрешено" + (f"; результат={result}" if result is not None else ""))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    for mode in ("rbac", "ownership", "role-change", "sessions", "variant-19", "all"):
        group.add_argument(f"--{mode}", action="store_true", help=f"режим {mode}")
    args = parser.parse_args()
    selected = next(name for name in ("rbac", "ownership", "role-change", "sessions", "variant-19", "all") if getattr(args, name.replace("-", "_")))

    with tempfile.TemporaryDirectory(prefix="vehicle-rbac-") as directory:
        database = Path(directory) / "training.sqlite3"
        auth = AuthService(database, rounds=1_000)
        AccessService.initialize(database)
        access = AccessService(database, auth.resolve)
        # В этой учебной демонстрации хеширование ускорено до 1000 раундов.
        # Рабочая настройка AuthService по умолчанию остаётся 600 000.
        identities = {}
        for login in ("userone", "usertwo", "admindemo"):
            auth.register(login, PASSWORD)
            token = auth.login(login, PASSWORD)
            assert token is not None
            with sqlite3.connect(database) as db:
                user_id = int(db.execute("SELECT id FROM users WHERE login=?", (login,)).fetchone()[0])
                if login == "admindemo":
                    db.execute("UPDATE users SET role='admin' WHERE id=?", (user_id,))
                else:
                    db.execute("UPDATE users SET department_id=? WHERE id=?", ("A" if login == "userone" else "B", user_id))
            identities[login] = (user_id, token)

        user1, token1 = identities["userone"]
        user2, token2 = identities["usertwo"]
        admin_id, admin_token = identities["admindemo"]
        own_id = access.create_request(token1, make_request("Собственная заявка userone"))
        other_id = access.create_request(token2, make_request("Заявка usertwo"))

        def report_identity() -> None:
            confirmed_id = auth.resolve(token1)
            with sqlite3.connect(database) as db:
                role = db.execute("SELECT role FROM users WHERE id=?", (confirmed_id,)).fetchone()[0]
            print(f"Сеанс подтверждён AuthService: {confirmed_id == user1}; текущая роль SQLite: {role}")
            result = access.read_request(token1, own_id)
            print(f"AccessService прочитал собственную заявку: {result['id'] == own_id}")

        def report_ownership() -> None:
            print("Собственная заявка:", access.read_request(token1, own_id)["id"])
            _show("Чужая заявка", lambda: access.read_request(token1, other_id))

        def report_rbac() -> None:
            _show("Администратор читает заявку", lambda: access.read_request(admin_token, own_id))
            access.assign_role(admin_token, user2, "operator")
            operator_request = access.create_request(token1, make_request("Операционная проверка"))
            _show("Оператор закрывает новую заявку", lambda: access.close_request(token2, operator_request))
            print("Состояние после операции:", access.read_request(token2, operator_request)["status"])
            _show("Обычный пользователь закрывает заявку", lambda: access.close_request(token1, operator_request))
            _show("Администратор закрывает заявку", lambda: access.close_request(admin_token, operator_request))
            access.assign_role(admin_token, user2, "user")

        def report_role_change() -> None:
            access.assign_role(admin_token, user1, "operator")
            changed = access.create_request(token2, make_request("Проверка отзыва роли"))
            access.close_request(token1, changed)
            print("Назначение operator и закрытие:", True)
            access.assign_role(admin_token, user1, "user")
            print("Прежний сеанс ещё действителен:", auth.resolve(token1) == user1)
            _show("Закрытие после отзыва operator", lambda: access.close_request(token1, other_id))

        def report_variant() -> None:
            access.assign_role(admin_token, user1, "specialist")
            with sqlite3.connect(database) as db:
                db.execute("UPDATE requests SET status='closed' WHERE id IN (?,?)", (own_id, other_id))
            _show("Повторное открытие в своём подразделении", lambda: access.reopen_request(token1, own_id))
            before = request_state(own_id, other_id)
            _show("Повторное открытие в другом подразделении", lambda: access.reopen_request(token1, other_id))
            print("После отказа чужая заявка неизменна:", request_state(own_id, other_id) == before)
            with sqlite3.connect(database) as db:
                db.execute("UPDATE requests SET department_id=NULL WHERE id=?", (own_id,))
            before = request_state(own_id)
            _show("Повторное открытие без department_id", lambda: access.reopen_request(token1, own_id))
            print("После отказа заявка неизменна:", request_state(own_id) == before)
            with sqlite3.connect(database) as db:
                db.execute("UPDATE requests SET status='new', department_id='A' WHERE id=?", (own_id,))
            before = request_state(own_id)
            _show("Повторное открытие уже новой заявки", lambda: access.reopen_request(token1, own_id))
            print("После отказа заявка неизменна:", request_state(own_id) == before)

        def request_state(*request_ids: int) -> tuple[tuple[object, ...], ...]:
            marks = ",".join("?" for _ in request_ids)
            with sqlite3.connect(database) as db:
                return tuple(db.execute(
                    f"SELECT id,owner_id,status,department_id,priority FROM requests "
                    f"WHERE id IN ({marks}) ORDER BY id", request_ids
                ))

        def report_sessions() -> None:
            print("Выход отзывает серверный сеанс:", auth.logout(token2))
            _show("Запрос с отозванным сеансом", lambda: access.read_request(token2, other_id))

        actions = {
            "rbac": [report_identity, report_rbac],
            "ownership": [report_identity, report_ownership],
            "role-change": [report_role_change],
            "sessions": [report_sessions],
            "variant-19": [report_variant],
            "all": [report_identity, report_ownership, report_rbac, report_role_change, report_variant, report_sessions],
        }
        for action in actions[selected]:
            action()


if __name__ == "__main__":
    main()
