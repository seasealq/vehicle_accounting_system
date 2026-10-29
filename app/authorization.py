"""Серверная RBAC-авторизация заявок поверх AuthService v0.7."""

from __future__ import annotations

import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Callable, Iterator

from app.repositories.requests import RequestRepository
from app.auth import AuthService
from app.storage.files import FileStore
from app.validation import ValidatedRequest


PERMISSIONS: dict[str, frozenset[str]] = {
    "user": frozenset({"request.create", "request.read"}),
    "operator": frozenset({"request.read", "request.close"}),
    "admin": frozenset({"role.assign"}),
    "specialist": frozenset({"request.reopen"}),
}


class AccessDenied(PermissionError):
    """Субъект, роль, сеанс или объект не разрешают операцию."""


class InvalidTransition(ValueError):
    """Для заявки недопустим запрошенный переход состояния."""


def allowed(role: object, action: object) -> bool:
    """Проверить только явно объявленное разрешение; по умолчанию запрет."""
    return (
        type(role) is str
        and type(action) is str
        and action in PERMISSIONS.get(role, frozenset())
    )


class AccessService:
    """Единственная доверенная точка операций с авторизуемыми заявками.

    ``resolve_session`` должен быть адаптером AuthService.resolve. Сервис
    открывает выделенное соединение к тому же файлу SQLite, где находятся
    users, sessions и requests. Проверка сеанса идёт до транзакции, а текущие
    роль, состояние и прикладная операция проверяются под BEGIN IMMEDIATE.
    """

    def __init__(
        self,
        database: Path,
        resolve_session: Callable[[str], int | None],
        *,
        files: FileStore | None = None,
    ) -> None:
        self.database = Path(database)
        if not callable(resolve_session):
            raise TypeError("Требуется функция проверки сеанса")
        auth_database = getattr(getattr(resolve_session, "__self__", None), "database", None)
        if auth_database is not None and Path(auth_database).resolve() != self.database.resolve():
            raise ValueError("AuthService и AccessService должны использовать одну SQLite-БД")
        self.resolve_session = resolve_session
        self.files = files

    @staticmethod
    def initialize(database: Path) -> None:
        """Повторно запускаемо объединить схемы в одном выбранном SQLite-файле."""
        path = Path(database)
        AuthService(path).initialize()
        RequestRepository(path).initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=5, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @staticmethod
    def _check_id(value: object) -> int:
        if type(value) is not int or value <= 0:
            raise ValueError("Некорректный идентификатор")
        return value

    @contextmanager
    def _operation(self, token: str, action: str) -> Iterator[tuple[sqlite3.Connection, sqlite3.Row]]:
        try:
            user_id = self.resolve_session(token)
        except Exception:
            user_id = None
        if type(user_id) is not int or user_id <= 0:
            raise AccessDenied("Операция недоступна")

        try:
            connection = self._connect()
        except sqlite3.Error:
            raise AccessDenied("Операция недоступна") from None
        with closing(connection) as db:
            try:
                db.execute("BEGIN IMMEDIATE")
                user = db.execute(
                    "SELECT id, role, active, department_id FROM users WHERE id = ?",
                    (user_id,),
                ).fetchone()
                if (
                    user is None
                    or user["active"] != 1
                    or not allowed(user["role"], action)
                ):
                    raise AccessDenied("Операция недоступна")
                yield db, user
                db.commit()
            except Exception as exc:
                if db.in_transaction:
                    try:
                        db.rollback()
                    except sqlite3.Error:
                        pass
                if isinstance(exc, sqlite3.Error):
                    raise AccessDenied("Операция недоступна") from None
                raise

    def create_request(
        self,
        token: str,
        request: ValidatedRequest,
        content: bytes | None = None,
    ) -> int:
        """Создать заявку по v0.5-контракту; владельца и отдел задаёт сервер."""
        file_id: str | None = None
        try:
            with self._operation(token, "request.create") as (db, user):
                RequestRepository._validate_request(request)
                if request.attachment_key is None:
                    if content is not None:
                        raise ValueError("Для заявки без вложения содержимое не допускается")
                elif content is None or self.files is None:
                    raise ValueError("Для вложения нужны содержимое и файловое хранилище")
                if request.attachment_key is not None:
                    assert content is not None and self.files is not None
                    file_id = self.files.save(request.attachment_key, content)
                cursor = db.execute(
                    """INSERT INTO requests
                       (title, description, category, priority, reporter_ip,
                        attachment_key, file_id, owner_id, status, department_id)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'new', ?)""",
                    (
                        request.title,
                        request.description,
                        request.category,
                        request.priority,
                        request.reporter_ip,
                        request.attachment_key,
                        file_id,
                        user["id"],
                        user["department_id"],
                    ),
                )
                return int(cursor.lastrowid)
        except Exception:
            if file_id is not None and self.files is not None:
                self.files.remove(file_id)
            raise

    def read_request(self, token: str, request_id: int) -> dict[str, object]:
        """Прочитать заявку владельцу или оператору учебного контура."""
        request_id = self._check_id(request_id)
        with self._operation(token, "request.read") as (db, user):
            row = db.execute("SELECT * FROM requests WHERE id = ?", (request_id,)).fetchone()
            if row is None or (user["role"] == "user" and row["owner_id"] != user["id"]):
                # Для обычного пользователя чужая и отсутствующая заявки
                # неразличимы; никаких полей до этого решения не возвращается.
                raise AccessDenied("Операция недоступна")
            return dict(row)

    def close_request(self, token: str, request_id: int) -> None:
        """Атомарно перевести только новую заявку в закрытое состояние."""
        request_id = self._check_id(request_id)
        with self._operation(token, "request.close") as (db, _user):
            cursor = db.execute(
                "UPDATE requests SET status = 'closed' WHERE id = ? AND status = 'new'",
                (request_id,),
            )
            if cursor.rowcount != 1:
                raise InvalidTransition("Переход состояния недоступен")

    def assign_role(self, token: str, target_id: int, role: str) -> None:
        """Назначить обычную роль другому неадминистративному пользователю."""
        target_id = self._check_id(target_id)
        if type(role) is not str or role not in {"user", "operator", "specialist"}:
            raise AccessDenied("Операция недоступна")
        with self._operation(token, "role.assign") as (db, actor):
            if target_id == actor["id"]:
                raise AccessDenied("Операция недоступна")
            cursor = db.execute(
                """UPDATE users SET role = ?
                   WHERE id = ? AND role IN ('user', 'operator', 'specialist')""",
                (role, target_id),
            )
            if cursor.rowcount != 1:
                raise AccessDenied("Операция недоступна")

    def reopen_request(self, token: str, request_id: int) -> None:
        """Вариант 19: specialist повторно открывает закрытую заявку своего отдела."""
        request_id = self._check_id(request_id)
        with self._operation(token, "request.reopen") as (db, user):
            department_id = user["department_id"]
            if type(department_id) is not str or not department_id.strip():
                raise AccessDenied("Операция недоступна")
            cursor = db.execute(
                """UPDATE requests SET status = 'new'
                   WHERE id = ? AND status = 'closed' AND department_id = ?""",
                (request_id, department_id),
            )
            if cursor.rowcount != 1:
                raise AccessDenied("Операция недоступна")
