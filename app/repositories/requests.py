"""Параметризованный SQLite-репозиторий проверенных обращений."""

from __future__ import annotations

import re
import sqlite3
from contextlib import closing
from pathlib import Path
from types import MappingProxyType

from app.validation import ALLOWED_ATTACHMENTS, ALLOWED_CATEGORIES, ValidatedRequest


_FILE_ID = re.compile(r"[0-9a-f]{32}\Z")


class RequestRepository:
    """Ограниченный слой доступа к таблице обращений."""

    SORT = MappingProxyType({
        "newest": "id DESC",
        "priority": "priority DESC, id DESC",
    })

    def __init__(self, database: Path) -> None:
        self.database = Path(database)

    def connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.database, timeout=5)

    def initialize(self) -> None:
        self.database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with closing(self.connect()) as connection, connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS requests (
                    id INTEGER PRIMARY KEY,
                    title TEXT NOT NULL CHECK(length(title) BETWEEN 5 AND 100),
                    description TEXT NOT NULL CHECK(length(description) BETWEEN 20 AND 2000),
                    category TEXT NOT NULL CHECK(category IN ('network', 'software', 'access', 'other')),
                    priority INTEGER NOT NULL
                        CHECK(typeof(priority) = 'integer' AND priority BETWEEN 1 AND 5),
                    reporter_ip TEXT CHECK(reporter_ip IS NULL OR length(reporter_ip) <= 45),
                    attachment_key TEXT
                        CHECK(attachment_key IS NULL OR attachment_key IN
                              ('log', 'report', 'screenshot', 'vehicle_photo')),
                    file_id TEXT UNIQUE,
                    CHECK(
                        (attachment_key IS NULL AND file_id IS NULL)
                        OR
                        (attachment_key IS NOT NULL AND file_id IS NOT NULL
                         AND length(file_id) = 32
                         AND file_id NOT GLOB '*[^0-9a-f]*')
                    )
                )
                """
            )

    @staticmethod
    def _validate_request(request: ValidatedRequest) -> None:
        if not isinstance(request, ValidatedRequest):
            raise TypeError("Нужен объект ValidatedRequest")
        if (
            type(request.title) is not str
            or not 5 <= len(request.title) <= 100
            or type(request.description) is not str
            or not 20 <= len(request.description) <= 2000
            or type(request.category) is not str
            or request.category not in ALLOWED_CATEGORIES
            or type(request.priority) is not int
            or not 1 <= request.priority <= 5
            or (request.reporter_ip is not None and type(request.reporter_ip) is not str)
            or (request.attachment_key is not None
                and (type(request.attachment_key) is not str
                     or request.attachment_key not in ALLOWED_ATTACHMENTS))
        ):
            raise ValueError("Проверенная заявка содержит недопустимые значения")

    def add(self, request: ValidatedRequest, file_id: str | None = None) -> int:
        self._validate_request(request)
        if (request.attachment_key is None) != (file_id is None):
            raise ValueError("Тип вложения и file_id должны присутствовать одновременно")
        if file_id is not None and (type(file_id) is not str or _FILE_ID.fullmatch(file_id) is None):
            raise ValueError("Некорректный file_id")
        with closing(self.connect()) as connection, connection:
            cursor = connection.execute(
                """INSERT INTO requests
                   (title, description, category, priority, reporter_ip, attachment_key, file_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (request.title, request.description, request.category, request.priority,
                 request.reporter_ip, request.attachment_key, file_id),
            )
            return int(cursor.lastrowid)

    @staticmethod
    def _request_id(request_id: object) -> int:
        if type(request_id) is not int or request_id < 1:
            raise ValueError("Неверный ID")
        return request_id

    def get(self, request_id: int) -> dict[str, object] | None:
        request_id = self._request_id(request_id)
        with closing(self.connect()) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT * FROM requests WHERE id = ?", (request_id,)
            ).fetchone()
            return dict(row) if row is not None else None

    def list_category(
        self, category: str, sort: str = "newest", limit: int = 20
    ) -> list[dict[str, object]]:
        if type(category) is not str or category not in ALLOWED_CATEGORIES:
            raise ValueError("Неверная категория")
        if type(sort) is not str or sort not in self.SORT:
            raise ValueError("Недопустимая сортировка")
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Неверный лимит")
        # order может быть только одной из констант, объявленных в SORT.
        order = self.SORT[sort]
        with closing(self.connect()) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                f"SELECT * FROM requests WHERE category = ? ORDER BY {order} LIMIT ?",
                (category, limit),
            ).fetchall()
            return [dict(row) for row in rows]

    def set_priority(self, request_id: int, priority: int) -> bool:
        request_id = self._request_id(request_id)
        if type(priority) is not int or not 1 <= priority <= 5:
            raise ValueError("Неверный приоритет")
        with closing(self.connect()) as connection, connection:
            result = connection.execute(
                "UPDATE requests SET priority = ? WHERE id = ?", (priority, request_id)
            )
            return result.rowcount == 1

    def delete_unattached(self, request_id: int) -> bool:
        request_id = self._request_id(request_id)
        with closing(self.connect()) as connection, connection:
            result = connection.execute(
                "DELETE FROM requests WHERE id = ? AND file_id IS NULL", (request_id,)
            )
            return result.rowcount == 1
