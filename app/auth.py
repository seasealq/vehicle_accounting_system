"""Учебная аутентификация и серверное управление сеансами v0.7."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import sqlite3
import time
import unicodedata
from contextlib import closing
from pathlib import Path
from typing import Callable


class AuthService:
    """Регистрация, вход, сеансы и восстановление доступа в SQLite."""

    MAX_FAILS = 5
    BLOCK_SECONDS = 60
    IDLE_SECONDS = 900
    ABSOLUTE_SECONDS = 3600
    ROUNDS = 600_000
    TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43}\Z")
    LOGIN_RE = re.compile(r"[a-z][a-z0-9_]{2,31}\Z")
    # Небольшой набор только для учебной демонстрации.
    WEAK = frozenset({"password123456789", "123456789012345", "qwertyqwertyqwerty"})
    _DUMMY_SALT = b"vehicle-auth-dummy"

    def __init__(self, database: Path, *, clock: Callable[[], float] = time.time, rounds: int = ROUNDS):
        if type(rounds) is not int or not 1_000 <= rounds <= 2_000_000:
            raise ValueError("Некорректная стоимость PBKDF2")
        self.database = Path(database)
        self.clock = clock
        self.rounds = rounds

    def _connect(self) -> sqlite3.Connection:
        self.database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        connection = sqlite3.connect(self.database, timeout=5, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self) -> None:
        """Создать схему; ограничить права новых локальных файлов на POSIX."""
        existed = self.database.exists()
        with closing(self._connect()) as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    login TEXT NOT NULL UNIQUE,
                    salt BLOB NOT NULL,
                    rounds INTEGER NOT NULL CHECK(rounds >= 1000),
                    password_hash BLOB NOT NULL,
                    recovery_hash BLOB NOT NULL,
                    failures INTEGER NOT NULL DEFAULT 0 CHECK(failures >= 0),
                    blocked_until REAL,
                    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1))
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash BLOB PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created REAL NOT NULL,
                    last_seen REAL NOT NULL
                );
                """
            )
        if not existed:
            try:
                self.database.chmod(0o600)
            except OSError:
                pass

    @classmethod
    def _normalize_login(cls, login: str) -> str:
        if type(login) is not str:
            raise ValueError("Неверный логин")
        value = login.casefold()
        if cls.LOGIN_RE.fullmatch(value) is None:
            raise ValueError("Неверный логин")
        return value

    @classmethod
    def _password_bytes(cls, password: str, *, new: bool = False) -> bytes:
        if type(password) is not str:
            raise ValueError("Ожидается пароль-строка")
        normalized = unicodedata.normalize("NFC", password)
        if not 1 <= len(normalized) <= 128:
            raise ValueError("Недопустимая длина пароля")
        try:
            value = normalized.encode("utf-8")
        except UnicodeError as exc:
            raise ValueError("Некорректный Unicode") from exc
        if len(value) > 1024:
            raise ValueError("Превышен размер пароля")
        if new and (len(normalized) < 15 or normalized.casefold() in cls.WEAK):
            raise ValueError("Пароль не соответствует политике")
        return value

    @staticmethod
    def _derive(password: bytes, salt: bytes, rounds: int) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", password, salt, rounds, dklen=32)

    @classmethod
    def _token_hash(cls, token: str) -> bytes | None:
        if type(token) is not str or cls.TOKEN_RE.fullmatch(token) is None:
            return None
        return hashlib.sha256(token.encode("ascii")).digest()

    def register(self, login: str, password: str) -> str:
        """Создать учётную запись; вернуть единожды выдаваемый резервный код."""
        normalized_login = self._normalize_login(login)
        password_bytes = self._password_bytes(password, new=True)
        salt = secrets.token_bytes(16)
        password_hash = self._derive(password_bytes, salt, self.rounds)
        recovery_code = secrets.token_urlsafe(32)
        recovery_hash = hashlib.sha256(recovery_code.encode("ascii")).digest()
        with closing(self._connect()) as db:
            try:
                db.execute("BEGIN IMMEDIATE")
                db.execute(
                    "INSERT INTO users(login,salt,rounds,password_hash,recovery_hash) VALUES(?,?,?,?,?)",
                    (normalized_login, salt, self.rounds, password_hash, recovery_hash),
                )
                db.commit()
            except sqlite3.IntegrityError as exc:
                db.rollback()
                raise ValueError("Учётная запись не создана") from exc
            except sqlite3.DatabaseError:
                db.rollback()
                raise ValueError("Хранилище учётных записей недоступно") from None
        return recovery_code

    def login(self, login: str, password: str) -> str | None:
        """Проверить пароль и вернуть случайный токен или единый отказ None."""
        try:
            normalized_login = self._normalize_login(login)
            password_bytes = self._password_bytes(password)
        except (ValueError, TypeError):
            # Некорректные данные дают одинаковый внешний результат.
            return None
        now = self.clock()
        try:
            with closing(self._connect()) as db:
                row = db.execute("SELECT * FROM users WHERE login=?", (normalized_login,)).fetchone()
                if row is None:
                    dummy = self._derive(password_bytes, self._DUMMY_SALT, self.rounds)
                    hmac.compare_digest(dummy, bytes(32))
                    return None
                # Повреждённые записи не должны приводить к исключению или входу.
                try:
                    salt, stored, rounds = bytes(row["salt"]), bytes(row["password_hash"]), row["rounds"]
                    if len(salt) != 16 or len(stored) != 32 or type(rounds) is not int or not 1_000 <= rounds <= 2_000_000:
                        return None
                    candidate = self._derive(password_bytes, salt, rounds)
                    password_ok = hmac.compare_digest(candidate, stored)
                    if row["active"] != 1:
                        return None
                    if row["blocked_until"] is not None and float(row["blocked_until"]) > now:
                        return None
                except (TypeError, ValueError, OverflowError):
                    return None
                db.execute("BEGIN IMMEDIATE")
                # Повторно читаем изменяемые поля после блокировки записи.
                current = db.execute(
                    "SELECT salt,rounds,password_hash,failures,blocked_until,active FROM users WHERE id=?",
                    (row["id"],),
                ).fetchone()
                if current is None or current["active"] != 1:
                    db.rollback()
                    return None
                # Не выдавать сеанс по старым учётным данным, если параллельно
                # завершилось восстановление пароля между чтением и транзакцией.
                try:
                    credentials_unchanged = (
                        bytes(current["salt"]) == salt
                        and current["rounds"] == rounds
                        and hmac.compare_digest(bytes(current["password_hash"]), stored)
                    )
                except (TypeError, ValueError):
                    credentials_unchanged = False
                if not credentials_unchanged:
                    db.rollback()
                    return None
                if current["blocked_until"] is not None and float(current["blocked_until"]) > now:
                    db.rollback()
                    return None
                if not password_ok:
                    failures = int(current["failures"]) + 1
                    blocked_until = now + self.BLOCK_SECONDS if failures >= self.MAX_FAILS else None
                    db.execute("UPDATE users SET failures=?, blocked_until=? WHERE id=?", (failures, blocked_until, row["id"]))
                    db.commit()
                    return None
                token = secrets.token_urlsafe(32)
                digest = self._token_hash(token)
                assert digest is not None
                db.execute("UPDATE users SET failures=0, blocked_until=NULL WHERE id=?", (row["id"],))
                db.execute("INSERT INTO sessions(token_hash,user_id,created,last_seen) VALUES(?,?,?,?)", (digest, row["id"], now, now))
                db.commit()
                return token
        except (sqlite3.DatabaseError, OSError, TypeError, ValueError, OverflowError):
            return None

    def resolve(self, token: str) -> int | None:
        """Подтвердить токен, обновить активность и вернуть серверный user_id."""
        digest = self._token_hash(token)
        if digest is None:
            return None
        now = self.clock()
        try:
            with closing(self._connect()) as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute(
                    "SELECT s.user_id,s.created,s.last_seen,u.active FROM sessions s "
                    "JOIN users u ON u.id=s.user_id WHERE s.token_hash=?", (digest,),
                ).fetchone()
                if row is None or row["active"] != 1:
                    db.rollback()
                    return None
                if now - float(row["created"]) >= self.ABSOLUTE_SECONDS or now - float(row["last_seen"]) >= self.IDLE_SECONDS:
                    db.execute("DELETE FROM sessions WHERE token_hash=?", (digest,))
                    db.commit()
                    return None
                db.execute("UPDATE sessions SET last_seen=? WHERE token_hash=?", (now, digest))
                db.commit()
                return int(row["user_id"])
        except (sqlite3.DatabaseError, OSError, TypeError, ValueError, OverflowError):
            return None

    def logout(self, token: str) -> bool:
        """Отозвать серверную запись сеанса; повторный выход безопасен."""
        digest = self._token_hash(token)
        if digest is None:
            return False
        try:
            with closing(self._connect()) as db:
                cursor = db.execute("DELETE FROM sessions WHERE token_hash=?", (digest,))
                return cursor.rowcount > 0
        except (sqlite3.DatabaseError, OSError):
            return False

    def reset_password(self, login: str, code: str, new_password: str) -> str | None:
        """Атомарно заменить пароль и резервный код и отозвать все сеансы."""
        try:
            normalized_login = self._normalize_login(login)
            password_bytes = self._password_bytes(new_password, new=True)
            if type(code) is not str or self.TOKEN_RE.fullmatch(code) is None:
                return None
            new_salt = secrets.token_bytes(16)
            new_password_hash = self._derive(password_bytes, new_salt, self.rounds)
            next_code = secrets.token_urlsafe(32)
            next_code_hash = hashlib.sha256(next_code.encode("ascii")).digest()
            old_code_hash = hashlib.sha256(code.encode("ascii")).digest()
            with closing(self._connect()) as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT id,recovery_hash,active FROM users WHERE login=?", (normalized_login,)).fetchone()
                if row is None or row["active"] != 1 or not hmac.compare_digest(bytes(row["recovery_hash"]), old_code_hash):
                    db.rollback()
                    return None
                db.execute(
                    "UPDATE users SET salt=?,rounds=?,password_hash=?,recovery_hash=?,failures=0,blocked_until=NULL WHERE id=?",
                    (new_salt, self.rounds, new_password_hash, next_code_hash, row["id"]),
                )
                db.execute("DELETE FROM sessions WHERE user_id=?", (row["id"],))
                db.commit()
                return next_code
        except (ValueError, TypeError, sqlite3.DatabaseError, OSError, UnicodeError):
            return None
