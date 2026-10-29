"""Интеграция авторизации с реальным AuthService и аддитивная миграция."""

import sqlite3
import json
import tempfile
import unittest
from pathlib import Path

from app.auth import AuthService
from app.authorization import AccessDenied, AccessService
from app.repositories.requests import RequestRepository
from app.storage.files import FileStore
from app.validation import ValidatedRequest
from app.validation import ValidationError, validate_request


def valid_request(title: str) -> ValidatedRequest:
    return ValidatedRequest(
        title=title,
        description="Тестовое описание обращения для интеграционного сценария.",
        category="access",
        priority=2,
    )


class AuthorizationIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "integrated.sqlite3"
        self.now = [1_800_000_000.0]
        self.auth = AuthService(self.path, clock=lambda: self.now[0], rounds=1_000)
        self.auth.initialize()
        self.requests = RequestRepository(self.path)
        self.requests.initialize()
        self.access = AccessService(self.path, self.auth.resolve)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _user_id(self, login: str) -> int:
        with sqlite3.connect(self.path) as db:
            row = db.execute("SELECT id FROM users WHERE login = ?", (login,)).fetchone()
        assert row is not None
        return int(row[0])

    def test_real_auth_roles_objects_revoke_expiry_and_disable(self):
        self.auth.register("ownerone", "LongTrainingPassphraseOne!")
        self.auth.register("ownertwo", "LongTrainingPassphraseTwo!")
        self.auth.register("ownertre", "LongTrainingPassphraseThree!")
        id1, id2, id3 = (self._user_id(name) for name in ("ownerone", "ownertwo", "ownertre"))
        token1 = self.auth.login("ownerone", "LongTrainingPassphraseOne!")
        token2 = self.auth.login("ownertwo", "LongTrainingPassphraseTwo!")
        token3 = self.auth.login("ownertre", "LongTrainingPassphraseThree!")
        self.assertTrue(token1 and token2 and token3)
        with sqlite3.connect(self.path) as db:
            # Доверенная подготовка тестового контура, не публичный метод.
            db.execute("UPDATE users SET role='admin' WHERE id=?", (id3,))

        first = self.access.create_request(token1, valid_request("Заявка владельца один"))
        second = self.access.create_request(token2, valid_request("Заявка владельца два"))
        self.assertEqual(self.access.read_request(token1, first)["owner_id"], id1)
        self.assertEqual(self.access.read_request(token2, second)["owner_id"], id2)
        with self.assertRaises(AccessDenied):
            self.access.read_request(token1, second)

        self.access.assign_role(token3, id1, "operator")
        self.assertEqual(self.access.read_request(token1, second)["id"], second)
        self.access.close_request(token1, second)
        self.access.assign_role(token3, id1, "user")
        self.assertIsNotNone(self.auth.resolve(token1))
        with self.assertRaises(AccessDenied):
            self.access.close_request(token1, first)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT status FROM requests WHERE id=?", (first,)).fetchone()[0], "new")
            db.execute("UPDATE users SET role='specialist', department_id='DEP-A' WHERE id=?", (id1,))
            db.execute(
                "UPDATE requests SET status='closed', department_id='DEP-A' WHERE id=?", (first,)
            )
        self.access.reopen_request(token1, first)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT status FROM requests WHERE id=?", (first,)).fetchone()[0], "new")
        self.access.assign_role(token3, id1, "user")
        with self.assertRaises(AccessDenied):
            self.access.reopen_request(token1, first)

        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE users SET active=0 WHERE id=?", (id2,))
        with self.assertRaises(AccessDenied):
            self.access.read_request(token2, second)
        self.assertTrue(self.auth.logout(token2))
        with self.assertRaises(AccessDenied):
            self.access.read_request(token2, second)
        self.now[0] += AuthService.ABSOLUTE_SECONDS + 1
        self.assertIsNone(self.auth.resolve(token3))
        with self.assertRaises(AccessDenied):
            self.access.assign_role(token3, id1, "operator")

    def test_v07_and_v06_schema_migration_preserves_rows_and_credentials(self):
        old = Path(self.temp.name) / "old.sqlite3"
        with sqlite3.connect(old) as db:
            db.executescript(
                """CREATE TABLE users (
                    id INTEGER PRIMARY KEY, login TEXT NOT NULL UNIQUE, salt BLOB NOT NULL,
                    rounds INTEGER NOT NULL, password_hash BLOB NOT NULL, recovery_hash BLOB NOT NULL,
                    failures INTEGER NOT NULL DEFAULT 0, blocked_until REAL,
                    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1))
                );
                CREATE TABLE sessions (
                    token_hash BLOB PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
                    created REAL NOT NULL, last_seen REAL NOT NULL
                );
                CREATE TABLE requests (
                    id INTEGER PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL,
                    category TEXT NOT NULL, priority INTEGER NOT NULL, reporter_ip TEXT,
                    attachment_key TEXT, file_id TEXT UNIQUE
                );"""
            )
            db.execute(
                "INSERT INTO users VALUES(1,'existing',x'0102',600000,x'0304',x'0506',0,NULL,1)"
            )
            db.execute("INSERT INTO sessions VALUES(x'0708',1,10,11)")
            db.execute(
                "INSERT INTO requests VALUES(9,'Старая заявка','Существующее описание достаточно длинное',"
                "'software',4,NULL,'vehicle_photo','0123456789abcdef0123456789abcdef')"
            )

        old_auth = AuthService(old, rounds=1_000)
        old_auth.initialize()
        RequestRepository(old).initialize()
        AccessService.initialize(old)
        with sqlite3.connect(old) as db:
            user = db.execute(
                "SELECT salt,rounds,password_hash,recovery_hash,role,department_id FROM users WHERE id=1"
            ).fetchone()
            session = db.execute("SELECT token_hash,user_id,created,last_seen FROM sessions").fetchone()
            request_row = db.execute("SELECT * FROM requests WHERE id=9").fetchone()
            request_columns = {row[1] for row in db.execute("PRAGMA table_info(requests)")}
        self.assertEqual(user, (b"\x01\x02", 600_000, b"\x03\x04", b"\x05\x06", "user", None))
        self.assertEqual(session, (b"\x07\x08", 1, 10.0, 11.0))
        self.assertEqual(request_row[1:8], ("Старая заявка", "Существующее описание достаточно длинное", "software", 4, None, "vehicle_photo", "0123456789abcdef0123456789abcdef"))
        self.assertIsNone(request_row[8])  # owner_id remains unknown, never fabricated
        self.assertEqual(request_row[9], "legacy")
        self.assertIsNone(request_row[10])
        self.assertTrue({"title", "description", "category", "priority", "attachment_key", "file_id", "owner_id", "status", "department_id"} <= request_columns)

    def test_client_cannot_supply_server_owned_fields(self):
        payload = {
            "title": "Заявка с подменой",
            "description": "Тестовое описание запроса с лишними атрибутами.",
            "category": "access",
            "priority": 2,
            "owner_id": 999,
            "role": "admin",
            "active": 1,
            "department_id": "A",
        }
        with self.assertRaises(ValidationError):
            validate_request(json.dumps(payload, ensure_ascii=False).encode("utf-8"))

    def test_authorized_creation_preserves_vehicle_photo_file_store(self):
        self.auth.register("photouser", "LongTrainingPassphrasePhoto!")
        token = self.auth.login("photouser", "LongTrainingPassphrasePhoto!")
        self.assertIsNotNone(token)
        files = FileStore(Path(self.temp.name) / "attachments")
        access = AccessService(self.path, self.auth.resolve, files=files)
        item = ValidatedRequest(
            title="Фотография транспорта",
            description="Искусственное описание файла для теста FileStore.",
            category="other",
            priority=2,
            attachment_key="vehicle_photo",
        )
        contents = b"\x89PNG\r\n\x1a\nsynthetic"
        request_id = access.create_request(token, item, contents)
        stored = self.requests.get(request_id)
        self.assertEqual(stored["attachment_key"], "vehicle_photo")
        self.assertEqual(files.read(stored["file_id"]), contents)


if __name__ == "__main__":
    unittest.main(verbosity=2)
