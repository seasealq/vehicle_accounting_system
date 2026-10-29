"""Двадцать базовых сценариев политики доступа v0.8."""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from app.authorization import AccessDenied, AccessService, InvalidTransition, allowed
from app.validation import ValidatedRequest


def request(title: str = "Учебная заявка", priority: int = 3) -> ValidatedRequest:
    return ValidatedRequest(
        title=title,
        description="Описание учебной заявки для проверки доступа.",
        category="software",
        priority=priority,
    )


class AuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "shared.sqlite3"
        AccessService.initialize(self.path)
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA ignore_check_constraints = ON")
            db.executemany(
                "INSERT INTO users(id,login,salt,rounds,password_hash,recovery_hash,active,role,department_id) "
                "VALUES(?,?,x'00',1000,x'00',x'00',?,?,?)",
                [
                    (1, "userone", 1, "user", "A"),
                    (2, "usertwo", 1, "user", "A"),
                    (3, "operator", 1, "operator", "A"),
                    (4, "adminone", 1, "admin", None),
                    (5, "inactive", 0, "user", "A"),
                    (6, "unknown", 1, "unknown", "A"),
                    (7, "admintwo", 1, "admin", None),
                    (8, "specialist", 1, "specialist", "A"),
                ],
            )
            db.executemany(
                "INSERT INTO requests(id,title,description,category,priority,owner_id,status,department_id) "
                "VALUES(?,?,?,?,?,?,?,?)",
                [
                    (101, "Заявка пользователя 1", "Описание заявки пользователя один.", "software", 3, 1, "new", "A"),
                    (102, "Заявка пользователя 2", "Описание заявки пользователя два.", "software", 4, 2, "new", "B"),
                    (103, "Закрытая заявка", "Описание закрытой заявки специалиста.", "access", 2, 2, "closed", "A"),
                    (104, "Старая заявка", "Описание исторической заявки.", "other", 1, None, "legacy", None),
                ],
            )
        self.sessions = {f"s{i}": i for i in range(1, 9)}
        self.service = AccessService(self.path, self.sessions.get)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def snapshot(self) -> tuple[tuple[tuple[object, ...], ...], tuple[tuple[object, ...], ...]]:
        with sqlite3.connect(self.path) as db:
            users = tuple(db.execute("SELECT * FROM users ORDER BY id"))
            requests = tuple(db.execute("SELECT * FROM requests ORDER BY id"))
        return users, requests

    def denied_unchanged(self, action, error=AccessDenied) -> None:
        before = self.snapshot()
        with self.assertRaises(error):
            action()
        self.assertEqual(before, self.snapshot())

    def test_01_owner_reads_own_request(self):
        self.assertEqual(self.service.read_request("s1", 101)["owner_id"], 1)

    def test_02_other_users_request_is_denied(self):
        self.denied_unchanged(lambda: self.service.read_request("s1", 102))

    def test_03_operator_reads_training_contour(self):
        self.assertEqual(self.service.read_request("s3", 102)["id"], 102)

    def test_04_operator_closes_new_request(self):
        self.service.close_request("s3", 101)
        self.assertEqual(self.service.read_request("s3", 101)["status"], "closed")

    def test_05_user_cannot_close_request(self):
        self.denied_unchanged(lambda: self.service.close_request("s1", 101))

    def test_06_owner_is_derived_from_confirmed_session(self):
        rid = self.service.create_request("s1", request())
        self.assertEqual(self.service.read_request("s1", rid)["owner_id"], 1)

    def test_07_owner_id_is_not_a_service_argument(self):
        self.denied_unchanged(
            lambda: self.service.create_request("s1", request(), owner_id=2),
            TypeError,
        )

    def test_08_admin_does_not_read_requests(self):
        self.denied_unchanged(lambda: self.service.read_request("s4", 101))

    def test_09_admin_assigns_operator(self):
        self.service.assign_role("s4", 2, "operator")
        self.assertEqual(self.service.read_request("s2", 101)["id"], 101)

    def test_10_user_cannot_assign_role(self):
        self.denied_unchanged(lambda: self.service.assign_role("s1", 2, "operator"))

    def test_11_operator_cannot_assign_role(self):
        self.denied_unchanged(lambda: self.service.assign_role("s3", 2, "user"))

    def test_12_admin_role_cannot_be_assigned(self):
        self.denied_unchanged(lambda: self.service.assign_role("s4", 2, "admin"))

    def test_13_existing_admin_account_cannot_be_changed(self):
        self.denied_unchanged(lambda: self.service.assign_role("s4", 7, "user"))

    def test_14_role_change_applies_to_existing_session(self):
        self.service.assign_role("s4", 3, "user")
        self.denied_unchanged(lambda: self.service.close_request("s3", 101))

    def test_15_invalid_and_revoked_sessions_are_denied(self):
        self.denied_unchanged(lambda: self.service.read_request("bad", 101))
        self.sessions.pop("s1")
        self.denied_unchanged(lambda: self.service.read_request("s1", 101))

    def test_16_inactive_account_is_denied(self):
        self.denied_unchanged(lambda: self.service.create_request("s5", request()))

    def test_17_unknown_role_is_denied(self):
        self.denied_unchanged(lambda: self.service.read_request("s6", 101))

    def test_18_unknown_permission_is_denied(self):
        self.assertFalse(allowed("admin", "request.export"))

    def test_19_missing_request_is_denied(self):
        self.denied_unchanged(lambda: self.service.read_request("s1", 999))

    def test_20_request_cannot_be_closed_twice(self):
        self.service.close_request("s3", 101)
        self.denied_unchanged(
            lambda: self.service.close_request("s3", 101), InvalidTransition
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
