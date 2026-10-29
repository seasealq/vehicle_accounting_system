"""Дополнительные проверки индивидуального варианта 19, область Б."""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from app.authorization import AccessDenied, AccessService


class Variant19Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "variant.sqlite3"
        AccessService.initialize(self.path)
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA ignore_check_constraints = ON")
            db.executemany(
                "INSERT INTO users(id,login,salt,rounds,password_hash,recovery_hash,role,department_id) "
                "VALUES(?,?,x'00',1000,x'00',x'00',?,?)",
                [(1, "specialist", "specialist", "A"), (2, "otherdept", "specialist", "B"),
                 (3, "operator", "operator", "A"), (4, "admin", "admin", None)],
            )
            db.executemany(
                "INSERT INTO requests(id,title,description,category,priority,owner_id,status,department_id) "
                "VALUES(?,?,?,?,?,?,?,?)",
                [(101, "Closed A", "Closed request A description.", "access", 2, 1, "closed", "A"),
                 (102, "Closed B", "Closed request B description.", "access", 3, 2, "closed", "B"),
                 (103, "New A", "New request A description.", "access", 4, 1, "new", "A"),
                 (104, "Missing dept", "Request without department.", "access", 1, 1, "closed", None)],
            )
        self.sessions = {"sp-a": 1, "sp-b": 2, "op": 3, "admin": 4}
        self.service = AccessService(self.path, self.sessions.get)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def snapshot(self):
        with sqlite3.connect(self.path) as db:
            return tuple(db.execute("SELECT * FROM requests ORDER BY id")), tuple(db.execute("SELECT * FROM users ORDER BY id"))

    def denied_unchanged(self, action, error=AccessDenied):
        before = self.snapshot()
        with self.assertRaises(error):
            action()
        self.assertEqual(before, self.snapshot())

    def test_01_specialist_reopens_closed_request_in_own_department(self):
        self.service.reopen_request("sp-a", 101)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT status FROM requests WHERE id=101").fetchone()[0], "new")

    def test_02_specialist_cannot_reopen_another_department(self):
        self.denied_unchanged(lambda: self.service.reopen_request("sp-a", 102))

    def test_03_absent_department_never_grants_access(self):
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE users SET department_id=NULL WHERE id=1")
        self.denied_unchanged(lambda: self.service.reopen_request("sp-a", 101))
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE users SET department_id='A' WHERE id=1")
        self.denied_unchanged(lambda: self.service.reopen_request("sp-a", 104))

    def test_04_revoked_role_is_effective_with_same_session(self):
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE users SET role='user' WHERE id=1")
        self.denied_unchanged(lambda: self.service.reopen_request("sp-a", 101))

    def test_05_already_new_request_cannot_be_reopened(self):
        self.denied_unchanged(lambda: self.service.reopen_request("sp-a", 103))

    def test_06_operator_and_admin_do_not_inherit_specialist_permission(self):
        self.denied_unchanged(lambda: self.service.reopen_request("op", 101))
        self.denied_unchanged(lambda: self.service.reopen_request("admin", 101))

    def test_07_department_cannot_be_supplied_by_client(self):
        self.denied_unchanged(
            lambda: self.service.reopen_request("sp-a", 102, department_id="A"), TypeError
        )

    def test_08_nonexistent_request_is_denied_without_changes(self):
        self.denied_unchanged(lambda: self.service.reopen_request("sp-a", 999))


if __name__ == "__main__":
    unittest.main(verbosity=2)
