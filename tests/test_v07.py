"""Изолированные проверки подсистемы аутентификации v0.7."""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from app.auth import AuthService


GOOD = "Correct horse battery staple 42"
NEW = "Another correct password 84"


class FakeClock:
    def __init__(self):
        self.value = 1_000.0

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


class AuthServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.clock = FakeClock()
        self.auth = AuthService(Path(self.temp.name) / "users.sqlite3", clock=self.clock, rounds=1000)
        self.auth.initialize()
        self.code = self.auth.register("Student_1", GOOD)

    def tearDown(self):
        self.temp.cleanup()

    def test_01_correct_password_and_server_user_id(self):
        token = self.auth.login("student_1", GOOD)
        self.assertIsNotNone(token)
        self.assertEqual(self.auth.resolve(token), 1)

    def test_02_wrong_password_rejected(self):
        self.assertIsNone(self.auth.login("student_1", NEW))

    def test_03_duplicate_normalized_login_rejected(self):
        with self.assertRaises(ValueError):
            self.auth.register("STUDENT_1", NEW)

    def test_04_same_password_uses_different_salts(self):
        self.auth.register("student_2", GOOD)
        with sqlite3.connect(self.auth.database) as db:
            salts = [row[0] for row in db.execute("SELECT salt FROM users ORDER BY id")]
        self.assertNotEqual(salts[0], salts[1])

    def test_05_database_does_not_contain_password(self):
        raw = self.auth.database.read_bytes()
        self.assertNotIn(GOOD.encode(), raw)
        with sqlite3.connect(self.auth.database) as db:
            stored = db.execute("SELECT password_hash FROM users").fetchone()[0]
        self.assertNotEqual(stored, GOOD.encode())

    def test_06_short_password_rejected(self):
        with self.assertRaises(ValueError):
            self.auth.register("student_2", "short")

    def test_07_spaces_are_significant(self):
        token = self.auth.login("student_1", " " + GOOD)
        self.assertIsNone(token)

    def test_08_unknown_login_rejected(self):
        self.assertIsNone(self.auth.login("nobody_1", GOOD))

    def test_09_five_failures_block_account(self):
        for _ in range(5):
            self.assertIsNone(self.auth.login("student_1", NEW))
        self.assertIsNone(self.auth.login("student_1", GOOD))

    def test_10_block_expires_at_exact_boundary(self):
        for _ in range(5):
            self.auth.login("student_1", NEW)
        self.clock.advance(60)
        self.assertIsNotNone(self.auth.login("student_1", GOOD))

    def test_11_logout_revokes_session(self):
        token = self.auth.login("student_1", GOOD)
        self.assertTrue(self.auth.logout(token))
        self.assertIsNone(self.auth.resolve(token))

    def test_12_idle_expiration_at_exact_boundary(self):
        token = self.auth.login("student_1", GOOD)
        self.clock.advance(900)
        self.assertIsNone(self.auth.resolve(token))

    def test_13_absolute_expiration_at_exact_boundary(self):
        token = self.auth.login("student_1", GOOD)
        self.clock.advance(3600)
        self.assertIsNone(self.auth.resolve(token))

    def test_14_recovery_revokes_sessions_and_replaces_code(self):
        token = self.auth.login("student_1", GOOD)
        replacement = self.auth.reset_password("student_1", self.code, NEW)
        self.assertIsNotNone(replacement)
        self.assertIsNone(self.auth.resolve(token))
        self.assertIsNone(self.auth.reset_password("student_1", self.code, GOOD))
        self.assertIsNone(self.auth.login("student_1", GOOD))
        self.assertIsNotNone(self.auth.login("student_1", NEW))

    def test_15_invalid_recovery_does_not_change_account(self):
        token = self.auth.login("student_1", GOOD)
        self.assertIsNone(self.auth.reset_password("student_1", "bad", NEW))
        self.assertEqual(self.auth.resolve(token), 1)
        self.assertIsNotNone(self.auth.login("student_1", GOOD))

    # Вариант 19: контролируемое злоупотребление блокировкой чужой учётной записи.
    def test_16_variant_owner_can_login_before_attack(self):
        self.assertIsNotNone(self.auth.login("student_1", GOOD))

    def test_17_variant_other_actor_can_block_known_login(self):
        for _ in range(5):
            self.auth.login("student_1", NEW)
        self.assertIsNone(self.auth.login("student_1", GOOD))

    def test_18_variant_availability_returns_after_block(self):
        for _ in range(5):
            self.auth.login("student_1", NEW)
        self.clock.advance(60)
        self.assertIsNotNone(self.auth.login("student_1", GOOD))

    def test_19_unicode_nfc_and_password_length_edges(self):
        decomposed, composed = "Cafe\u0301 and a strong password", "Caf\u00e9 and a strong password"
        self.auth.register("unicode_1", decomposed)
        self.assertIsNotNone(self.auth.login("unicode_1", composed))
        self.auth.register("minlen_1", "a" * 15)
        self.auth.register("maxlen_1", "b" * 128)
        with self.assertRaises(ValueError):
            self.auth.register("toolong_1", "b" * 129)

    def test_20_utf8_byte_limit_and_weak_list(self):
        with self.assertRaises(ValueError):
            self.auth.register("utf8_1", "é" * 513)
        with self.assertRaises(ValueError):
            self.auth.register("weak_1", "password123456789")

    def test_21_login_casefold_and_strict_types(self):
        self.assertIsNotNone(self.auth.login("STUDENT_1", GOOD))
        with self.assertRaises(ValueError):
            self.auth.register(17, GOOD)
        self.assertIsNone(self.auth.login("student_1", 17))

    def test_22_invalid_tokens_and_hash_only_storage(self):
        token = self.auth.login("student_1", GOOD)
        self.assertIsNone(self.auth.resolve("bad"))
        self.assertIsNone(self.auth.resolve(None))
        raw = self.auth.database.read_bytes()
        self.assertNotIn(token.encode(), raw)

    def test_23_recovery_code_hash_only_and_single_use(self):
        raw = self.auth.database.read_bytes()
        self.assertNotIn(self.code.encode(), raw)
        self.assertIsNotNone(self.auth.reset_password("student_1", self.code, NEW))
        self.assertIsNone(self.auth.reset_password("student_1", self.code, GOOD))

    def test_24_unchanged_account_is_not_locked_by_other_account_failures(self):
        self.auth.register("other_1", NEW)
        for _ in range(5):
            self.auth.login("student_1", NEW)
        self.assertIsNotNone(self.auth.login("other_1", NEW))

    def test_25_success_resets_failure_counter(self):
        for _ in range(4):
            self.auth.login("student_1", NEW)
        self.auth.login("student_1", GOOD)
        for _ in range(4):
            self.auth.login("student_1", NEW)
        self.assertIsNotNone(self.auth.login("student_1", GOOD))

    def test_26_idle_window_refreshes_on_resolution(self):
        token = self.auth.login("student_1", GOOD)
        self.clock.advance(899)
        self.assertEqual(self.auth.resolve(token), 1)
        self.clock.advance(899)
        self.assertEqual(self.auth.resolve(token), 1)

    def test_27_recovery_does_not_create_a_session(self):
        self.auth.reset_password("student_1", self.code, NEW)
        with sqlite3.connect(self.auth.database) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM sessions").fetchone()[0], 0)

    def test_28_corrupted_password_record_fails_closed(self):
        with sqlite3.connect(self.auth.database) as db:
            db.execute("UPDATE users SET salt=? WHERE login=?", (b"short", "student_1"))
        self.assertIsNone(self.auth.login("student_1", GOOD))

    def test_29_lockout_does_not_revoke_existing_session(self):
        token = self.auth.login("student_1", GOOD)
        for _ in range(5):
            self.auth.login("student_1", NEW)
        self.assertEqual(self.auth.resolve(token), 1)


if __name__ == "__main__":
    unittest.main()
