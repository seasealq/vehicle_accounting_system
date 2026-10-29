"""Позитивные и негативные проверки работы с SQLite и файлами."""

import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.repositories.requests import RequestRepository
from app.security.process import safe_argument
from app.services.request_service import RequestService
from app.storage.files import FileStore, FileValidationError, MAX_BYTES, PNG_SIGNATURE
from app.validation import ValidatedRequest, validate_request


def request(title="Ошибка сетевого сервиса", kind=None):
    data = {
        "title": title,
        "description": "На сервере обнаружены неполадки, требуется диагностика.",
        "category": "network",
        "priority": 3,
        "reporter_ip": "192.0.2.10",
    }
    if kind is not None:
        data["attachment_key"] = kind
    raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
    return validate_request(raw)


class TestV06(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = RequestRepository(self.root / "data" / "requests.sqlite3")
        self.repo.initialize()
        self.files = FileStore(self.root / "private")

    def test_01_add_read(self):
        request_id = self.repo.add(request())
        self.assertEqual(self.repo.get(request_id)["category"], "network")

    def test_02_change_priority(self):
        request_id = self.repo.add(request())
        self.assertTrue(self.repo.set_priority(request_id, 5))
        self.assertEqual(self.repo.get(request_id)["priority"], 5)

    def test_03_delete_unattached(self):
        request_id = self.repo.add(request())
        self.assertTrue(self.repo.delete_unattached(request_id))
        self.assertIsNone(self.repo.get(request_id))

    def test_04_sql_like_title_is_data(self):
        value = "' OR 1=1 --"
        request_id = self.repo.add(request(value))
        self.repo.add(request())
        self.assertEqual(self.repo.get(request_id)["title"], value)
        self.assertEqual(len(self.repo.list_category("network")), 2)

    def test_05_unknown_sort_is_rejected(self):
        with self.assertRaises(ValueError):
            self.repo.list_category("network", sort="id; DROP TABLE requests")

    def test_06_unknown_category_is_rejected(self):
        with self.assertRaises(ValueError):
            self.repo.list_category("network OR 1=1")

    def test_07_boolean_priority_is_rejected(self):
        with self.assertRaises(ValueError):
            self.repo.set_priority(1, True)

    def test_08_limit_over_100_is_rejected(self):
        with self.assertRaises(ValueError):
            self.repo.list_category("network", limit=101)

    def test_09_file_round_trip(self):
        file_id = self.files.save("log", b"INFO start\n")
        self.assertEqual(self.files.read(file_id), b"INFO start\n")

    def test_10_file_over_limit_is_rejected(self):
        with self.assertRaises(FileValidationError):
            self.files.save("log", b"a" * (MAX_BYTES + 1))

    def test_11_unknown_file_kind_is_rejected(self):
        with self.assertRaises(FileValidationError):
            self.files.save("exe", b"hello")

    def test_12_bad_pdf_signature_is_rejected(self):
        with self.assertRaises(FileValidationError):
            self.files.save("report", b"bad")

    def test_13_path_like_file_id_is_rejected(self):
        with self.assertRaises(FileValidationError):
            self.files.read("../secret")

    def test_14_invalid_utf8_log_is_rejected(self):
        with self.assertRaises(FileValidationError):
            self.files.save("log", b"\xff")

    def test_15_repository_failure_compensates_file_save(self):
        service = RequestService(self.repo, self.files)
        with patch.object(self.repo, "add", side_effect=sqlite3.IntegrityError):
            with self.assertRaises(sqlite3.IntegrityError):
                service.submit(request("Ошибка сетевого сервиса", "log"), b"LOG\n")
        self.assertEqual(list(self.files.root.iterdir()), [])

    def test_16_delete_attached_request_is_rejected(self):
        request_id = self.repo.add(request(kind="log"), "a" * 32)
        self.assertFalse(self.repo.delete_unattached(request_id))
        self.assertIsNotNone(self.repo.get(request_id))

    def test_17_bool_and_nonpositive_ids_are_rejected(self):
        for request_id in (True, 0, -1):
            with self.subTest(request_id=request_id), self.assertRaises(ValueError):
                self.repo.get(request_id)

    def test_18_file_id_must_match_attachment_presence(self):
        with self.assertRaises(ValueError):
            self.repo.add(request(kind="log"))
        with self.assertRaises(ValueError):
            self.repo.add(request(), "a" * 32)

    def test_19_vehicle_photo_png_signature_is_preserved(self):
        content = PNG_SIGNATURE + b"limited-signature-check"
        file_id = self.files.save("vehicle_photo", content)
        request_id = self.repo.add(request(kind="vehicle_photo"), file_id)
        self.assertEqual(self.repo.get(request_id)["attachment_key"], "vehicle_photo")
        self.assertEqual(self.files.read(file_id), content)

    def test_20_vehicle_photo_rejects_non_png_signature(self):
        with self.assertRaises(FileValidationError):
            self.files.save("vehicle_photo", b"\xff\xd8\xffjpeg")

    @unittest.skipUnless(hasattr(os, "symlink") and hasattr(os, "O_NOFOLLOW"), "Нужна поддержка symlink и O_NOFOLLOW")
    def test_21_variant19_read_rejects_symlink_to_external_file(self):
        outside = self.root / "outside.txt"
        outside.write_bytes(b"outside")
        os.symlink(outside, self.files.root / ("a" * 32 + ".bin"))
        with self.assertRaises(FileValidationError):
            self.files.read("a" * 32)

    @unittest.skipUnless(hasattr(os, "symlink") and hasattr(os, "O_NOFOLLOW"), "Нужна поддержка symlink и O_NOFOLLOW")
    def test_22_variant19_exclusive_save_does_not_overwrite_symlink_target(self):
        outside = self.root / "outside.txt"
        outside.write_bytes(b"untouched")
        first, second = "a" * 32, "b" * 32
        os.symlink(outside, self.files.root / f"{first}.bin")
        with patch("app.storage.files.secrets.token_hex", side_effect=[first, second]):
            file_id = self.files.save("log", b"owned")
        self.assertEqual(file_id, second)
        self.assertEqual(outside.read_bytes(), b"untouched")

    @unittest.skipUnless(hasattr(os, "symlink") and hasattr(os, "O_NOFOLLOW"), "Нужна поддержка symlink и O_NOFOLLOW")
    def test_23_variant19_rejects_storage_root_symlink_replacement(self):
        original = self.files.root
        moved = self.root / "moved-private"
        original.rename(moved)
        os.symlink(self.root, original)
        with self.assertRaises(FileValidationError):
            self.files.save("log", b"must not escape")

    def test_24_list_category_applies_limit_and_allowlisted_priority_sort(self):
        self.repo.add(request("Первое обращение"))
        self.repo.add(request("Второе обращение"))
        self.repo.set_priority(1, 5)
        rows = self.repo.list_category("network", sort="priority", limit=1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["priority"], 5)

    def test_25_safe_argument_keeps_shell_metacharacters_as_data(self):
        value = "example; echo TEST"
        self.assertEqual(safe_argument(value), repr(value))

    def test_26_safe_argument_rejects_invalid_type_and_length(self):
        for value in (True, "x" * 201, "bad\x00value"):
            with self.subTest(value=type(value).__name__), self.assertRaises(ValueError):
                safe_argument(value)

    def test_27_database_check_rejects_orphan_or_invalid_file_id(self):
        values = (("log", None), ("log", "z" * 32), (None, "a" * 32))
        for attachment_key, file_id in values:
            with self.subTest(attachment_key=attachment_key, file_id=file_id):
                with self.repo.connect() as connection, self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        """INSERT INTO requests
                           (title, description, category, priority, attachment_key, file_id)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        ("Ошибка сетевого сервиса",
                         "На сервере обнаружены неполадки, требуется диагностика.",
                         "network", 3, attachment_key, file_id),
                    )

    def test_28_empty_file_is_rejected(self):
        with self.assertRaises(FileValidationError):
            self.files.save("log", b"")


if __name__ == "__main__":
    unittest.main()
