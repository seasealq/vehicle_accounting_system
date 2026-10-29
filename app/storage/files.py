"""Файловое хранилище с непрозрачными ID и проверками формата."""

from __future__ import annotations

import os
import re
import secrets
import stat
from pathlib import Path

MAX_BYTES = 1_048_576
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_FILE_ID = re.compile(r"[0-9a-f]{32}\Z")


class FileValidationError(ValueError):
    """Вложение, ID или файловый объект не соответствует политике."""


def check_file(kind: str, data: bytes) -> None:
    if type(kind) is not str or kind not in {"log", "report", "screenshot", "vehicle_photo"}:
        raise FileValidationError("Категория запрещена")
    if type(data) is not bytes or not 0 < len(data) <= MAX_BYTES:
        raise FileValidationError("Размер или тип недопустим")
    if kind == "log":
        try:
            data.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise FileValidationError("Журнал должен быть UTF-8") from None
        if b"\x00" in data:
            raise FileValidationError("Нулевой байт в журнале запрещён")
    elif kind == "report" and not data.startswith(b"%PDF-"):
        raise FileValidationError("Не распознана сигнатура PDF")
    elif kind in {"screenshot", "vehicle_photo"} and not data.startswith(PNG_SIGNATURE):
        raise FileValidationError("Не распознана сигнатура PNG")


class FileStore:
    """Хранилище. Его каталог и родительские каталоги должны быть доверенными."""

    def __init__(self, root: Path) -> None:
        root = Path(root)
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root = root.resolve(strict=True)
        if not self.root.is_dir():
            raise ValueError("Корень хранилища не является каталогом")
        os.chmod(self.root, 0o700)

    @staticmethod
    def _name(file_id: str) -> str:
        if type(file_id) is not str or _FILE_ID.fullmatch(file_id) is None:
            raise FileValidationError("Неверный идентификатор")
        return f"{file_id}.bin"

    def _open_root(self) -> int:
        required = ("O_NOFOLLOW", "O_DIRECTORY")
        if any(not hasattr(os, flag) for flag in required) or os.open not in os.supports_dir_fd:
            raise FileValidationError("ОС не предоставляет безопасное открытие каталога")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(self.root, flags)
        except OSError:
            raise FileValidationError("Не удалось безопасно открыть хранилище") from None
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise FileValidationError("Корень хранилища не является каталогом")
        return descriptor

    def save(self, kind: str, data: bytes) -> str:
        check_file(kind, data)
        root_fd = self._open_root()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        try:
            for _ in range(5):
                file_id = secrets.token_hex(16)
                name = self._name(file_id)
                try:
                    descriptor = os.open(name, flags, 0o600, dir_fd=root_fd)
                except FileExistsError:
                    continue
                try:
                    with os.fdopen(descriptor, "wb") as stream:
                        stream.write(data)
                except BaseException:
                    try:
                        os.unlink(name, dir_fd=root_fd)
                    except FileNotFoundError:
                        pass
                    raise
                return file_id
            raise RuntimeError("Не удалось создать уникальное имя файла")
        finally:
            os.close(root_fd)

    def read(self, file_id: str) -> bytes:
        name = self._name(file_id)
        root_fd = self._open_root()
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        try:
            try:
                descriptor = os.open(name, flags, dir_fd=root_fd)
            except OSError:
                raise FileValidationError("Файл отсутствует или не может быть безопасно открыт") from None
        finally:
            os.close(root_fd)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_BYTES:
                raise FileValidationError("Недопустимый файловый объект или размер")
            data = stream.read(MAX_BYTES + 1)
            if not 0 < len(data) <= MAX_BYTES:
                raise FileValidationError("Недопустимый размер файла")
            return data

    def remove(self, file_id: str) -> None:
        name = self._name(file_id)
        root_fd = self._open_root()
        try:
            try:
                os.unlink(name, dir_fd=root_fd)
            except FileNotFoundError:
                pass
        finally:
            os.close(root_fd)
