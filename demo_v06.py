"""Демонстрация цепочки валидации, FileStore и SQLite."""

import json
import tempfile
from pathlib import Path

from app.repositories.requests import RequestRepository
from app.security.process import safe_argument
from app.services.request_service import RequestService
from app.storage.files import FileStore
from app.validation import validate_request


def main() -> None:
    payload = {
        "title": "Ошибка сетевого сервиса",
        "description": "На сервере обнаружены неполадки, требуется диагностика.",
        "category": "network",
        "priority": 3,
        "reporter_ip": "192.0.2.10",
        "attachment_key": "log",
    }
    request = validate_request(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
    content = b"INFO Service started\n"

    with tempfile.TemporaryDirectory(prefix="vehicle-accounting-v06-") as temporary:
        root = Path(temporary)
        repository = RequestRepository(root / "data" / "requests.sqlite3")
        repository.initialize()
        files = FileStore(root / "private_data" / "attachments")
        service = RequestService(repository, files)
        request_id = service.submit(request, content)
        stored = repository.get(request_id)
        print("ID заявки:", request_id)
        print("Ключ вложения:", stored["attachment_key"])
        print("Содержимое совпадает:", files.read(stored["file_id"]) == content)
        print("Аргумент процесса:", safe_argument("example; echo TEST"))


if __name__ == "__main__":
    main()
