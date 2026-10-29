"""Сквозное сохранение проверенного обращения и его вложения."""

from app.repositories.requests import RequestRepository
from app.storage.files import FileStore
from app.validation import ValidatedRequest


class RequestService:
    def __init__(self, repository: RequestRepository, files: FileStore) -> None:
        self.repository = repository
        self.files = files

    def submit(self, request: ValidatedRequest, content: bytes | None = None) -> int:
        if not isinstance(request, ValidatedRequest):
            raise TypeError("Нужен объект ValidatedRequest")
        if request.attachment_key is None:
            if content is not None:
                raise ValueError("Для заявки без вложения содержимое не допускается")
            return self.repository.add(request)
        if content is None:
            raise ValueError("Для указанного вложения требуется содержимое")

        file_id = self.files.save(request.attachment_key, content)
        try:
            return self.repository.add(request, file_id)
        except Exception:
            self.files.remove(file_id)
            raise
