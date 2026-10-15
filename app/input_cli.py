"""CLI для ограниченного приёма и проверки JSON через стандартный ввод."""

import json
import sys
from dataclasses import asdict

from app.validation import MAX_REQUEST_BYTES, ValidationError, validate_request


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    try:
        request = validate_request(raw)
    except ValidationError as error:
        print(json.dumps({"status": "rejected", "field": error.field, "message": error.message}, ensure_ascii=False))
        return 2
    print(json.dumps({"status": "accepted", "request": asdict(request)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
