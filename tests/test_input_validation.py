"""Обязательные сценарии безопасной обработки JSON (ЛР5)."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from app.validation import MAX_REQUEST_BYTES, ValidationError, validate_request


def payload(**changes: object) -> bytes:
    data: dict[str, object] = {
        "title": "Сбой учёта",
        "description": "При обработке сведений о транспортном средстве возникла ошибка.",
        "category": "network",
        "priority": 3,
    }
    data.update(changes)
    return json.dumps(data, ensure_ascii=False).encode("utf-8")


def reject(raw: bytes, field: str | None = None) -> ValidationError:
    with pytest.raises(ValidationError) as caught:
        validate_request(raw)
    source_text = raw.decode("utf-8", errors="ignore")
    assert not source_text or source_text not in str(caught.value)
    if field:
        assert caught.value.field == field
    return caught.value


def test_01_valid_request_is_accepted() -> None:
    assert validate_request(payload()).priority == 3


def test_02_missing_required_field_is_rejected() -> None:
    reject(b'{"title":"Valid","description":"A sufficiently long description","category":"other"}')


def test_03_unknown_field_is_rejected() -> None:
    reject(payload(is_admin=True))


def test_04_short_title_is_rejected() -> None:
    reject(payload(title="Test"), "title")


def test_05_long_description_is_rejected() -> None:
    reject(payload(description="x" * 2001), "description")


def test_06_unknown_category_is_rejected() -> None:
    reject(payload(category="vehicle"), "category")


@pytest.mark.parametrize("value", [0, -1])
def test_07_priority_below_range_is_rejected(value: int) -> None:
    reject(payload(priority=value), "priority")


def test_08_priority_above_range_is_rejected() -> None:
    reject(payload(priority=6), "priority")


def test_09_string_priority_is_rejected() -> None:
    reject(payload(priority="3"), "priority")


def test_10_boolean_priority_is_rejected() -> None:
    reject(payload(priority=True), "priority")


def test_11_invalid_ip_is_rejected() -> None:
    reject(payload(reporter_ip="999.1.1.1"), "reporter_ip")


def test_12_unknown_attachment_is_rejected() -> None:
    reject(payload(attachment_key="archive"), "attachment_key")


def test_13_path_instead_of_attachment_key_is_rejected() -> None:
    reject(payload(attachment_key="../secret"), "attachment_key")


def test_14_malformed_json_is_rejected() -> None:
    reject(b'{"title":')


def test_15_request_over_limit_is_rejected_before_json_parse() -> None:
    reject(b"{" + b" " * MAX_REQUEST_BYTES)


def test_16_duplicate_keys_are_rejected_even_when_nested() -> None:
    reject(b'{"title":"Valid title","description":"Long enough description here","category":"other","priority":2,"extra":{"x":1,"x":2}}')


def test_17_control_character_is_rejected() -> None:
    reject(payload(title="Valid\x01title"), "title")


def test_18_valid_ipv6_is_accepted() -> None:
    assert validate_request(payload(reporter_ip="2001:db8::1")).reporter_ip == "2001:db8::1"


def test_19_canonically_equivalent_unicode_is_normalized() -> None:
    result = validate_request(payload(title="Cafe\u0301 issue"))
    assert result.title == "Café issue"


def test_20_html_like_text_is_preserved_as_text() -> None:
    result = validate_request(payload(description="Текст <script>alert('test')</script> остаётся обычным описанием."))
    assert "<script>" in result.description


def test_variant_19_vehicle_photo_is_allowed() -> None:
    assert validate_request(payload(attachment_key="vehicle_photo")).attachment_key == "vehicle_photo"


def test_variant_19_unknown_attachment_type_is_rejected() -> None:
    reject(payload(attachment_key="vehicle_video"), "attachment_key")


def test_variant_19_filename_instead_of_key_is_rejected() -> None:
    reject(payload(attachment_key="vehicle_photo.jpg"), "attachment_key")


@pytest.mark.parametrize("raw", [b"", b"[]", b"null", b"\xff", b'{"title":"x","title":"y"}', b'{"priority":NaN}', b'{"priority":Infinity}'])
def test_malformed_and_non_object_requests_fail_safely(raw: bytes) -> None:
    reject(raw)


def test_optional_fields_can_be_absent_and_request_is_immutable() -> None:
    from dataclasses import FrozenInstanceError

    request = validate_request(payload())
    assert request.reporter_ip is None and request.attachment_key is None
    with pytest.raises(FrozenInstanceError):
        request.priority = 4  # type: ignore[misc]


def test_exact_byte_limit_with_trailing_json_whitespace_is_accepted() -> None:
    raw = payload()
    raw += b" " * (MAX_REQUEST_BYTES - len(raw))
    assert len(raw) == MAX_REQUEST_BYTES
    assert validate_request(raw).priority == 3


def test_text_length_boundaries_are_accepted() -> None:
    assert len(validate_request(payload(title="12345", description="x" * 20)).title) == 5
    assert len(validate_request(payload(title="x" * 100, description="x" * 2000)).description) == 2000


def test_deeply_nested_json_fails_with_controlled_error() -> None:
    reject(b"{" + b'"x":[' * 2000 + b"0" + b"]" * 2000 + b"}")


def test_non_bytes_message_is_rejected() -> None:
    with pytest.raises(ValidationError) as caught:
        validate_request("{}")  # type: ignore[arg-type]
    assert caught.value.field == "request"


def test_newline_allowed_only_in_description_and_crlf_is_normalized() -> None:
    request = validate_request(payload(description="Первая строка описания.\r\nВторая строка."))
    assert "\r" not in request.description and "\n" in request.description
    reject(payload(title="Первая\nстрока"), "title")


@pytest.mark.parametrize("value", [None, 1.5, -1.5, True])
def test_non_integer_priorities_fail(value: object) -> None:
    reject(payload(priority=value), "priority")


def test_ipv6_zone_and_surrogate_are_rejected() -> None:
    reject(payload(reporter_ip="fe80::1%en0"), "reporter_ip")
    reject(b'{"title":"\\ud800title","description":"Long enough description here","category":"other","priority":1}', "title")


def test_unknown_field_diagnostic_does_not_echo_user_content() -> None:
    secret = "do-not-echo-this-secret"
    error = reject(payload(secret_field=secret))
    assert secret not in error.message


@pytest.mark.parametrize(
    ("example", "status", "code"),
    [
        ("valid.json", "accepted", 0),
        ("valid_vehicle_photo.json", "accepted", 0),
        ("invalid_priority.json", "rejected", 2),
        ("invalid_attachment.json", "rejected", 2),
    ],
)
def test_real_cli_entrypoint(example: str, status: str, code: int) -> None:
    root = Path(__file__).resolve().parents[1]
    raw = (root / "examples" / "lab5" / example).read_bytes()
    result = subprocess.run(
        [sys.executable, "-m", "app.input_cli"],
        input=raw,
        capture_output=True,
        cwd=root,
        check=False,
    )
    assert result.returncode == code
    assert json.loads(result.stdout)["status"] == status
    assert result.stderr == b""
