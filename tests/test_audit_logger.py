import logging

import pytest

from app.audit.audit_logger import log_security_event


def test_audit_rejects_untrusted_multiline_identifier(caplog: pytest.LogCaptureFixture) -> None:
    logger = logging.getLogger("test.audit.validation")
    caplog.set_level(logging.INFO, logger=logger.name)
    with pytest.raises(ValueError):
        log_security_event(
            logger,
            subject_id="driver-01\nAPP_SECRET_KEY=hidden",
            action="trip.read",
            object_id="TRIP-001",
            result="denied",
        )
    assert caplog.text == ""


def test_audit_accepts_only_known_actions_and_results() -> None:
    logger = logging.getLogger("test.audit.values")
    with pytest.raises(ValueError):
        log_security_event(
            logger,
            subject_id="driver-01",
            action="unknown.action",
            object_id=None,
            result="allowed",
        )
