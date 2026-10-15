import logging
import json
from datetime import datetime, timezone

import pytest

from app.security.access_control import AccessDenied, Principal, Role, Trip
from app.security.validation import ValidationError
from app.services.vehicle_service import VehicleService


def make_service(caplog: pytest.LogCaptureFixture) -> VehicleService:
    logger = logging.getLogger("test.vehicle.security")
    caplog.set_level(logging.INFO, logger="test.vehicle.security")
    return VehicleService({"CAR-019": "available"}, {"T1": Trip("T1", "driver-01", "private route")}, logger)


def test_dispatcher_changes_status_and_audit_records_success(caplog: pytest.LogCaptureFixture) -> None:
    service = make_service(caplog)
    service.change_vehicle_status(Principal("dispatcher-01", Role.DISPATCHER), "CAR-019", "maintenance")
    assert service.vehicles["CAR-019"] == "maintenance"
    assert '"result": "allowed"' in caplog.text


def test_driver_denial_is_audited_and_does_not_mutate_data(caplog: pytest.LogCaptureFixture) -> None:
    service = make_service(caplog)
    with pytest.raises(AccessDenied):
        service.change_vehicle_status(Principal("driver-01", Role.DRIVER), "CAR-019", "maintenance")
    assert service.vehicles["CAR-019"] == "available"
    assert '"result": "denied"' in caplog.text


def test_trip_read_denial_is_audited(caplog: pytest.LogCaptureFixture) -> None:
    service = make_service(caplog)
    with pytest.raises(AccessDenied):
        service.read_trip(Principal("driver-02", Role.DRIVER), "T1")
    assert '"action": "trip.read"' in caplog.text
    assert '"result": "denied"' in caplog.text


@pytest.mark.parametrize(
    "principal,trip_id",
    [
        (Principal("driver-02", Role.DRIVER), "T1"),
        (Principal("driver-01", Role.DRIVER), "MISSING"),
        (Principal("manager-01", Role.MANAGER), "T1"),
    ],
)
def test_trip_read_denials_have_same_external_error(
    caplog: pytest.LogCaptureFixture, principal: Principal, trip_id: str
) -> None:
    service = make_service(caplog)
    with pytest.raises(AccessDenied, match="^Доступ к поездке запрещён$"):
        service.read_trip(principal, trip_id)
    assert '"result": "denied"' in caplog.text


@pytest.mark.parametrize("trip_id", [None, " " * 33, "TRIP\n001"])
def test_invalid_trip_id_is_audited_and_denied_before_lookup(
    caplog: pytest.LogCaptureFixture, trip_id: object
) -> None:
    service = make_service(caplog)
    with pytest.raises(ValidationError):
        service.read_trip(Principal("driver-01", Role.DRIVER), trip_id)
    assert '"result": "validation_denied"' in caplog.text


def test_audit_does_not_include_trip_route(caplog: pytest.LogCaptureFixture) -> None:
    service = make_service(caplog)
    service.read_trip(Principal("driver-01", Role.DRIVER), "T1")
    assert "private route" not in caplog.text


def test_driver_can_read_own_trip_and_audit_has_utc_fixed_fields(caplog: pytest.LogCaptureFixture) -> None:
    service = make_service(caplog)
    trip = service.read_trip(Principal("driver-01", Role.DRIVER), "T1")
    event = json.loads(caplog.records[-1].message)
    timestamp = datetime.fromisoformat(event["timestamp"])
    assert trip.driver_id == "driver-01"
    assert timestamp.tzinfo == timezone.utc
    assert set(event) == {"timestamp", "subject_id", "action", "object_id", "result"}
    assert event["result"] == "allowed"


def test_invalid_vehicle_status_is_audited_without_mutation(caplog: pytest.LogCaptureFixture) -> None:
    service = make_service(caplog)
    with pytest.raises(ValidationError):
        service.change_vehicle_status(Principal("dispatcher-01", Role.DISPATCHER), "CAR-019", "broken")
    assert service.vehicles["CAR-019"] == "available"
    assert '"result": "validation_denied"' in caplog.text


def test_missing_principal_is_denied_audited_and_does_not_mutate(caplog: pytest.LogCaptureFixture) -> None:
    service = make_service(caplog)
    with pytest.raises(AccessDenied):
        service.change_vehicle_status(None, "CAR-019", "maintenance")  # type: ignore[arg-type]
    assert service.vehicles["CAR-019"] == "available"
    assert '"subject_id": "unknown"' in caplog.text
    assert '"result": "denied"' in caplog.text
