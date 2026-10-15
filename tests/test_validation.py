import pytest

from app.security.validation import ValidationError, validate_mileage_report, validate_vehicle_status_change


def test_valid_vehicle_status_change_is_normalized() -> None:
    assert validate_vehicle_status_change(" CAR-019 ", "MAINTENANCE").new_status == "maintenance"


@pytest.mark.parametrize("vehicle_id", ["", "   ", "x" * 33, 19])
def test_invalid_vehicle_id_is_rejected(vehicle_id: object) -> None:
    with pytest.raises(ValidationError):
        validate_vehicle_status_change(vehicle_id, "available")


@pytest.mark.parametrize("trip_id", ["", "  ", "T" * 33, 19, "TRIP\n001"])
def test_invalid_trip_id_is_rejected(trip_id: object) -> None:
    with pytest.raises(ValidationError):
        validate_mileage_report(trip_id, 10, 11)


def test_unknown_vehicle_status_is_rejected() -> None:
    with pytest.raises(ValidationError):
        validate_vehicle_status_change("CAR-019", "unknown")


def test_valid_mileage_report_passes() -> None:
    assert validate_mileage_report("TRIP-001", 1200, 1250).end_km == 1250


@pytest.mark.parametrize("start,end", [(-1, 0), (10, -1), (20, 19), (True, 20)])
def test_invalid_mileage_is_rejected(start: object, end: object) -> None:
    with pytest.raises(ValidationError):
        validate_mileage_report("TRIP-001", start, end)
