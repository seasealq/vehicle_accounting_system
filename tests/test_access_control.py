import pytest

from app.security.access_control import AccessDenied, Principal, Role, Trip, authorize


def test_driver_can_read_own_trip() -> None:
    authorize(Principal("driver-01", Role.DRIVER), "trip.read", Trip("T1", "driver-01", "route"))


def test_driver_cannot_read_another_drivers_trip() -> None:
    with pytest.raises(AccessDenied):
        authorize(Principal("driver-02", Role.DRIVER), "trip.read", Trip("T1", "driver-01", "route"))


@pytest.mark.parametrize("role", [Role.DRIVER, Role.MANAGER, Role.SECURITY_ADMIN, Role.ANONYMOUS])
def test_only_dispatcher_can_change_vehicle_status(role: Role) -> None:
    with pytest.raises(AccessDenied):
        authorize(Principal("user-01", role), "vehicle.status.change", "CAR-019")


def test_unknown_operation_is_denied() -> None:
    with pytest.raises(AccessDenied):
        authorize(Principal("dispatcher-01", Role.DISPATCHER), "unknown.action")


@pytest.mark.parametrize(
    "principal",
    [None, Principal("", Role.DRIVER), Principal("driver-01", "driver")],
)
def test_invalid_principal_is_denied_without_attribute_error(principal: object) -> None:
    with pytest.raises(AccessDenied):
        authorize(principal, "trip.read", Trip("T1", "driver-01", "route"))


def test_security_admin_does_not_automatically_read_trips() -> None:
    with pytest.raises(AccessDenied):
        authorize(Principal("admin-01", Role.SECURITY_ADMIN), "trip.read", Trip("T1", "d1", "route"))
