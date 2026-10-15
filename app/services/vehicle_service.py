"""Минимальные операции учета ТС с проверками и аудитом."""

import logging
import re

from app.audit.audit_logger import log_security_event
from app.security.access_control import AccessDenied, Principal, Trip, authorize
from app.security.validation import ValidationError, validate_trip_id, validate_vehicle_status_change


_SAFE_SUBJECT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z")


class VehicleService:
    """Учебный сервис над переданными in-memory данными."""

    def __init__(self, vehicles: dict[str, str], trips: dict[str, Trip], logger: logging.Logger):
        self.vehicles = vehicles
        self.trips = trips
        self.logger = logger

    @staticmethod
    def _audit_subject(principal: object) -> str:
        """Не обращается к недоверенному или отсутствующему principal напрямую."""
        if isinstance(principal, Principal) and isinstance(principal.subject_id, str):
            subject_id = principal.subject_id
            if _SAFE_SUBJECT_ID.fullmatch(subject_id):
                return subject_id
        return "unknown"

    def change_vehicle_status(self, principal: Principal, vehicle_id: object, status: object) -> str:
        """Сменить состояние ТС только после валидации и проверки диспетчера."""
        try:
            change = validate_vehicle_status_change(vehicle_id, status)
        except ValidationError:
            log_security_event(
                self.logger, subject_id=self._audit_subject(principal), action="vehicle.status.change",
                object_id=None, result="validation_denied",
            )
            raise
        try:
            authorize(principal, "vehicle.status.change", change.vehicle_id)
            if change.vehicle_id not in self.vehicles:
                raise KeyError("Транспортное средство не найдено")
        except (AccessDenied, KeyError):
            log_security_event(
                self.logger, subject_id=self._audit_subject(principal), action="vehicle.status.change",
                object_id=change.vehicle_id, result="denied",
            )
            raise
        self.vehicles[change.vehicle_id] = change.new_status
        log_security_event(
            self.logger, subject_id=self._audit_subject(principal), action="vehicle.status.change",
            object_id=change.vehicle_id, result="allowed",
        )
        return change.new_status

    def read_trip(self, principal: Principal, trip_id: object) -> Trip:
        """Прочитать поездку после объектной проверки принадлежности."""
        try:
            normalized_trip_id = validate_trip_id(trip_id)
        except ValidationError:
            log_security_event(
                self.logger, subject_id=self._audit_subject(principal), action="trip.read",
                object_id=None, result="validation_denied",
            )
            raise
        trip = self.trips.get(normalized_trip_id)
        try:
            authorize(principal, "trip.read", trip)
        except AccessDenied:
            log_security_event(
                self.logger, subject_id=self._audit_subject(principal), action="trip.read",
                object_id=normalized_trip_id, result="denied",
            )
            raise AccessDenied("Доступ к поездке запрещён") from None
        log_security_event(
            self.logger, subject_id=self._audit_subject(principal), action="trip.read",
            object_id=trip.trip_id, result="allowed",
        )
        return trip
