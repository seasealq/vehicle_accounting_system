"""Воспроизводимая демонстрация прототипа защитных проверок."""

import argparse
import logging

from app.security.access_control import AccessDenied, Principal, Role, Trip
from app.security.validation import ValidationError, validate_mileage_report
from app.services.vehicle_service import VehicleService


def show_validation() -> None:
    print("Валидный пробег:", validate_mileage_report("TRIP-001", 1200, 1235).end_km)
    try:
        validate_mileage_report("TRIP-001", 1235, 1200)
    except ValidationError as error:
        print("Невалидный пробег: отклонён —", error)


def show_authorization(logger: logging.Logger) -> None:
    vehicles = {"CAR-019": "available"}
    trips = {"TRIP-001": Trip("TRIP-001", "driver-01", "Склад — филиал")}
    service = VehicleService(vehicles, trips, logger)
    dispatcher = Principal("dispatcher-01", Role.DISPATCHER)
    driver = Principal("driver-01", Role.DRIVER)
    print("Статус ТС до операции:", vehicles["CAR-019"])
    service.change_vehicle_status(dispatcher, "CAR-019", "maintenance")
    print("Диспетчер: разрешено; статус:", vehicles["CAR-019"])
    before = vehicles["CAR-019"]
    try:
        service.change_vehicle_status(driver, "CAR-019", "available")
    except AccessDenied:
        print("Водитель: отказ; состояние сохранено:", vehicles["CAR-019"] == before)
    try:
        service.read_trip(Principal("driver-02", Role.DRIVER), "TRIP-001")
    except AccessDenied:
        print("Чужая поездка: отказ")


def main() -> None:
    parser = argparse.ArgumentParser(description="Демонстрация проверок безопасности v0.4")
    parser.add_argument("--validation", action="store_true", help="показать проверки входных данных")
    parser.add_argument("--authorization", action="store_true", help="показать разрешения и аудит")
    args = parser.parse_args()
    if args.validation and args.authorization:
        parser.error("выберите не более одного режима")

    logging.basicConfig(level=logging.INFO, format="AUDIT %(message)s")
    logger = logging.getLogger("vehicle_accounting.security")
    if args.validation:
        show_validation()
    elif args.authorization:
        show_authorization(logger)
    else:
        show_validation()
        show_authorization(logger)


if __name__ == "__main__":
    main()
