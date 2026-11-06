"""
Service Collector
-----------------
Collects Windows service information.

This module is part of the Data Collection Layer of the
Digital DNA Security Framework.
"""

from datetime import datetime, timezone
from typing import Any

import psutil


def _get_service_information(
    service: Any,
) -> tuple[dict[str, Any] | None, dict[str, str] | None]:
    """
    Collect and normalize information about a single Windows service.

    Returns:
        A tuple containing the service record and an optional error.
        Services that disappear during collection are skipped.
    """

    try:
        information = service.as_dict()

        return {
            "name": information.get("name"),
            "display_name": information.get("display_name"),
            "status": information.get("status"),
            "pid": information.get("pid"),
            "username": information.get("username"),
            "start_type": information.get("start_type"),
            "description": information.get("description"),
            "binpath": information.get("binpath"),
            "dependencies": information.get("dependencies"),
        }, None

    except psutil.AccessDenied as exc:
        return None, {
            "component": "service",
            "error_type": type(exc).__name__,
            "message": str(exc),
        }

    except (
        psutil.NoSuchProcess,
        psutil.ZombieProcess,
    ):
        return None, None


def collect_services() -> dict[str, Any]:
    """
    Collect Windows service information.

    Returns:
        A structured dictionary containing collection metadata,
        service records, collection status, and any errors.
    """

    collected_at = datetime.now(
        timezone.utc
    ).isoformat()

    services: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    enumeration_completed = False

    try:
        service_iterator = psutil.win_service_iter()

        for service in service_iterator:
            service_information, service_error = (
                _get_service_information(service)
            )

            if service_information is not None:
                services.append(service_information)

            if service_error is not None:
                errors.append(service_error)

        enumeration_completed = True

    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess,
    ) as exc:
        errors.append({
            "component": "service_enumeration",
            "error_type": type(exc).__name__,
            "message": str(exc),
        })

    services.sort(
        key=lambda item: (
            item["name"] or ""
        ).lower()
    )

    if not errors:
        status = "success"
    elif services:
        status = "partial"
    else:
        status = "error"

    return {
        "collector": "service_collector",
        "entity_type": "service",
        "collected_at": collected_at,
        "count": len(services),
        "items": services,
        "status": status,
        "errors": errors,
    }
