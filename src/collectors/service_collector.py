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
    service: psutil.win_service_get,
) -> dict[str, Any] | None:
    """
    Collect and normalize information about a single Windows service.

    Returns:
        A normalized service record, or None if the service
        cannot be accessed.
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
        }

    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess,
    ):
        return None


def collect_services() -> dict[str, Any]:
    """
    Collect accessible Windows services.

    Returns:
        A structured dictionary containing collection metadata,
        the number of collected services, and service records.
    """

    collected_at = datetime.now(timezone.utc).isoformat()
    services: list[dict[str, Any]] = []

    for service in psutil.win_service_iter():
        service_information = _get_service_information(service)

        if service_information is not None:
            services.append(service_information)

    services.sort(
        key=lambda item: (item["name"] or "").lower()
    )

    return {
        "collector": "service_collector",
        "entity_type": "service",
        "collected_at": collected_at,
        "count": len(services),
        "items": services,
    }