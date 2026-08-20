"""
Process Collector
-----------------
Collects process information from the Windows operating system.

This module is part of the Data Collection Layer of the
Digital DNA Security Framework.
"""

from datetime import datetime, timezone
from typing import Any

import psutil


def _get_process_information(process: psutil.Process) -> dict[str, Any] | None:
    """
    Collect information about a single process.

    Returns:
        A dictionary containing process information, or None if
        the process cannot be accessed.
    """

    try:
        information = process.as_dict(
            attrs=[
                "pid",
                "name",
                "exe",
                "username",
                "ppid",
                "create_time",
            ],
            ad_value=None,
        )

        return {
            "pid": information["pid"],
            "name": information["name"],
            "path": information["exe"],
            "username": information["username"],
            "parent_pid": information["ppid"],
            "create_time": _format_timestamp(information["create_time"]),
        }

    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess,
    ):
        return None


def _format_timestamp(timestamp: float | None) -> str | None:
    """
    Convert a valid Unix timestamp to an ISO 8601 UTC timestamp.

    Invalid or unavailable timestamps are returned as None.
    """

    if timestamp is None or timestamp <= 0:
        return None

    try:
        return datetime.fromtimestamp(
            timestamp,
            tz=timezone.utc,
        ).isoformat()

    except (OverflowError, OSError, ValueError):
        return None

def collect_processes() -> dict[str, Any]:
    """
    Collect information about all accessible Windows processes.

    Returns:
        A structured dictionary containing:
        - collection metadata
        - number of collected processes
        - process records
    """

    collected_at = datetime.now(timezone.utc).isoformat()
    processes: list[dict[str, Any]] = []

    for process in psutil.process_iter():
        process_information = _get_process_information(process)

        if process_information is not None:
            processes.append(process_information)

    processes.sort(key=lambda item: item["pid"])

    return {
        "collector": "process_collector",
        "entity_type": "process",
        "collected_at": collected_at,
        "count": len(processes),
        "items": processes,
    }