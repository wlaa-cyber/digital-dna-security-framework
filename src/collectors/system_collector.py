"""
System Collector
----------------
Collects stable system metadata from the Windows operating system.

This module is part of the Data Collection Layer of the
Digital DNA Security Framework.
"""

from datetime import datetime, timezone
from typing import Any

import platform
import psutil


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


def collect_system() -> dict[str, Any]:
    """
    Collect system metadata from Windows.

    The collected information describes the host environment
    and is treated as system metadata rather than a dynamic
    Digital DNA graph entity.

    Returns:
        A structured dictionary containing collection metadata,
        operating system information, boot information,
        CPU information, and memory information.
    """

    collected_at = datetime.now(timezone.utc).isoformat()

    virtual_memory = psutil.virtual_memory()

    return {
        "collector": "system_collector",
        "entity_type": "system_metadata",
        "collected_at": collected_at,

        "system": {
            "hostname": platform.node(),
            "os": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
        },

        "boot": {
            "boot_time": _format_timestamp(
                psutil.boot_time()
            ),
        },

        "memory": {
            "total": virtual_memory.total,
            "available": virtual_memory.available,
            "used": virtual_memory.used,
            "free": virtual_memory.free,
            "percent": virtual_memory.percent,
        },

        "cpu": {
            "logical_count": psutil.cpu_count(
                logical=True
            ),
            "physical_count": psutil.cpu_count(
                logical=False
            ),
        },
    }