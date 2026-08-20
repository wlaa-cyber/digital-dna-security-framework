"""
Snapshot Collector
------------------
Coordinates all Data Collection Layer collectors and
builds a unified system snapshot.

This module is part of the Baseline Layer of the
Digital DNA Security Framework.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from src.collectors.digital_signature_collector import (
    collect_digital_signatures,
)
from src.collectors.installed_applications_collector import (
    collect_installed_applications,
)
from src.collectors.network_collector import collect_network
from src.collectors.process_collector import collect_processes
from src.collectors.registry_collector import collect_registry
from src.collectors.scheduled_task_collector import (
    collect_scheduled_tasks,
)
from src.collectors.service_collector import collect_services
from src.collectors.startup_collector import collect_startup
from src.collectors.system_collector import collect_system


CollectorFunction = Callable[[], dict[str, Any]]


COLLECTORS: dict[str, CollectorFunction] = {
    "system": collect_system,
    "processes": collect_processes,
    "services": collect_services,
    "network": collect_network,
    "scheduled_tasks": collect_scheduled_tasks,
    "registry": collect_registry,
    "startup": collect_startup,
    "installed_applications": collect_installed_applications,
}


def _run_collector(
    name: str,
    collector: CollectorFunction,
) -> dict[str, Any]:
    """
    Execute a collector safely.

    Returns:
        Collector result or a structured error record.
    """

    try:
        return collector()

    except Exception as error:
        return {
            "collector": name,
            "entity_type": name,
            "collected_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "count": 0,
            "items": [],
            "status": "error",
            "error": str(error),
        }


def _extract_process_paths(
    process_data: dict[str, Any],
) -> list[str]:
    """
    Extract valid executable paths from process data.

    Only existing executable files are returned.
    """

    executable_paths: set[str] = set()

    for process in process_data.get("items", []):
        path = process.get("path")

        if not path:
            continue

        file_path = Path(path)

        if (
            file_path.is_file()
            and file_path.suffix.lower() == ".exe"
        ):
            executable_paths.add(
                str(file_path)
            )

    return sorted(
        executable_paths,
        key=str.lower,
    )


def _collect_digital_signatures(
    executable_paths: list[str],
) -> dict[str, Any]:
    """
    Collect digital signatures safely.

    Digital signature verification is treated as an optional
    enrichment step for executable process paths. A failure
    must not stop the complete system snapshot.
    """

    try:
        return collect_digital_signatures(
            executable_paths
        )

    except Exception as error:
        return {
            "collector": "digital_signature_collector",
            "entity_type": "digital_signature",
            "collected_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "count": 0,
            "items": [],
            "status": "error",
            "error": str(error),
        }


def collect_snapshot() -> dict[str, Any]:
    """
    Collect a unified snapshot of the Windows system.

    Returns:
        A structured snapshot containing all collector results.
    """

    collected_at = datetime.now(
        timezone.utc
    ).isoformat()

    collectors: dict[str, dict[str, Any]] = {}

    # Collect process information first because
    # executable paths are used for signature verification.
    process_data = _run_collector(
        "processes",
        collect_processes,
    )

    collectors["processes"] = process_data

    executable_paths = _extract_process_paths(
        process_data
    )

    # Collect the remaining data sources.
    for name, collector in COLLECTORS.items():

        if name == "processes":
            continue

        collectors[name] = _run_collector(
            name,
            collector,
        )

    # Verify signatures only for executable files
    # associated with currently running processes.
    collectors["digital_signatures"] = (
        _collect_digital_signatures(
            executable_paths
        )
    )

    successful = [
        name
        for name, result in collectors.items()
        if result.get("status", "success") != "error"
    ]

    failed = [
        name
        for name, result in collectors.items()
        if result.get("status") == "error"
    ]

    return {
        "snapshot": {
            "version": "1.0",
            "collected_at": collected_at,
            "collector_count": len(collectors),
            "successful_collectors": successful,
            "failed_collectors": failed,
        },
        "collectors": collectors,
    }


def save_snapshot(
    snapshot: dict[str, Any],
    output_directory: str = "data",
) -> Path:
    """
    Save a system snapshot as a timestamped JSON file.

    Returns:
        The path of the created snapshot file.
    """

    directory = Path(output_directory)

    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%dT%H%M%SZ")

    output_path = (
        directory
        / f"system_snapshot_{timestamp}.json"
    )

    with output_path.open(
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            snapshot,
            file,
            indent=2,
            ensure_ascii=False,
        )

    return output_path


def collect_and_save_snapshot(
    output_directory: str = "data",
) -> Path:
    """
    Collect a complete system snapshot and save it to disk.

    Returns:
        The path of the saved snapshot.
    """

    snapshot = collect_snapshot()

    return save_snapshot(
        snapshot,
        output_directory,
    )