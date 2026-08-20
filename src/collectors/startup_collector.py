"""
Startup Collector
------------------
Collects files located in Windows Startup folders.

This module is part of the Data Collection Layer of the
Digital DNA Security Framework.
"""

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _get_startup_directories() -> list[dict[str, str]]:
    """
    Return the supported Windows Startup directories.
    """

    directories = [
        {
            "scope": "user",
            "path": os.path.join(
                os.environ.get("APPDATA", ""),
                r"Microsoft\Windows\Start Menu\Programs\Startup",
            ),
        },
        {
            "scope": "system",
            "path": os.path.join(
                os.environ.get("ProgramData", ""),
                r"Microsoft\Windows\Start Menu\Programs\StartUp",
            ),
        },
    ]

    return directories


def _collect_directory_entries(
    scope: str,
    directory_path: str,
) -> list[dict[str, Any]]:
    """
    Collect files from a single Startup directory.
    """

    entries: list[dict[str, Any]] = []

    directory = Path(directory_path)

    if not directory.exists() or not directory.is_dir():
        return entries

    try:
        for entry in directory.iterdir():

            if not entry.is_file():
                continue

            # desktop.ini is a Windows folder configuration file,
            # not an executable Startup item.
            if entry.name.lower() == "desktop.ini":
                continue

            try:
                file_information = entry.stat()

                entries.append(
                    {
                        "scope": scope,
                        "name": entry.name,
                        "path": str(entry.resolve()),
                        "extension": entry.suffix.lower(),
                        "size": file_information.st_size,
                        "modified_at": datetime.fromtimestamp(
                            file_information.st_mtime,
                            tz=timezone.utc,
                        ).isoformat(),
                    }
                )

            except (
                OSError,
                PermissionError,
            ):
                continue

    except (
        OSError,
        PermissionError,
    ):
        return entries

    return entries


def collect_startup() -> dict[str, Any]:
    """
    Collect files from Windows Startup directories.

    Returns:
        A structured dictionary containing collection metadata,
        the number of Startup entries, and their information.
    """

    collected_at = datetime.now(
        timezone.utc
    ).isoformat()

    entries: list[dict[str, Any]] = []

    for directory in _get_startup_directories():
        entries.extend(
            _collect_directory_entries(
                scope=directory["scope"],
                directory_path=directory["path"],
            )
        )

    entries.sort(
        key=lambda item: (
            item["scope"],
            item["path"],
        )
    )

    return {
        "collector": "startup_collector",
        "entity_type": "startup_item",
        "collected_at": collected_at,
        "count": len(entries),
        "items": entries,
    }