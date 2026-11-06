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
    errors: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """
    Collect files from a single Startup directory.
    Missing directories are treated as normal.
    Access and file errors are recorded when an errors list is provided.
    """

    entries: list[dict[str, Any]] = []
    error_list = errors if errors is not None else []

    try:
        with os.scandir(directory_path) as directory:
            for entry in directory:
                try:
                    if not entry.is_file():
                        continue

                    # desktop.ini is a Windows folder configuration file,
                    # not an executable Startup item.
                    if entry.name.lower() == "desktop.ini":
                        continue

                    file_information = entry.stat()
                    resolved_path = str(Path(entry.path).resolve())

                    entries.append(
                        {
                            "scope": scope,
                            "name": entry.name,
                            "path": resolved_path,
                            "extension": Path(entry.name).suffix.lower(),
                            "size": file_information.st_size,
                            "modified_at": datetime.fromtimestamp(
                                file_information.st_mtime,
                                tz=timezone.utc,
                            ).isoformat(),
                        }
                    )

                except FileNotFoundError:
                    # The entry may have disappeared during collection.
                    continue

                except OSError as exc:
                    error_list.append(
                        {
                            "scope": scope,
                            "path": entry.path,
                            "component": "startup_file",
                            "error": f"{type(exc).__name__}: {exc}",
                        }
                    )

    except (FileNotFoundError, NotADirectoryError):
        # A missing or invalid Startup directory is a normal condition.
        return entries

    except OSError as exc:
        error_list.append(
            {
                "scope": scope,
                "path": directory_path,
                "component": "startup_directory",
                "error": f"{type(exc).__name__}: {exc}",
            }
        )

    return entries


def collect_startup() -> dict[str, Any]:
    """
    Collect files from Windows Startup directories.

    Returns:
        A structured dictionary containing collection metadata,
        the number of Startup entries, their information, status, and errors.
    """

    collected_at = datetime.now(
        timezone.utc
    ).isoformat()

    entries: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    for directory in _get_startup_directories():
        entries.extend(
            _collect_directory_entries(
                scope=directory["scope"],
                directory_path=directory["path"],
                errors=errors,
            )
        )

    entries.sort(
        key=lambda item: (
            item["scope"],
            item["path"],
        )
    )

    if not errors:
        status = "success"
    elif entries:
        status = "partial"
    else:
        status = "error"

    return {
        "collector": "startup_collector",
        "entity_type": "startup_item",
        "collected_at": collected_at,
        "count": len(entries),
        "items": entries,
        "status": status,
        "errors": errors,
    }
