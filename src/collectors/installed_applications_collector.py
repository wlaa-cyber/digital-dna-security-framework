"""
Installed Applications Collector
---------------------------------
Collects installed application information from the
Windows Registry.

This module is part of the Data Collection Layer of the
Digital DNA Security Framework.
"""

from datetime import datetime, timezone
from typing import Any

import winreg


UNINSTALL_LOCATIONS = [
    {
        "hive": winreg.HKEY_LOCAL_MACHINE,
        "hive_name": "HKLM",
        "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "scope": "machine",
    },
    {
        "hive": winreg.HKEY_LOCAL_MACHINE,
        "hive_name": "HKLM",
        "path": r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "scope": "machine",
    },
    {
        "hive": winreg.HKEY_CURRENT_USER,
        "hive_name": "HKCU",
        "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "scope": "user",
    },
]


def _read_value(
    key: Any,
    name: str,
) -> Any:
    """
    Read a Registry value safely.

    Returns:
        The Registry value if available, otherwise None.
    """

    try:
        value, _ = winreg.QueryValueEx(key, name)
        return value

    except (
        FileNotFoundError,
        OSError,
    ):
        return None


def _collect_from_location(
    hive: Any,
    hive_name: str,
    path: str,
    scope: str,
) -> list[dict[str, Any]]:
    """
    Collect installed applications from one Registry location.
    """

    applications: list[dict[str, Any]] = []

    try:
        root_key = winreg.OpenKey(
            hive,
            path,
            0,
            winreg.KEY_READ,
        )

    except (
        FileNotFoundError,
        PermissionError,
        OSError,
    ):
        return applications

    try:
        subkey_count = winreg.QueryInfoKey(root_key)[0]

        for index in range(subkey_count):
            try:
                subkey_name = winreg.EnumKey(
                    root_key,
                    index,
                )

                subkey = winreg.OpenKey(
                    root_key,
                    subkey_name,
                    0,
                    winreg.KEY_READ,
                )

                try:
                    display_name = _read_value(
                        subkey,
                        "DisplayName",
                    )

                    if not display_name:
                        continue

                    application = {
                        "name": str(display_name),
                        "version": _read_value(
                            subkey,
                            "DisplayVersion",
                        ),
                        "publisher": _read_value(
                            subkey,
                            "Publisher",
                        ),
                        "install_date": _read_value(
                            subkey,
                            "InstallDate",
                        ),
                        "install_location": _read_value(
                            subkey,
                            "InstallLocation",
                        ),
                        "uninstall_string": _read_value(
                            subkey,
                            "UninstallString",
                        ),
                        "display_icon": _read_value(
                            subkey,
                            "DisplayIcon",
                        ),
                        "scope": scope,
                        "registry_hive": hive_name,
                        "registry_path": (
                            f"{path}\\{subkey_name}"
                        ),
                    }

                    applications.append(application)

                finally:
                    winreg.CloseKey(subkey)

            except (
                FileNotFoundError,
                PermissionError,
                OSError,
            ):
                continue

    finally:
        winreg.CloseKey(root_key)

    return applications


def _deduplicate_applications(
    applications: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Remove duplicate application records.

    Applications may appear in more than one Registry location,
    especially when both 32-bit and 64-bit entries exist.
    """

    unique_applications: dict[tuple[Any, ...], dict[str, Any]] = {}

    for application in applications:
        key = (
            application["name"],
            application["version"],
            application["publisher"],
            application["install_location"],
        )

        if key not in unique_applications:
            unique_applications[key] = application

    return list(unique_applications.values())


def collect_installed_applications() -> dict[str, Any]:
    """
    Collect installed applications registered in Windows.

    Returns:
        A structured dictionary containing collection metadata,
        the number of unique applications, and application records.
    """

    collected_at = datetime.now(
        timezone.utc
    ).isoformat()

    applications: list[dict[str, Any]] = []

    for location in UNINSTALL_LOCATIONS:
        applications.extend(
            _collect_from_location(
                hive=location["hive"],
                hive_name=location["hive_name"],
                path=location["path"],
                scope=location["scope"],
            )
        )

    applications = _deduplicate_applications(
        applications
    )

    applications.sort(
        key=lambda item: (
            item["name"] or ""
        ).lower()
    )

    return {
        "collector": "installed_applications_collector",
        "entity_type": "installed_application",
        "collected_at": collected_at,
        "count": len(applications),
        "items": applications,
    }