"""
Registry Collector
------------------
Collects selected Windows Registry values related to
persistence and automatic execution.

This module is part of the Data Collection Layer of the
Digital DNA Security Framework.
"""

from datetime import datetime, timezone
from typing import Any

import winreg


REGISTRY_LOCATIONS = [
    {
        "hive": winreg.HKEY_CURRENT_USER,
        "hive_name": "HKCU",
        "path": r"Software\Microsoft\Windows\CurrentVersion\Run",
    },
    {
        "hive": winreg.HKEY_CURRENT_USER,
        "hive_name": "HKCU",
        "path": r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    },
    {
        "hive": winreg.HKEY_LOCAL_MACHINE,
        "hive_name": "HKLM",
        "path": r"Software\Microsoft\Windows\CurrentVersion\Run",
    },
    {
        "hive": winreg.HKEY_LOCAL_MACHINE,
        "hive_name": "HKLM",
        "path": r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    },
]


WINLOGON_VALUES = {
    "Shell",
    "Userinit",
    "AutoAdminLogon",
    "DefaultUserName",
}


def _get_registry_values(
    hive: Any,
    hive_name: str,
    path: str,
) -> list[dict[str, Any]]:
    """
    Collect all values from a selected Registry key.

    Returns:
        A list of normalized Registry value records.
    """

    values: list[dict[str, Any]] = []

    try:
        key = winreg.OpenKey(
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
        return values

    try:
        value_count = winreg.QueryInfoKey(key)[1]

        for index in range(value_count):
            try:
                name, value, value_type = winreg.EnumValue(
                    key,
                    index,
                )

                values.append(
                    {
                        "hive": hive_name,
                        "path": path,
                        "name": name,
                        "value": value,
                        "type": value_type,
                    }
                )

            except OSError:
                continue

    finally:
        winreg.CloseKey(key)

    return values


def _get_selected_winlogon_values(
    hive: Any,
    hive_name: str,
) -> list[dict[str, Any]]:
    """
    Collect selected security-relevant Winlogon values.

    Only values related to shell execution, user initialization,
    automatic logon, and the configured default username are
    collected.
    """

    path = (
        r"Software\Microsoft\Windows NT"
        r"\CurrentVersion\Winlogon"
    )

    values: list[dict[str, Any]] = []

    try:
        key = winreg.OpenKey(
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
        return values

    try:
        value_count = winreg.QueryInfoKey(key)[1]

        for index in range(value_count):
            try:
                name, value, value_type = winreg.EnumValue(
                    key,
                    index,
                )

                if name not in WINLOGON_VALUES:
                    continue

                values.append(
                    {
                        "hive": hive_name,
                        "path": path,
                        "name": name,
                        "value": value,
                        "type": value_type,
                    }
                )

            except OSError:
                continue

    finally:
        winreg.CloseKey(key)

    return values


def collect_registry() -> dict[str, Any]:
    """
    Collect selected Windows Registry persistence locations.

    The collector focuses on Run, RunOnce, and selected
    security-relevant Winlogon values instead of scanning
    the entire Registry.

    Returns:
        A structured dictionary containing collection metadata,
        the number of collected values, and Registry records.
    """

    collected_at = datetime.now(
        timezone.utc
    ).isoformat()

    values: list[dict[str, Any]] = []

    # Collect Run and RunOnce locations.
    for location in REGISTRY_LOCATIONS:
        values.extend(
            _get_registry_values(
                hive=location["hive"],
                hive_name=location["hive_name"],
                path=location["path"],
            )
        )

    # Collect selected Winlogon values.
    values.extend(
        _get_selected_winlogon_values(
            hive=winreg.HKEY_CURRENT_USER,
            hive_name="HKCU",
        )
    )

    values.extend(
        _get_selected_winlogon_values(
            hive=winreg.HKEY_LOCAL_MACHINE,
            hive_name="HKLM",
        )
    )

    values.sort(
        key=lambda item: (
            item["hive"],
            item["path"],
            item["name"],
        )
    )

    return {
        "collector": "registry_collector",
        "entity_type": "registry_value",
        "collected_at": collected_at,
        "count": len(values),
        "items": values,
    }