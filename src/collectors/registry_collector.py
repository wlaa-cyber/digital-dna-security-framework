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
    errors: list[dict[str, str]] | None = None,
) -> list[dict[str, Any]]:
    """Collect Registry values and record access/read failures."""

    values: list[dict[str, Any]] = []

    if errors is None:
        errors = []

    try:
        key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
    except FileNotFoundError:
        return values
    except OSError as exc:
        errors.append({
            "component": f"{hive_name}\\{path}",
            "error_type": type(exc).__name__,
            "message": str(exc),
        })
        return values

    try:
        try:
            value_count = winreg.QueryInfoKey(key)[1]
        except OSError as exc:
            errors.append({
                "component": f"{hive_name}\\{path}",
                "error_type": type(exc).__name__,
                "message": str(exc),
            })
            return values

        for index in range(value_count):
            try:
                name, value, value_type = winreg.EnumValue(key, index)
                values.append({
                    "hive": hive_name,
                    "path": path,
                    "name": name,
                    "value": value,
                    "type": value_type,
                })
            except OSError as exc:
                errors.append({
                    "component": f"{hive_name}\\{path}\\value[{index}]",
                    "error_type": type(exc).__name__,
                    "message": str(exc),
                })
    finally:
        winreg.CloseKey(key)

    return values


def _get_selected_winlogon_values(
    hive: Any,
    hive_name: str,
    errors: list[dict[str, str]] | None = None,
) -> list[dict[str, Any]]:
    """Collect selected Winlogon values and record access/read failures."""

    path = (
        r"Software\Microsoft\Windows NT"
        r"\CurrentVersion\Winlogon"
    )

    values: list[dict[str, Any]] = []

    if errors is None:
        errors = []

    try:
        key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
    except FileNotFoundError:
        return values
    except OSError as exc:
        errors.append({
            "component": f"{hive_name}\\{path}",
            "error_type": type(exc).__name__,
            "message": str(exc),
        })
        return values

    try:
        try:
            value_count = winreg.QueryInfoKey(key)[1]
        except OSError as exc:
            errors.append({
                "component": f"{hive_name}\\{path}",
                "error_type": type(exc).__name__,
                "message": str(exc),
            })
            return values

        for index in range(value_count):
            try:
                name, value, value_type = winreg.EnumValue(key, index)

                if name not in WINLOGON_VALUES:
                    continue

                values.append({
                    "hive": hive_name,
                    "path": path,
                    "name": name,
                    "value": value,
                    "type": value_type,
                })
            except OSError as exc:
                errors.append({
                    "component": f"{hive_name}\\{path}\\value[{index}]",
                    "error_type": type(exc).__name__,
                    "message": str(exc),
                })
    finally:
        winreg.CloseKey(key)

    return values


def collect_registry() -> dict[str, Any]:
    """
    Collect selected Windows Registry persistence locations.
    Missing Registry keys are normal; access/read failures are reported.
    """

    collected_at = datetime.now(
        timezone.utc
    ).isoformat()

    values: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []

    for location in REGISTRY_LOCATIONS:
        values.extend(
            _get_registry_values(
                hive=location["hive"],
                hive_name=location["hive_name"],
                path=location["path"],
                errors=errors,
            )
        )

    values.extend(
        _get_selected_winlogon_values(
            hive=winreg.HKEY_CURRENT_USER,
            hive_name="HKCU",
            errors=errors,
        )
    )

    values.extend(
        _get_selected_winlogon_values(
            hive=winreg.HKEY_LOCAL_MACHINE,
            hive_name="HKLM",
            errors=errors,
        )
    )

    values.sort(
        key=lambda item: (
            item["hive"],
            item["path"],
            item["name"],
        )
    )

    if not errors:
        status = "success"
    elif values:
        status = "partial"
    else:
        status = "error"

    return {
        "collector": "registry_collector",
        "entity_type": "registry_value",
        "collected_at": collected_at,
        "count": len(values),
        "items": values,
        "status": status,
        "errors": errors,
    }
