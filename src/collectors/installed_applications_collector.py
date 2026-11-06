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
    errors: list[dict[str, str]] | None = None,
    component: str = "registry_value",
) -> Any:
    """
    Read an optional Registry value.

    Missing values are normal. Other read failures are recorded.
    """

    try:
        value, _ = winreg.QueryValueEx(key, name)
        return value

    except FileNotFoundError:
        return None

    except OSError as exc:
        if errors is not None:
            errors.append({
                "component": f"{component}:{name}",
                "error_type": type(exc).__name__,
                "message": str(exc),
            })
        return None

def _collect_from_location(
    hive: Any,
    hive_name: str,
    path: str,
    scope: str,
    errors: list[dict[str, str]] | None = None,
) -> list[dict[str, Any]]:
    """
    Collect installed applications from one Registry location.

    Missing locations and keys are normal. Access and read failures
    are recorded in the supplied errors list.
    """

    applications: list[dict[str, Any]] = []

    if errors is None:
        errors = []

    try:
        root_key = winreg.OpenKey(
            hive,
            path,
            0,
            winreg.KEY_READ,
        )

    except FileNotFoundError:
        return applications

    except OSError as exc:
        errors.append({
            "component": f"{hive_name}\\{path}",
            "error_type": type(exc).__name__,
            "message": str(exc),
        })
        return applications

    try:
        try:
            subkey_count = winreg.QueryInfoKey(root_key)[0]

        except OSError as exc:
            errors.append({
                "component": f"{hive_name}\\{path}",
                "error_type": type(exc).__name__,
                "message": str(exc),
            })
            return applications

        for index in range(subkey_count):

            try:
                subkey_name = winreg.EnumKey(
                    root_key,
                    index,
                )

            except FileNotFoundError:
                continue

            except OSError as exc:
                errors.append({
                    "component": f"{hive_name}\\{path}\\subkey[{index}]",
                    "error_type": type(exc).__name__,
                    "message": str(exc),
                })
                continue

            try:
                subkey = winreg.OpenKey(
                    root_key,
                    subkey_name,
                    0,
                    winreg.KEY_READ,
                )

            except FileNotFoundError:
                continue

            except OSError as exc:
                errors.append({
                    "component": f"{hive_name}\\{path}\\{subkey_name}",
                    "error_type": type(exc).__name__,
                    "message": str(exc),
                })
                continue

            try:
                component = (
                    f"{hive_name}\\{path}\\{subkey_name}"
                )

                display_name = _read_value(
                    subkey,
                    "DisplayName",
                    errors,
                    component,
                )

                if not display_name:
                    continue

                application = {
                    "name": str(display_name),
                    "version": _read_value(
                        subkey, "DisplayVersion", errors, component
                    ),
                    "publisher": _read_value(
                        subkey, "Publisher", errors, component
                    ),
                    "install_date": _read_value(
                        subkey, "InstallDate", errors, component
                    ),
                    "install_location": _read_value(
                        subkey, "InstallLocation", errors, component
                    ),
                    "uninstall_string": _read_value(
                        subkey, "UninstallString", errors, component
                    ),
                    "display_icon": _read_value(
                        subkey, "DisplayIcon", errors, component
                    ),
                    "scope": scope,
                    "registry_hive": hive_name,
                    "registry_path": f"{path}\\{subkey_name}",
                }

                applications.append(application)

            finally:
                winreg.CloseKey(subkey)

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
    Missing Registry locations are normal; access/read failures
    are reported in the collection result.
    """

    collected_at = datetime.now(
        timezone.utc
    ).isoformat()

    applications: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []

    for location in UNINSTALL_LOCATIONS:
        applications.extend(
            _collect_from_location(
                hive=location["hive"],
                hive_name=location["hive_name"],
                path=location["path"],
                scope=location["scope"],
                errors=errors,
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

    if not errors:
        status = "success"
    elif applications:
        status = "partial"
    else:
        status = "error"

    return {
        "collector": "installed_applications_collector",
        "entity_type": "installed_application",
        "collected_at": collected_at,
        "count": len(applications),
        "items": applications,
        "status": status,
        "errors": errors,
    }
