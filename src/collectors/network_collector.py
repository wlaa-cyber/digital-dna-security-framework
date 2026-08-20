"""
Network Collector
-----------------
Collects network interface and active connection information
from the Windows operating system.

This module is part of the Data Collection Layer of the
Digital DNA Security Framework.
"""

from datetime import datetime, timezone
from typing import Any

import psutil


def _format_address_family(
    family: Any,
) -> str:
    """
    Convert a socket address family to a readable name.
    """

    family_value = str(family)

    if family_value == "2":
        return "IPv4"

    if family_value == "23":
        return "IPv6"

    if family == psutil.AF_LINK:
        return "MAC"

    return family_value


def _format_connection_type(
    connection_type: Any,
) -> str:
    """
    Convert a socket type to a readable protocol name.
    """

    if connection_type == 1:
        return "TCP"

    if connection_type == 2:
        return "UDP"

    return str(connection_type)


def _get_interfaces() -> list[dict[str, Any]]:
    """
    Collect information about available network interfaces.

    Returns:
        A sorted list containing network interface information.
    """

    interfaces: list[dict[str, Any]] = []

    try:
        addresses = psutil.net_if_addrs()
        statistics = psutil.net_if_stats()

    except (
        psutil.AccessDenied,
        OSError,
    ):
        return interfaces

    for interface_name, interface_addresses in addresses.items():
        stats = statistics.get(interface_name)

        interface_information: dict[str, Any] = {
            "name": interface_name,
            "is_up": stats.isup if stats else None,
            "speed_mbps": stats.speed if stats else None,
            "mtu": stats.mtu if stats else None,
            "addresses": [],
        }

        for address in interface_addresses:
            interface_information[
                "addresses"
            ].append(
                {
                    "family": _format_address_family(
                        address.family
                    ),
                    "address": address.address,
                    "netmask": address.netmask,
                    "broadcast": address.broadcast,
                }
            )

        interfaces.append(
            interface_information
        )

    interfaces.sort(
        key=lambda item: item["name"].lower()
    )

    return interfaces


def _get_connections() -> list[dict[str, Any]]:
    """
    Collect active Internet protocol connections.

    Returns:
        A sorted list containing network connection information.
    """

    connections: list[dict[str, Any]] = []

    try:
        network_connections = psutil.net_connections(
            kind="inet"
        )

    except (
        psutil.AccessDenied,
        OSError,
    ):
        return connections

    for connection in network_connections:
        local_address = None
        remote_address = None

        if connection.laddr:
            local_address = {
                "ip": connection.laddr.ip,
                "port": connection.laddr.port,
            }

        if connection.raddr:
            remote_address = {
                "ip": connection.raddr.ip,
                "port": connection.raddr.port,
            }

        connections.append(
            {
                "family": _format_address_family(
                    connection.family
                ),
                "protocol": _format_connection_type(
                    connection.type
                ),
                "status": connection.status,
                "local_address": local_address,
                "remote_address": remote_address,
                "pid": connection.pid,
            }
        )

    connections.sort(
        key=lambda item: (
            item["pid"]
            if item["pid"] is not None
            else -1,
            item["status"] or "",
        )
    )

    return connections


def collect_network() -> dict[str, Any]:
    """
    Collect network information from Windows.

    Returns:
        A structured dictionary containing collection metadata
        and network information.
    """

    collected_at = datetime.now(
        timezone.utc
    ).isoformat()

    interfaces = _get_interfaces()
    connections = _get_connections()

    items = {
        "interfaces": interfaces,
        "connections": connections,
    }

    return {
        "collector": "network_collector",
        "entity_type": "network",
        "collected_at": collected_at,
        "interface_count": len(interfaces),
        "connection_count": len(connections),
        "items": items,
    }