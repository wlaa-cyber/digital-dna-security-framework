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


def _get_interfaces() -> list[dict[str, Any]]:
    """
    Collect information about available network interfaces.

    Returns:
        A sorted list containing network interface information.
    """

    interfaces: list[dict[str, Any]] = []

    addresses = psutil.net_if_addrs()
    statistics = psutil.net_if_stats()

    for interface_name, interface_addresses in addresses.items():
        stats = statistics.get(interface_name)

        interface_information = {
            "name": interface_name,
            "is_up": stats.isup if stats else None,
            "speed_mbps": stats.speed if stats else None,
            "mtu": stats.mtu if stats else None,
            "addresses": [],
        }

        for address in interface_addresses:
            interface_information["addresses"].append(
                {
                    "family": str(address.family),
                    "address": address.address,
                    "netmask": address.netmask,
                    "broadcast": address.broadcast,
                }
            )

        interfaces.append(interface_information)

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

    except psutil.AccessDenied:
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
                "family": str(connection.family),
                "type": str(connection.type),
                "status": connection.status,
                "local_address": local_address,
                "remote_address": remote_address,
                "pid": connection.pid,
            }
        )

    connections.sort(
        key=lambda item: (
            item["pid"] if item["pid"] is not None else -1,
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

    collected_at = datetime.now(timezone.utc).isoformat()

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