"""
Data Normalizer
---------------
Transforms collected system snapshot data into a unified
structure suitable for System Identity Graph construction.

This module is part of the Normalization Layer of the
Digital DNA Security Framework.
"""

from typing import Any


def _create_entity(
    entity_type: str,
    entity_id: str,
    properties: dict[str, Any],
) -> dict[str, Any]:
    """
    Create a normalized entity with a unified structure.
    """

    return {
        "id": entity_id,
        "type": entity_type,
        "properties": properties,
    }


def _normalize_processes(
    processes: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Normalize process records into unified entities.
    """

    entities = []

    for process in processes:
        pid = process.get("pid")

        if pid is None:
            continue

        entity = _create_entity(
            entity_type="process",
            entity_id=f"process:{pid}",
            properties=process,
        )

        entities.append(entity)

    return entities


def _normalize_services(
    services: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Normalize service records into unified entities.
    """

    entities = []

    for service in services:
        name = service.get("name")

        if not name:
            continue

        entity = _create_entity(
            entity_type="service",
            entity_id=f"service:{name.lower()}",
            properties=service,
        )

        entities.append(entity)

    return entities


def _normalize_registry(
    registry_values: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Normalize Registry records into unified entities.
    """

    entities = []

    for registry_value in registry_values:
        hive = registry_value.get("hive")
        path = registry_value.get("path")
        name = registry_value.get("name")

        if not hive or not path or name is None:
            continue

        entity = _create_entity(
            entity_type="registry_value",
            entity_id=f"registry:{hive}:{path}:{name}",
            properties=registry_value,
        )

        entities.append(entity)

    return entities


def _task_completeness_score(
    task: dict[str, Any],
) -> int:
    """
    Calculate how complete a scheduled task record is.

    Fields containing None, empty values, or 'N/A' are not
    considered useful information.
    """

    score = 0

    for value in task.values():
        if value is None:
            continue

        if isinstance(value, str):
            if not value.strip():
                continue

            if value.strip().upper() == "N/A":
                continue

        score += 1

    return score


def _normalize_scheduled_tasks(
    tasks: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Normalize scheduled task records into unified entities.

    If multiple records represent the same task, keep the
    most complete record based on available information.
    """

    unique_tasks: dict[str, dict[str, Any]] = {}

    for task in tasks:
        task_name = task.get("task_name")

        if not task_name:
            continue

        task_id = (
            f"scheduled_task:{task_name.lower()}"
        )

        existing_task = unique_tasks.get(task_id)

        if existing_task is None:
            unique_tasks[task_id] = task

        elif (
            _task_completeness_score(task)
            > _task_completeness_score(existing_task)
        ):
            unique_tasks[task_id] = task

    entities = []

    for task_id, task in unique_tasks.items():
        entity = _create_entity(
            entity_type="scheduled_task",
            entity_id=task_id,
            properties=task,
        )

        entities.append(entity)

    return entities


def _normalize_startup(
    startup_items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Normalize Startup records into unified entities.
    """

    entities = []

    for startup_item in startup_items:
        path = startup_item.get("path")

        if not path:
            continue

        entity = _create_entity(
            entity_type="startup_item",
            entity_id=f"startup:{path.lower()}",
            properties=startup_item,
        )

        entities.append(entity)

    return entities


def _normalize_installed_applications(
    applications: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Normalize installed application records into unified entities.
    """

    entities = []

    for application in applications:
        name = application.get("name")
        version = application.get("version") or "unknown"

        if not name:
            continue

        entity = _create_entity(
            entity_type="installed_application",
            entity_id=(
                f"installed_application:"
                f"{name.lower()}:{str(version).lower()}"
            ),
            properties=application,
        )

        entities.append(entity)

    return entities


def _normalize_digital_signatures(
    signatures: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Normalize digital signature records into unified entities.
    """

    entities = []

    for signature in signatures:
        path = signature.get("path")

        if not path:
            continue

        entity = _create_entity(
            entity_type="digital_signature",
            entity_id=f"digital_signature:{path.lower()}",
            properties=signature,
        )

        entities.append(entity)

    return entities


def _normalize_network_interfaces(
    interfaces: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Normalize network interface records into unified entities.
    """

    entities = []

    for interface in interfaces:
        name = interface.get("name")

        if not name:
            continue

        entity = _create_entity(
            entity_type="network_interface",
            entity_id=f"network_interface:{name.lower()}",
            properties=interface,
        )

        entities.append(entity)

    return entities


def _normalize_network_connections(
    connections: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Normalize network connection records into unified entities.
    """

    entities = []

    for index, connection in enumerate(connections):
        pid = connection.get("pid")
        local_address = connection.get("local_address")
        remote_address = connection.get("remote_address")

        entity_id = (
            f"network_connection:{pid}:"
            f"{local_address}:{remote_address}:{index}"
        )

        entity = _create_entity(
            entity_type="network_connection",
            entity_id=entity_id,
            properties=connection,
        )

        entities.append(entity)

    return entities


def normalize_snapshot(
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    """
    Normalize all supported data from a system snapshot.
    """

    collectors = snapshot.get(
        "collectors",
        {}
    )

    entities = []

    entities.extend(
        _normalize_processes(
            collectors.get(
                "processes",
                {}
            ).get("items", [])
        )
    )

    entities.extend(
        _normalize_services(
            collectors.get(
                "services",
                {}
            ).get("items", [])
        )
    )

    entities.extend(
        _normalize_registry(
            collectors.get(
                "registry",
                {}
            ).get("items", [])
        )
    )

    entities.extend(
        _normalize_scheduled_tasks(
            collectors.get(
                "scheduled_tasks",
                {}
            ).get("items", [])
        )
    )

    entities.extend(
        _normalize_startup(
            collectors.get(
                "startup",
                {}
            ).get("items", [])
        )
    )

    entities.extend(
        _normalize_installed_applications(
            collectors.get(
                "installed_applications",
                {}
            ).get("items", [])
        )
    )

    entities.extend(
        _normalize_digital_signatures(
            collectors.get(
                "digital_signatures",
                {}
            ).get("items", [])
        )
    )

    network_data = collectors.get(
        "network",
        {}
    ).get("items", {})

    entities.extend(
        _normalize_network_interfaces(
            network_data.get(
                "interfaces",
                []
            )
        )
    )

    entities.extend(
        _normalize_network_connections(
            network_data.get(
                "connections",
                []
            )
        )
    )

    return {
        "normalization": {
            "entity_count": len(entities),
        },
        "entities": entities,
    }