"""
System Identity Graph Builder
-----------------------------
Builds a graph representation of the normalized
system entities and their relationships.

This module is part of the Graph Construction Layer
of the Digital DNA Security Framework.
"""

from typing import Any

import networkx as nx


def build_system_identity_graph(
    normalized_data: dict[str, Any],
) -> nx.MultiDiGraph:
    """
    Build a System Identity Graph from normalized entities.
    """

    graph = nx.MultiDiGraph()

    entities = normalized_data.get("entities", [])

    # Add all normalized entities as nodes.
    for entity in entities:
        entity_id = entity.get("id")
        entity_type = entity.get("type")
        properties = entity.get("properties", {})

        if not entity_id or not entity_type:
            continue

        graph.add_node(
            entity_id,
            entity_type=entity_type,
            **properties,
        )

    # Create lookup tables for processes and signatures.
    process_by_pid = {}
    signature_by_path = {}

    for entity in entities:
        entity_type = entity.get("type")
        properties = entity.get("properties", {})

        if entity_type == "process":
            pid = properties.get("pid")

            if pid is not None:
                process_by_pid[pid] = entity.get("id")

        elif entity_type == "digital_signature":
            path = properties.get("path")

            if path:
                signature_by_path[
                    str(path).lower()
                ] = entity.get("id")

    # Create Parent Process -> Child Process relationships.
    for entity in entities:
        if entity.get("type") != "process":
            continue

        child_id = entity.get("id")
        parent_pid = entity.get(
            "properties",
            {},
        ).get("parent_pid")

        parent_id = process_by_pid.get(parent_pid)

        if (
            parent_id
            and child_id
            and parent_id != child_id
        ):
            graph.add_edge(
                parent_id,
                child_id,
                relationship="parent_of",
            )

    # Create Process -> Network Connection relationships.
    for entity in entities:
        if entity.get("type") != "network_connection":
            continue

        connection_id = entity.get("id")
        pid = entity.get("properties", {}).get("pid")

        process_id = process_by_pid.get(pid)

        if process_id and connection_id:
            graph.add_edge(
                process_id,
                connection_id,
                relationship="has_connection",
            )

    # Create Service -> Process relationships.
    for entity in entities:
        if entity.get("type") != "service":
            continue

        service_id = entity.get("id")
        pid = entity.get("properties", {}).get("pid")

        process_id = process_by_pid.get(pid)

        if (
            service_id
            and process_id
            and pid not in (None, 0)
        ):
            graph.add_edge(
                service_id,
                process_id,
                relationship="runs_as_process",
            )

    # Create Process -> Digital Signature relationships.
    for entity in entities:
        if entity.get("type") != "process":
            continue

        process_id = entity.get("id")
        path = entity.get(
            "properties",
            {},
        ).get("path")

        if not path:
            continue

        signature_id = signature_by_path.get(
            str(path).lower()
        )

        if process_id and signature_id:
            graph.add_edge(
                process_id,
                signature_id,
                relationship="has_signature",
            )

    return graph