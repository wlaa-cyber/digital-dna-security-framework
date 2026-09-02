"""
Network Context
---------------

Provides evidence-based contextual analysis for network connections
observed in the System Identity Graph.

Responsibilities:
- Describe network connection context.
- Correlate network connections with their owning processes.
- Analyze connection properties and endpoints.
- Identify added, removed, and changed network relationships.
- Distinguish local/private endpoints from external endpoints.
- Provide evidence strength without producing a final security verdict.

This module does NOT:
- Calculate GED.
- Calculate Jaccard similarity.
- Calculate SIS.
- Produce a final malicious/legitimate decision.
- Treat a network port alone as malicious evidence.
"""

from __future__ import annotations

import ipaddress
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RELATIONSHIP_HAS_CONNECTION = "has_connection"

NODE_TYPE_PROCESS = "process"
NODE_TYPE_NETWORK_CONNECTION = "network_connection"

STATE_EXISTING = "EXISTING"
STATE_NEW = "NEW"
STATE_REMOVED = "REMOVED"
STATE_CHANGED = "CHANGED"
STATE_UNAVAILABLE = "UNAVAILABLE"

EVIDENCE_STRONG = "Strong"
EVIDENCE_MODERATE = "Moderate"
EVIDENCE_INFORMATIONAL = "Informational"
EVIDENCE_NONE = "None"

ENDPOINT_LOCAL = "LOCAL"
ENDPOINT_PRIVATE = "PRIVATE"
ENDPOINT_LOOPBACK = "LOOPBACK"
ENDPOINT_LINK_LOCAL = "LINK_LOCAL"
ENDPOINT_EXTERNAL = "EXTERNAL"
ENDPOINT_UNAVAILABLE = "UNAVAILABLE"
ENDPOINT_INVALID = "INVALID"

PROTOCOL_TCP = "TCP"
PROTOCOL_UDP = "UDP"

STATUS_ESTABLISHED = "ESTABLISHED"
STATUS_LISTEN = "LISTEN"
STATUS_TIME_WAIT = "TIME_WAIT"
STATUS_CLOSE_WAIT = "CLOSE_WAIT"
STATUS_SYN_SENT = "SYN_SENT"
STATUS_SYN_RECV = "SYN_RECV"
STATUS_FIN_WAIT1 = "FIN_WAIT1"
STATUS_FIN_WAIT2 = "FIN_WAIT2"
STATUS_CLOSING = "CLOSING"
STATUS_LAST_ACK = "LAST_ACK"
STATUS_NONE = "NONE"
STATUS_UNKNOWN = "UNKNOWN"


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def _safe_value(value: Any) -> Any:
    """
    Normalize unavailable textual values to None.
    """

    if value is None:
        return None

    if isinstance(value, str):
        normalized = value.strip()

        if not normalized:
            return None

        if normalized.lower() in {
            "n/a",
            "na",
            "none",
            "null",
            "unknown",
            "not available",
            "not_available",
            "-",
        }:
            return None

        return normalized

    return value


def _get_node_type(
    graph,
    node_id: Any,
) -> str | None:
    """
    Return the graph node type.
    """

    if graph is None:
        return None

    if node_id not in graph:
        return None

    return graph.nodes[node_id].get("entity_type")


def _get_node_properties(
    graph,
    node_id: Any,
) -> dict[str, Any]:
    """
    Return a copy of node properties excluding entity_type.
    """

    if graph is None:
        return {}

    if node_id not in graph:
        return {}

    properties = dict(graph.nodes[node_id])

    properties.pop("entity_type", None)

    return properties


def _normalize_protocol(value: Any) -> str | None:
    """
    Normalize network protocol values.
    """

    value = _safe_value(value)

    if value is None:
        return None

    normalized = str(value).strip().upper()

    if normalized in {"TCP", "TCP6"}:
        return PROTOCOL_TCP

    if normalized in {"UDP", "UDP6"}:
        return PROTOCOL_UDP

    return normalized


def _normalize_status(value: Any) -> str | None:
    """
    Normalize connection status.
    """

    value = _safe_value(value)

    if value is None:
        return None

    return str(value).strip().upper()


# ---------------------------------------------------------------------------
# Endpoint helpers
# ---------------------------------------------------------------------------

def _extract_ip(
    endpoint: Any,
) -> str | None:
    """
    Extract an IP address from a normalized endpoint.

    Expected structure:
        {
            "ip": "...",
            "port": ...
        }
    """

    if endpoint is None:
        return None

    if isinstance(endpoint, dict):
        return _safe_value(endpoint.get("ip"))

    if isinstance(endpoint, str):
        value = endpoint.strip()

        if not value:
            return None

        return value

    return None


def _extract_port(
    endpoint: Any,
) -> int | None:
    """
    Extract a port from a normalized endpoint.
    """

    if endpoint is None:
        return None

    if isinstance(endpoint, dict):
        port = endpoint.get("port")

        if port is None:
            return None

        try:
            return int(port)
        except (TypeError, ValueError):
            return None

    return None


def _classify_ip(
    ip_value: Any,
) -> str:
    """
    Classify an IP endpoint.

    This classification is contextual evidence only.
    """

    ip_value = _safe_value(ip_value)

    if ip_value is None:
        return ENDPOINT_UNAVAILABLE

    try:
        ip = ipaddress.ip_address(str(ip_value))
    except ValueError:
        return ENDPOINT_INVALID

    if ip.is_loopback:
        return ENDPOINT_LOOPBACK

    if ip.is_link_local:
        return ENDPOINT_LINK_LOCAL

    if ip.is_private:
        return ENDPOINT_PRIVATE

    return ENDPOINT_EXTERNAL


def classify_endpoint(
    endpoint: Any,
) -> dict[str, Any]:
    """
    Classify a local or remote endpoint.
    """

    ip = _extract_ip(endpoint)
    port = _extract_port(endpoint)

    classification = _classify_ip(ip)

    return {
        "ip": ip,
        "port": port,
        "classification": classification,
        "is_external": classification == ENDPOINT_EXTERNAL,
        "is_private": classification == ENDPOINT_PRIVATE,
        "is_loopback": classification == ENDPOINT_LOOPBACK,
    }


# ---------------------------------------------------------------------------
# Process correlation
# ---------------------------------------------------------------------------

def _find_process_for_connection(
    graph,
    connection_node_id: Any,
) -> Any | None:
    """
    Find the process connected to a network connection node through
    the existing has_connection relationship.
    """

    if graph is None:
        return None

    if connection_node_id not in graph:
        return None

    for source, target, data in graph.in_edges(
        connection_node_id,
        data=True,
    ):
        if data.get("relationship") != RELATIONSHIP_HAS_CONNECTION:
            continue

        if _get_node_type(graph, source) == NODE_TYPE_PROCESS:
            return source

    return None


def _find_connections_for_process(
    graph,
    process_node_id: Any,
) -> list[Any]:
    """
    Return network connection nodes owned by a process.
    """

    if graph is None:
        return []

    if process_node_id not in graph:
        return []

    connections = []

    for _, target, data in graph.out_edges(
        process_node_id,
        data=True,
    ):
        if data.get("relationship") != RELATIONSHIP_HAS_CONNECTION:
            continue

        if _get_node_type(graph, target) == NODE_TYPE_NETWORK_CONNECTION:
            connections.append(target)

    return sorted(connections)


def _relationship_exists(
    graph,
    source_node_id: Any,
    target_node_id: Any,
    relationship: str,
) -> bool:
    """
    Check whether a specific relationship exists.
    """

    if graph is None:
        return False

    if source_node_id not in graph:
        return False

    if target_node_id not in graph:
        return False

    if not graph.has_edge(source_node_id, target_node_id):
        return False

    for _, data in graph[source_node_id][target_node_id].items():
        if data.get("relationship") == relationship:
            return True

    return False


# ---------------------------------------------------------------------------
# Connection description
# ---------------------------------------------------------------------------

def _build_connection_reference(
    graph,
    connection_node_id: Any,
) -> dict[str, Any]:
    """
    Build a structured reference for a network connection.
    """

    properties = _get_node_properties(
        graph,
        connection_node_id,
    )

    process_node_id = _find_process_for_connection(
        graph,
        connection_node_id,
    )

    process_properties = _get_node_properties(
        graph,
        process_node_id,
    )

    local_endpoint = classify_endpoint(
        properties.get("local_address")
    )

    remote_endpoint = classify_endpoint(
        properties.get("remote_address")
    )

    protocol = _normalize_protocol(
        properties.get("protocol")
    )

    status = _normalize_status(
        properties.get("status")
    )

    return {
        "connection_node_id": connection_node_id,
        "entity_type": _get_node_type(
            graph,
            connection_node_id,
        ),
        "process_node_id": process_node_id,
        "process": {
            "node_id": process_node_id,
            "pid": process_properties.get("pid"),
            "name": process_properties.get("name"),
            "path": process_properties.get("path"),
        },
        "protocol": protocol,
        "status": status,
        "local_endpoint": local_endpoint,
        "remote_endpoint": remote_endpoint,
        "raw_properties": properties,
    }


# ---------------------------------------------------------------------------
# Context assessment
# ---------------------------------------------------------------------------

def _calculate_evidence_strength(
    connection_state: str,
    process_known: bool,
    remote_classification: str,
    protocol: str | None,
    status: str | None,
    property_changes: list[str] | None = None,
) -> str:
    """
    Determine contextual evidence strength.

    This is NOT a risk score and does not mean maliciousness.
    """

    property_changes = property_changes or []

    if connection_state == STATE_UNAVAILABLE:
        return EVIDENCE_NONE

    score = 0

    if connection_state == STATE_NEW:
        score += 1

    if connection_state == STATE_CHANGED:
        score += 1

    if remote_classification == ENDPOINT_EXTERNAL:
        score += 1

    if not process_known:
        score += 1

    if protocol in {
        PROTOCOL_TCP,
        PROTOCOL_UDP,
    }:
        score += 0

    if status == STATUS_ESTABLISHED:
        score += 1

    if property_changes:
        score += 1

    if score >= 4:
        return EVIDENCE_STRONG

    if score >= 2:
        return EVIDENCE_MODERATE

    return EVIDENCE_INFORMATIONAL


def _build_context_assessment(
    connection_state: str,
    process_known: bool,
    remote_classification: str,
    status: str | None,
    property_changes: list[str],
) -> str:
    """
    Build a neutral contextual assessment.
    """

    if connection_state == STATE_UNAVAILABLE:
        return (
            "Network context could not be determined from the "
            "available graph evidence."
        )

    observations = []

    if connection_state == STATE_NEW:
        observations.append(
            "A new network connection was observed."
        )

    elif connection_state == STATE_REMOVED:
        observations.append(
            "A previously observed network connection is no longer present."
        )

    elif connection_state == STATE_CHANGED:
        observations.append(
            "A previously observed network connection has changed."
        )

    else:
        observations.append(
            "The network connection is present in the current graph."
        )

    if process_known:
        observations.append(
            "The connection is associated with a known process node."
        )
    else:
        observations.append(
            "The owning process could not be resolved in the graph."
        )

    if remote_classification == ENDPOINT_EXTERNAL:
        observations.append(
            "The remote endpoint is classified as external."
        )

    elif remote_classification == ENDPOINT_PRIVATE:
        observations.append(
            "The remote endpoint is classified as private/internal."
        )

    elif remote_classification == ENDPOINT_LOOPBACK:
        observations.append(
            "The remote endpoint is a loopback address."
        )

    elif remote_classification == ENDPOINT_LINK_LOCAL:
        observations.append(
            "The remote endpoint is link-local."
        )

    elif remote_classification == ENDPOINT_UNAVAILABLE:
        observations.append(
            "The remote endpoint is unavailable."
        )

    if status == STATUS_ESTABLISHED:
        observations.append(
            "The connection status is ESTABLISHED."
        )

    if property_changes:
        observations.append(
            "Network connection properties changed: "
            + ", ".join(sorted(property_changes))
            + "."
        )

    return " ".join(observations)


# ---------------------------------------------------------------------------
# Single connection analysis
# ---------------------------------------------------------------------------

def analyze_network_connection(
    graph,
    connection_node_id: Any,
    connection_state: str = STATE_EXISTING,
    property_changes: list[str] | None = None,
) -> dict[str, Any]:
    """
    Analyze one network connection in a graph.

    The result is evidence only.
    """

    property_changes = property_changes or []

    if (
        graph is None
        or connection_node_id not in graph
        or _get_node_type(graph, connection_node_id)
        != NODE_TYPE_NETWORK_CONNECTION
    ):
        return {
            "connection_node_id": connection_node_id,
            "entity_type": NODE_TYPE_NETWORK_CONNECTION,
            "connection_state": STATE_UNAVAILABLE,
            "process_known": False,
            "connection": None,
            "context_assessment": (
                "Network connection is unavailable in the graph."
            ),
            "evidence_strength": EVIDENCE_NONE,
        }

    connection = _build_connection_reference(
        graph,
        connection_node_id,
    )

    process_known = (
        connection.get("process_node_id") is not None
    )

    remote_classification = (
        connection["remote_endpoint"]["classification"]
    )

    evidence_strength = _calculate_evidence_strength(
        connection_state=connection_state,
        process_known=process_known,
        remote_classification=remote_classification,
        protocol=connection.get("protocol"),
        status=connection.get("status"),
        property_changes=property_changes,
    )

    context_assessment = _build_context_assessment(
        connection_state=connection_state,
        process_known=process_known,
        remote_classification=remote_classification,
        status=connection.get("status"),
        property_changes=property_changes,
    )

    return {
        "connection_node_id": connection_node_id,
        "entity_type": NODE_TYPE_NETWORK_CONNECTION,
        "connection_state": connection_state,
        "process_known": process_known,
        "connection": connection,
        "property_changes": sorted(property_changes),
        "context_assessment": context_assessment,
        "evidence_strength": evidence_strength,
    }


# ---------------------------------------------------------------------------
# Process network context
# ---------------------------------------------------------------------------

def analyze_process_network_context(
    graph,
    process_node_id: Any,
) -> dict[str, Any]:
    """
    Analyze all network connections associated with one process.
    """

    if (
        graph is None
        or process_node_id not in graph
        or _get_node_type(graph, process_node_id)
        != NODE_TYPE_PROCESS
    ):
        return {
            "process_node_id": process_node_id,
            "process_known": False,
            "connections": [],
            "connection_count": 0,
        }

    process_properties = _get_node_properties(
        graph,
        process_node_id,
    )

    connection_ids = _find_connections_for_process(
        graph,
        process_node_id,
    )

    connections = []

    for connection_id in connection_ids:
        connections.append(
            analyze_network_connection(
                graph,
                connection_id,
                connection_state=STATE_EXISTING,
            )
        )

    return {
        "process_node_id": process_node_id,
        "process_known": True,
        "process": {
            "pid": process_properties.get("pid"),
            "name": process_properties.get("name"),
            "path": process_properties.get("path"),
        },
        "connections": connections,
        "connection_count": len(connections),
    }


# ---------------------------------------------------------------------------
# Graph-wide network context
# ---------------------------------------------------------------------------

def analyze_all_network_connections(
    graph,
) -> dict[str, Any]:
    """
    Analyze all network connection nodes in a graph.
    """

    if graph is None:
        return {
            "connection_count": 0,
            "connections": [],
        }

    connection_ids = sorted(
        node_id
        for node_id in graph.nodes()
        if _get_node_type(graph, node_id)
        == NODE_TYPE_NETWORK_CONNECTION
    )

    connections = []

    for connection_id in connection_ids:
        connections.append(
            analyze_network_connection(
                graph,
                connection_id,
            )
        )

    return {
        "connection_count": len(connections),
        "connections": connections,
    }


# ---------------------------------------------------------------------------
# Comparison helpers
# ---------------------------------------------------------------------------

def _get_network_connection_changes(
    comparison_result: dict[str, Any],
) -> tuple[list[Any], list[Any], dict[Any, dict[str, Any]]]:
    """
    Extract network connection node changes from Comparator output.
    """

    added_nodes = []
    removed_nodes = []
    changed_nodes = {}

    for node_id in comparison_result.get(
        "added_nodes",
        [],
    ):
        added_nodes.append(node_id)

    for node_id in comparison_result.get(
        "removed_nodes",
        [],
    ):
        removed_nodes.append(node_id)

    for node_id, changes in comparison_result.get(
        "changed_nodes",
        {},
    ).items():
        changed_nodes[node_id] = changes

    return (
        added_nodes,
        removed_nodes,
        changed_nodes,
    )


def _filter_network_nodes(
    node_ids: list[Any],
    graph,
) -> list[Any]:
    """
    Keep only network connection nodes.
    """

    if graph is None:
        return []

    return sorted(
        node_id
        for node_id in node_ids
        if node_id in graph
        and _get_node_type(
            graph,
            node_id,
        ) == NODE_TYPE_NETWORK_CONNECTION
    )


def _filter_network_changed_nodes(
    changed_nodes: dict[Any, dict[str, Any]],
    graph,
) -> dict[Any, dict[str, Any]]:
    """
    Keep only changed network connection nodes.
    """

    if graph is None:
        return {}

    return {
        node_id: changes
        for node_id, changes in changed_nodes.items()
        if node_id in graph
        and _get_node_type(
            graph,
            node_id,
        ) == NODE_TYPE_NETWORK_CONNECTION
    }


def _build_network_edge_set(
    comparison_result: dict[str, Any],
    edge_key: str,
) -> list[tuple[Any, Any, Any]]:
    """
    Extract has_connection relationships from Comparator edge changes.
    """

    edges = []

    for edge in comparison_result.get(
        edge_key,
        [],
    ):
        if len(edge) != 3:
            continue

        source, target, relationship = edge

        if relationship != RELATIONSHIP_HAS_CONNECTION:
            continue

        edges.append(
            (
                source,
                target,
                relationship,
            )
        )

    return sorted(edges)


# ---------------------------------------------------------------------------
# Relationship analysis
# ---------------------------------------------------------------------------

def _build_relationship_evidence(
    graph,
    source_node_id: Any,
    target_node_id: Any,
    relationship_state: str,
) -> dict[str, Any]:
    """
    Build evidence for a process -> network connection relationship.
    """

    source_type = _get_node_type(
        graph,
        source_node_id,
    )

    target_type = _get_node_type(
        graph,
        target_node_id,
    )

    source_known = source_type is not None
    target_known = target_type is not None

    target_connection = None

    if target_type == NODE_TYPE_NETWORK_CONNECTION:
        target_connection = analyze_network_connection(
            graph,
            target_node_id,
            connection_state=relationship_state,
        )

    if (
        relationship_state == STATE_UNAVAILABLE
    ):
        evidence_strength = EVIDENCE_NONE

    elif (
        source_known
        and target_known
        and target_type == NODE_TYPE_NETWORK_CONNECTION
    ):
        if relationship_state == STATE_NEW:
            evidence_strength = EVIDENCE_MODERATE

        elif relationship_state == STATE_REMOVED:
            evidence_strength = EVIDENCE_INFORMATIONAL

        else:
            evidence_strength = EVIDENCE_INFORMATIONAL

    else:
        evidence_strength = EVIDENCE_NONE

    if relationship_state == STATE_NEW:
        assessment = (
            "A new process-to-network-connection relationship "
            "was observed."
        )

    elif relationship_state == STATE_REMOVED:
        assessment = (
            "A previously observed process-to-network-connection "
            "relationship is no longer present."
        )

    else:
        assessment = (
            "The process-to-network-connection relationship is present."
        )

    return {
        "source_node_id": source_node_id,
        "target_node_id": target_node_id,
        "source_type": source_type,
        "target_type": target_type,
        "relationship": RELATIONSHIP_HAS_CONNECTION,
        "relationship_state": relationship_state,
        "source_known": source_known,
        "target_known": target_known,
        "connection_context": target_connection,
        "context_assessment": assessment,
        "evidence_strength": evidence_strength,
    }


# ---------------------------------------------------------------------------
# Change analysis
# ---------------------------------------------------------------------------

def analyze_network_changes(
    comparison_result: dict[str, Any],
    baseline_graph,
    current_graph,
) -> dict[str, Any]:
    """
    Analyze network-related changes reported by the Comparator.

    The Comparator remains authoritative for determining whether
    nodes/edges changed. This function only interprets their context.
    """

    (
        added_nodes,
        removed_nodes,
        changed_nodes,
    ) = _get_network_connection_changes(
        comparison_result
    )

    added_network_nodes = _filter_network_nodes(
        added_nodes,
        current_graph,
    )

    removed_network_nodes = _filter_network_nodes(
        removed_nodes,
        baseline_graph,
    )

    changed_network_nodes = _filter_network_changed_nodes(
        changed_nodes,
        current_graph,
    )

    added_edges = _build_network_edge_set(
        comparison_result,
        "added_edges",
    )

    removed_edges = _build_network_edge_set(
        comparison_result,
        "removed_edges",
    )

    added_relationships = []

    for source, target, _ in added_edges:
        if source not in current_graph:
            continue

        if target not in current_graph:
            continue

        added_relationships.append(
            _build_relationship_evidence(
                current_graph,
                source,
                target,
                STATE_NEW,
            )
        )

    removed_relationships = []

    for source, target, _ in removed_edges:
        if source not in baseline_graph:
            continue

        if target not in baseline_graph:
            continue

        removed_relationships.append(
            _build_relationship_evidence(
                baseline_graph,
                source,
                target,
                STATE_REMOVED,
            )
        )

    added_connection_evidence = []

    for node_id in added_network_nodes:
        added_connection_evidence.append(
            analyze_network_connection(
                current_graph,
                node_id,
                connection_state=STATE_NEW,
            )
        )

    removed_connection_evidence = []

    for node_id in removed_network_nodes:
        removed_connection_evidence.append(
            analyze_network_connection(
                baseline_graph,
                node_id,
                connection_state=STATE_REMOVED,
            )
        )

    changed_connection_evidence = []

    for node_id, changes in changed_network_nodes.items():
        changed_connection_evidence.append(
            analyze_network_connection(
                current_graph,
                node_id,
                connection_state=STATE_CHANGED,
                property_changes=list(changes.keys()),
            )
        )

    return {
        "summary": {
            "added_connections": len(
                added_connection_evidence
            ),
            "removed_connections": len(
                removed_connection_evidence
            ),
            "changed_connections": len(
                changed_connection_evidence
            ),
            "added_relationships": len(
                added_relationships
            ),
            "removed_relationships": len(
                removed_relationships
            ),
            "total_network_changes": (
                len(added_connection_evidence)
                + len(removed_connection_evidence)
                + len(changed_connection_evidence)
                + len(added_relationships)
                + len(removed_relationships)
            ),
        },
        "added_connections": added_connection_evidence,
        "removed_connections": removed_connection_evidence,
        "changed_connections": changed_connection_evidence,
        "added_relationships": added_relationships,
        "removed_relationships": removed_relationships,
    }


def analyze_network_change_for_connection(
    comparison_result: dict[str, Any],
    connection_node_id: Any,
    baseline_graph,
    current_graph,
) -> dict[str, Any]:
    """
    Analyze one network connection using Comparator output.
    """

    added_nodes = set(
        comparison_result.get(
            "added_nodes",
            [],
        )
    )

    removed_nodes = set(
        comparison_result.get(
            "removed_nodes",
            [],
        )
    )

    changed_nodes = comparison_result.get(
        "changed_nodes",
        {},
    )

    if connection_node_id in added_nodes:
        if connection_node_id in current_graph:
            return analyze_network_connection(
                current_graph,
                connection_node_id,
                connection_state=STATE_NEW,
            )

        return {
            "connection_node_id": connection_node_id,
            "connection_state": STATE_UNAVAILABLE,
            "evidence_strength": EVIDENCE_NONE,
        }

    if connection_node_id in removed_nodes:
        if connection_node_id in baseline_graph:
            return analyze_network_connection(
                baseline_graph,
                connection_node_id,
                connection_state=STATE_REMOVED,
            )

        return {
            "connection_node_id": connection_node_id,
            "connection_state": STATE_UNAVAILABLE,
            "evidence_strength": EVIDENCE_NONE,
        }

    if connection_node_id in changed_nodes:
        if connection_node_id in current_graph:
            changes = changed_nodes[
                connection_node_id
            ]

            return analyze_network_connection(
                current_graph,
                connection_node_id,
                connection_state=STATE_CHANGED,
                property_changes=list(changes.keys()),
            )

        return {
            "connection_node_id": connection_node_id,
            "connection_state": STATE_UNAVAILABLE,
            "evidence_strength": EVIDENCE_NONE,
        }

    if connection_node_id in current_graph:
        if (
            _get_node_type(
                current_graph,
                connection_node_id,
            )
            == NODE_TYPE_NETWORK_CONNECTION
        ):
            return analyze_network_connection(
                current_graph,
                connection_node_id,
                connection_state=STATE_EXISTING,
            )

    return {
        "connection_node_id": connection_node_id,
        "connection_state": STATE_UNAVAILABLE,
        "evidence_strength": EVIDENCE_NONE,
    }


# ---------------------------------------------------------------------------
# Exported API
# ---------------------------------------------------------------------------

__all__ = [
    "RELATIONSHIP_HAS_CONNECTION",
    "NODE_TYPE_PROCESS",
    "NODE_TYPE_NETWORK_CONNECTION",
    "STATE_EXISTING",
    "STATE_NEW",
    "STATE_REMOVED",
    "STATE_CHANGED",
    "STATE_UNAVAILABLE",
    "EVIDENCE_STRONG",
    "EVIDENCE_MODERATE",
    "EVIDENCE_INFORMATIONAL",
    "EVIDENCE_NONE",
    "ENDPOINT_LOCAL",
    "ENDPOINT_PRIVATE",
    "ENDPOINT_LOOPBACK",
    "ENDPOINT_LINK_LOCAL",
    "ENDPOINT_EXTERNAL",
    "ENDPOINT_UNAVAILABLE",
    "ENDPOINT_INVALID",
    "PROTOCOL_TCP",
    "PROTOCOL_UDP",
    "STATUS_ESTABLISHED",
    "STATUS_LISTEN",
    "STATUS_TIME_WAIT",
    "STATUS_CLOSE_WAIT",
    "STATUS_SYN_SENT",
    "STATUS_SYN_RECV",
    "STATUS_FIN_WAIT1",
    "STATUS_FIN_WAIT2",
    "STATUS_CLOSING",
    "STATUS_LAST_ACK",
    "analyze_network_connection",
    "analyze_process_network_context",
    "analyze_all_network_connections",
    "analyze_network_changes",
    "analyze_network_change_for_connection",
    "classify_endpoint",
]