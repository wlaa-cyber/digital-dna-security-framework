"""
Identity Context
----------------
Stage 6 - Context Analyzer

This module describes WHAT changed in the System Identity Graph.

Responsibilities:
- Identify added nodes.
- Identify removed nodes.
- Describe changed node properties.
- Identify added edges.
- Identify removed edges.
- Preserve baseline/current values for changed properties.

This module does NOT:
- Perform graph comparison itself.
- Calculate GED.
- Calculate Jaccard similarity.
- Decide whether a change is malicious or legitimate.
- Calculate SIS.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def _safe_value(value: Any) -> Any:
    """
    Convert values into JSON-friendly/simple representations when possible.
    """
    if value is None:
        return None

    if isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, (list, tuple)):
        return [_safe_value(item) for item in value]

    if isinstance(value, dict):
        return {
            str(key): _safe_value(item)
            for key, item in value.items()
        }

    return str(value)


def _get_node_type(
    graph: Any,
    node_id: str,
) -> Optional[str]:
    """
    Return the entity type of a node if available.
    """
    if graph is None or node_id not in graph:
        return None

    node_data = graph.nodes[node_id]

    entity_type = node_data.get("entity_type")

    if entity_type is not None:
        return str(entity_type)

    # Fallback for graphs that may use "type".
    entity_type = node_data.get("type")

    if entity_type is not None:
        return str(entity_type)

    return None


def _get_node_properties(
    graph: Any,
    node_id: str,
) -> Dict[str, Any]:
    """
    Return node properties while excluding structural metadata.
    """
    if graph is None or node_id not in graph:
        return {}

    node_data = dict(graph.nodes[node_id])

    # entity_type describes the node itself and is not treated as
    # a changed security property here.
    node_data.pop("entity_type", None)
    node_data.pop("type", None)

    return {
        str(key): _safe_value(value)
        for key, value in node_data.items()
    }


def _edge_to_dict(
    edge: Any,
) -> Dict[str, Any]:
    """
    Convert an edge tuple into a structured representation.

    Expected format:
        (source, target, relationship)

    The graph comparator currently represents edges this way.
    """
    source = None
    target = None
    relationship = None

    if isinstance(edge, (list, tuple)):
        if len(edge) >= 1:
            source = edge[0]

        if len(edge) >= 2:
            target = edge[1]

        if len(edge) >= 3:
            relationship = edge[2]

    return {
        "source": _safe_value(source),
        "target": _safe_value(target),
        "relationship": _safe_value(relationship),
    }


def _build_added_node_evidence(
    graph: Any,
    node_id: str,
) -> Dict[str, Any]:
    """
    Build evidence describing a newly added node.
    """
    return {
        "change_type": "ADDED_NODE",
        "node_id": node_id,
        "entity_type": _get_node_type(graph, node_id),
        "current_properties": _get_node_properties(graph, node_id),
    }


def _build_removed_node_evidence(
    graph: Any,
    node_id: str,
) -> Dict[str, Any]:
    """
    Build evidence describing a removed node.
    """
    return {
        "change_type": "REMOVED_NODE",
        "node_id": node_id,
        "entity_type": _get_node_type(graph, node_id),
        "baseline_properties": _get_node_properties(graph, node_id),
    }


def _build_changed_node_evidence(
    baseline_graph: Any,
    current_graph: Any,
    node_id: str,
    changed_properties: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Build evidence describing a node whose properties changed.

    The comparison result is treated as the authoritative source
    for which properties changed.
    """
    normalized_changes: Dict[str, Dict[str, Any]] = {}

    for property_name, values in changed_properties.items():
        if not isinstance(values, dict):
            normalized_changes[str(property_name)] = {
                "baseline": None,
                "current": _safe_value(values),
            }
            continue

        normalized_changes[str(property_name)] = {
            "baseline": _safe_value(values.get("baseline")),
            "current": _safe_value(values.get("current")),
        }

    return {
        "change_type": "CHANGED_NODE",
        "node_id": node_id,
        "entity_type": (
            _get_node_type(current_graph, node_id)
            or _get_node_type(baseline_graph, node_id)
        ),
        "changed_properties": normalized_changes,
    }


def analyze_identity_changes(
    comparison_result: Dict[str, Any],
    baseline_graph: Any = None,
    current_graph: Any = None,
) -> Dict[str, Any]:
    """
    Analyze structural identity changes reported by graph_comparator.

    Parameters
    ----------
    comparison_result:
        Result returned by compare_graphs().

    baseline_graph:
        Trusted/baseline System Identity Graph.

    current_graph:
        Current System Identity Graph.

    Returns
    -------
    dict
        Structured Identity Context evidence report.
    """

    if not isinstance(comparison_result, dict):
        raise TypeError("comparison_result must be a dictionary.")

    added_nodes = comparison_result.get("added_nodes", [])
    removed_nodes = comparison_result.get("removed_nodes", [])
    changed_nodes = comparison_result.get("changed_nodes", {})
    added_edges = comparison_result.get("added_edges", [])
    removed_edges = comparison_result.get("removed_edges", [])

    if added_nodes is None:
        added_nodes = []

    if removed_nodes is None:
        removed_nodes = []

    if changed_nodes is None:
        changed_nodes = {}

    if added_edges is None:
        added_edges = []

    if removed_edges is None:
        removed_edges = []

    added_node_evidence: List[Dict[str, Any]] = []

    for node_id in added_nodes:
        added_node_evidence.append(
            _build_added_node_evidence(
                current_graph,
                node_id,
            )
        )

    removed_node_evidence: List[Dict[str, Any]] = []

    for node_id in removed_nodes:
        removed_node_evidence.append(
            _build_removed_node_evidence(
                baseline_graph,
                node_id,
            )
        )

    changed_node_evidence: List[Dict[str, Any]] = []

    if isinstance(changed_nodes, dict):
        for node_id, changed_properties in changed_nodes.items():
            if not isinstance(changed_properties, dict):
                changed_properties = {}

            changed_node_evidence.append(
                _build_changed_node_evidence(
                    baseline_graph,
                    current_graph,
                    node_id,
                    changed_properties,
                )
            )

    added_edge_evidence = [
        {
            "change_type": "ADDED_EDGE",
            "edge": _edge_to_dict(edge),
        }
        for edge in added_edges
    ]

    removed_edge_evidence = [
        {
            "change_type": "REMOVED_EDGE",
            "edge": _edge_to_dict(edge),
        }
        for edge in removed_edges
    ]

    total_node_changes = (
        len(added_node_evidence)
        + len(removed_node_evidence)
        + len(changed_node_evidence)
    )

    total_edge_changes = (
        len(added_edge_evidence)
        + len(removed_edge_evidence)
    )

    total_changes = total_node_changes + total_edge_changes

    return {
        "identity_context": {
            "added_nodes": added_node_evidence,
            "removed_nodes": removed_node_evidence,
            "changed_nodes": changed_node_evidence,
            "added_edges": added_edge_evidence,
            "removed_edges": removed_edge_evidence,
        },
        "summary": {
            "added_nodes": len(added_node_evidence),
            "removed_nodes": len(removed_node_evidence),
            "changed_nodes": len(changed_node_evidence),
            "added_edges": len(added_edge_evidence),
            "removed_edges": len(removed_edge_evidence),
            "total_node_changes": total_node_changes,
            "total_edge_changes": total_edge_changes,
            "total_changes": total_changes,
        },
    }


def analyze_identity_change_for_node(
    comparison_result: Dict[str, Any],
    node_id: str,
    baseline_graph: Any = None,
    current_graph: Any = None,
) -> Optional[Dict[str, Any]]:
    """
    Return Identity Context evidence for one specific node.

    This helper is useful later when other Context dimensions
    need to enrich the evidence for a particular changed element.
    """

    if not isinstance(comparison_result, dict):
        raise TypeError("comparison_result must be a dictionary.")

    added_nodes = comparison_result.get("added_nodes", []) or []
    removed_nodes = comparison_result.get("removed_nodes", []) or []
    changed_nodes = comparison_result.get("changed_nodes", {}) or {}

    if node_id in added_nodes:
        return _build_added_node_evidence(
            current_graph,
            node_id,
        )

    if node_id in removed_nodes:
        return _build_removed_node_evidence(
            baseline_graph,
            node_id,
        )

    if node_id in changed_nodes:
        changed_properties = changed_nodes[node_id]

        if not isinstance(changed_properties, dict):
            changed_properties = {}

        return _build_changed_node_evidence(
            baseline_graph,
            current_graph,
            node_id,
            changed_properties,
        )

    return None