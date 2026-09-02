"""
Parent-Child Context Analyzer
=============================

Stage 6 context dimension for the DDS framework.

Purpose
-------
Analyze parent-child relationships between Windows processes as contextual
evidence for system changes.

This module does NOT:
- calculate Graph Edit Distance (GED)
- calculate Jaccard Similarity
- calculate SIS
- make a malware/legitimate verdict
- assign a final security risk score

It only describes and evaluates process parent-child relationship evidence
that already exists in the System Identity Graph and graph comparison result.
"""

from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RELATIONSHIP_PARENT_OF = "parent_of"

STATE_EXISTING = "EXISTING"
STATE_NEW = "NEW"
STATE_REMOVED = "REMOVED"
STATE_CHANGED = "CHANGED"
STATE_UNAVAILABLE = "UNAVAILABLE"

EVIDENCE_STRONG = "Strong"
EVIDENCE_MODERATE = "Moderate"
EVIDENCE_INFORMATIONAL = "Informational"
EVIDENCE_NONE = None


# ---------------------------------------------------------------------------
# Safe helpers
# ---------------------------------------------------------------------------

def _safe_value(value: Any) -> Any:
    """
    Return a normalized value suitable for evidence output.
    """
    if value is None:
        return None

    if isinstance(value, str):
        value = value.strip()

        if not value:
            return None

        if value.lower() in {
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

        return value

    return value


def _get_node_type(graph: Any, node_id: Any) -> str | None:
    """
    Return the node entity type from the graph.
    """
    if graph is None or node_id is None:
        return None

    try:
        if node_id not in graph:
            return None

        node_data = graph.nodes[node_id]
        return _safe_value(node_data.get("entity_type"))

    except (AttributeError, KeyError, TypeError):
        return None


def _get_node_properties(graph: Any, node_id: Any) -> dict[str, Any]:
    """
    Return a safe copy of node properties.
    """
    if graph is None or node_id is None:
        return {}

    try:
        if node_id not in graph:
            return {}

        return dict(graph.nodes[node_id])

    except (AttributeError, KeyError, TypeError, ValueError):
        return {}


def _is_process_node(graph: Any, node_id: Any) -> bool:
    """
    Determine whether a node represents a process.
    """
    return _get_node_type(graph, node_id) == "process"


def _get_process_name(graph: Any, node_id: Any) -> str | None:
    """
    Return process name.
    """
    properties = _get_node_properties(graph, node_id)

    return _safe_value(
        properties.get("name")
    )


def _get_process_path(graph: Any, node_id: Any) -> str | None:
    """
    Return process executable path.
    """
    properties = _get_node_properties(graph, node_id)

    return _safe_value(
        properties.get("path")
    )


def _get_process_pid(graph: Any, node_id: Any) -> Any:
    """
    Return process PID.
    """
    properties = _get_node_properties(graph, node_id)

    return _safe_value(
        properties.get("pid")
    )


def _get_parent_pid(graph: Any, node_id: Any) -> Any:
    """
    Return the parent_pid property stored on a process node.
    """
    properties = _get_node_properties(graph, node_id)

    return _safe_value(
        properties.get("parent_pid")
    )


# ---------------------------------------------------------------------------
# Parent-child relationship helpers
# ---------------------------------------------------------------------------

def _get_parent_children_edges(
    graph: Any,
) -> set[tuple[Any, Any]]:
    """
    Extract parent-child process relationships from a graph.

    Returns:
        Set of tuples:
            (parent_node_id, child_node_id)
    """
    relationships: set[tuple[Any, Any]] = set()

    if graph is None:
        return relationships

    try:
        for source, target, data in graph.edges(data=True):
            if data.get("relationship") != RELATIONSHIP_PARENT_OF:
                continue

            if not _is_process_node(graph, source):
                continue

            if not _is_process_node(graph, target):
                continue

            relationships.add((source, target))

    except (AttributeError, TypeError):
        return relationships

    return relationships


def _find_parent_for_child(
    graph: Any,
    child_node_id: Any,
) -> Any | None:
    """
    Find the parent process node for a child process.

    The graph's explicit parent_of relationship is preferred.
    """
    if graph is None or child_node_id is None:
        return None

    try:
        if child_node_id not in graph:
            return None

        for source, target, data in graph.in_edges(
            child_node_id,
            data=True,
        ):
            if data.get("relationship") != RELATIONSHIP_PARENT_OF:
                continue

            if _is_process_node(graph, source):
                return source

    except (AttributeError, KeyError, TypeError):
        return None

    return None


def _find_child_for_parent_pid(
    graph: Any,
    parent_pid: Any,
) -> Any | None:
    """
    Find a process node by PID.

    This is used as a fallback when parent_pid exists but the graph
    relationship cannot be resolved.
    """
    parent_pid = _safe_value(parent_pid)

    if graph is None or parent_pid is None:
        return None

    try:
        for node_id, properties in graph.nodes(data=True):
            if properties.get("entity_type") != "process":
                continue

            if properties.get("pid") == parent_pid:
                return node_id

    except (AttributeError, TypeError):
        return None

    return None


def _relationship_exists(
    graph: Any,
    parent_node_id: Any,
    child_node_id: Any,
) -> bool:
    """
    Determine whether a parent_of relationship exists.
    """
    if graph is None:
        return False

    try:
        if parent_node_id not in graph or child_node_id not in graph:
            return False

        edge_data = graph.get_edge_data(
            parent_node_id,
            child_node_id,
        )

        if not edge_data:
            return False

        if isinstance(edge_data, dict):
            for data in edge_data.values():
                if isinstance(data, dict):
                    if data.get("relationship") == RELATIONSHIP_PARENT_OF:
                        return True

            if edge_data.get("relationship") == RELATIONSHIP_PARENT_OF:
                return True

    except (AttributeError, KeyError, TypeError):
        return False

    return False


def _find_parent_from_relationship(
    graph: Any,
    child_node_id: Any,
) -> Any | None:
    """
    Resolve the parent node from an explicit parent_of graph edge.
    """
    return _find_parent_for_child(
        graph,
        child_node_id,
    )


# ---------------------------------------------------------------------------
# Evidence strength
# ---------------------------------------------------------------------------

def _determine_existing_relationship_strength() -> str:
    """
    Existing parent-child relationships are mainly historical/contextual
    evidence. Their presence alone is not suspicious.
    """
    return EVIDENCE_INFORMATIONAL


def _determine_new_relationship_strength(
    parent_known: bool,
    child_known: bool,
    parent_was_existing: bool,
) -> str:
    """
    Determine contextual evidence strength for a newly observed relationship.

    Important:
        This is evidence strength, NOT a maliciousness score.

    A new relationship involving an already known parent and a new child
    provides contextual evidence.

    A completely new parent-child chain provides stronger contextual evidence
    because both sides of the relationship are newly observed.
    """
    if not parent_known or not child_known:
        return EVIDENCE_INFORMATIONAL

    if not parent_was_existing:
        return EVIDENCE_STRONG

    return EVIDENCE_MODERATE


# ---------------------------------------------------------------------------
# Context assessment
# ---------------------------------------------------------------------------

def _build_context_assessment(
    relationship_state: str,
    parent_known: bool,
    child_known: bool,
) -> str:
    """
    Generate a neutral contextual interpretation.

    No malicious/benign verdict is made here.
    """
    if relationship_state == STATE_EXISTING:
        return (
            "The parent-child relationship is already present in the "
            "observed graph and provides historical contextual evidence."
        )

    if relationship_state == STATE_NEW:
        if parent_known and child_known:
            return (
                "A new parent-child process relationship was observed. "
                "The relationship should be correlated with other context "
                "dimensions before making a security decision."
            )

        return (
            "A parent-child relationship change was observed, but one or "
            "more process references could not be fully resolved."
        )

    if relationship_state == STATE_REMOVED:
        return (
            "A previously observed parent-child relationship is no longer "
            "present in the current graph."
        )

    if relationship_state == STATE_CHANGED:
        return (
            "The process parent relationship changed between observations "
            "and should be correlated with other contextual evidence."
        )

    return (
        "Parent-child relationship information is insufficient for a "
        "complete contextual assessment."
    )


# ---------------------------------------------------------------------------
# Relationship evidence builders
# ---------------------------------------------------------------------------

def _build_process_reference(
    graph: Any,
    node_id: Any,
) -> dict[str, Any]:
    """
    Build a compact process reference for evidence output.
    """
    if node_id is None:
        return {
            "node_id": None,
            "entity_type": None,
            "pid": None,
            "name": None,
            "path": None,
            "known": False,
        }

    properties = _get_node_properties(graph, node_id)

    return {
        "node_id": node_id,
        "entity_type": properties.get("entity_type"),
        "pid": _safe_value(properties.get("pid")),
        "name": _safe_value(properties.get("name")),
        "path": _safe_value(properties.get("path")),
        "known": bool(properties),
    }


def _build_relationship_evidence(
    graph: Any,
    parent_node_id: Any,
    child_node_id: Any,
    relationship_state: str,
    parent_known: bool,
    child_known: bool,
    parent_was_existing: bool = True,
) -> dict[str, Any]:
    """
    Build the standardized parent-child evidence record.
    """
    parent = _build_process_reference(
        graph,
        parent_node_id,
    )

    child = _build_process_reference(
        graph,
        child_node_id,
    )

    if relationship_state == STATE_EXISTING:
        evidence_strength = _determine_existing_relationship_strength()

    elif relationship_state == STATE_NEW:
        evidence_strength = _determine_new_relationship_strength(
            parent_known=parent_known,
            child_known=child_known,
            parent_was_existing=parent_was_existing,
        )

    elif relationship_state == STATE_REMOVED:
        evidence_strength = EVIDENCE_INFORMATIONAL

    elif relationship_state == STATE_CHANGED:
        evidence_strength = EVIDENCE_MODERATE

    else:
        evidence_strength = EVIDENCE_NONE

    return {
        "relationship": RELATIONSHIP_PARENT_OF,
        "relationship_state": relationship_state,
        "parent": parent,
        "child": child,
        "parent_known": parent_known,
        "child_known": child_known,
        "evidence_strength": evidence_strength,
        "context_assessment": _build_context_assessment(
            relationship_state=relationship_state,
            parent_known=parent_known,
            child_known=child_known,
        ),
    }


# ---------------------------------------------------------------------------
# Single relationship analysis
# ---------------------------------------------------------------------------

def analyze_parent_child_relationship(
    graph: Any,
    parent_node_id: Any,
    child_node_id: Any,
    relationship_state: str = STATE_EXISTING,
    parent_was_existing: bool = True,
) -> dict[str, Any]:
    """
    Analyze one parent-child relationship.

    This function does not make a security verdict.
    """
    parent_known = (
        parent_node_id is not None
        and parent_node_id in graph
        if graph is not None
        else False
    )

    child_known = (
        child_node_id is not None
        and child_node_id in graph
        if graph is not None
        else False
    )

    if not parent_known or not child_known:
        if relationship_state != STATE_REMOVED:
            relationship_state = STATE_UNAVAILABLE

    evidence = _build_relationship_evidence(
        graph=graph,
        parent_node_id=parent_node_id,
        child_node_id=child_node_id,
        relationship_state=relationship_state,
        parent_known=parent_known,
        child_known=child_known,
        parent_was_existing=parent_was_existing,
    )

    return evidence


# ---------------------------------------------------------------------------
# Process-level analysis
# ---------------------------------------------------------------------------

def analyze_process_parent_context(
    graph: Any,
    process_node_id: Any,
) -> dict[str, Any]:
    """
    Analyze the parent context of one process node.
    """
    process = _build_process_reference(
        graph,
        process_node_id,
    )

    if not process["known"]:
        return {
            "process": process,
            "parent": _build_process_reference(graph, None),
            "relationship": RELATIONSHIP_PARENT_OF,
            "relationship_state": STATE_UNAVAILABLE,
            "parent_known": False,
            "child_known": False,
            "evidence_strength": EVIDENCE_NONE,
            "context_assessment": (
                "The process node could not be resolved."
            ),
        }

    parent_node_id = _find_parent_from_relationship(
        graph,
        process_node_id,
    )

    if parent_node_id is None:
        parent_pid = _get_parent_pid(
            graph,
            process_node_id,
        )

        parent_node_id = _find_child_for_parent_pid(
            graph,
            parent_pid,
        )

    if parent_node_id is None:
        return {
            "process": process,
            "parent": _build_process_reference(graph, None),
            "relationship": RELATIONSHIP_PARENT_OF,
            "relationship_state": STATE_UNAVAILABLE,
            "parent_known": False,
            "child_known": True,
            "evidence_strength": EVIDENCE_NONE,
            "context_assessment": (
                "The child process is known, but its parent process could "
                "not be resolved from the available graph information."
            ),
        }

    return {
        "process": process,
        "parent": _build_process_reference(
            graph,
            parent_node_id,
        ),
        "relationship": RELATIONSHIP_PARENT_OF,
        "relationship_state": STATE_EXISTING,
        "parent_known": True,
        "child_known": True,
        "evidence_strength": EVIDENCE_INFORMATIONAL,
        "context_assessment": _build_context_assessment(
            relationship_state=STATE_EXISTING,
            parent_known=True,
            child_known=True,
        ),
    }


# ---------------------------------------------------------------------------
# Graph-level relationship extraction
# ---------------------------------------------------------------------------

def analyze_all_parent_child_relationships(
    graph: Any,
) -> dict[str, Any]:
    """
    Analyze all parent-child relationships in a graph.
    """
    relationships = _get_parent_children_edges(graph)

    evidence = []

    for parent_node_id, child_node_id in sorted(
        relationships,
        key=lambda item: (
            str(item[0]),
            str(item[1]),
        ),
    ):
        evidence.append(
            analyze_parent_child_relationship(
                graph=graph,
                parent_node_id=parent_node_id,
                child_node_id=child_node_id,
                relationship_state=STATE_EXISTING,
            )
        )

    return {
        "relationship_count": len(evidence),
        "relationships": evidence,
    }


# ---------------------------------------------------------------------------
# Comparison helpers
# ---------------------------------------------------------------------------

def _get_comparison_set(
    comparison_result: dict[str, Any] | None,
    key: str,
) -> set[Any]:
    """
    Safely extract a comparison set.
    """
    if not comparison_result:
        return set()

    value = comparison_result.get(key, set())

    if value is None:
        return set()

    try:
        return set(value)
    except TypeError:
        return set()


def _get_changed_node_ids(
    comparison_result: dict[str, Any] | None,
) -> set[Any]:
    """
    Extract changed node IDs from the comparator result.

    The comparator stores changed_nodes as a dictionary in the current DDS
    implementation.
    """
    if not comparison_result:
        return set()

    changed_nodes = comparison_result.get(
        "changed_nodes",
        {},
    )

    if isinstance(changed_nodes, dict):
        return set(changed_nodes.keys())

    try:
        return set(changed_nodes)
    except TypeError:
        return set()


def _build_relationship_set_difference(
    baseline_graph: Any,
    current_graph: Any,
) -> dict[str, set[tuple[Any, Any]]]:
    """
    Calculate parent-child relationship differences.

    This is only used for contextual interpretation. The authoritative
    graph comparison remains Stage 4's responsibility.
    """
    baseline_relationships = _get_parent_children_edges(
        baseline_graph
    )

    current_relationships = _get_parent_children_edges(
        current_graph
    )

    return {
        "added": current_relationships - baseline_relationships,
        "removed": baseline_relationships - current_relationships,
        "existing": current_relationships & baseline_relationships,
    }


# ---------------------------------------------------------------------------
# Changed parent analysis
# ---------------------------------------------------------------------------

def _detect_parent_change(
    baseline_graph: Any,
    current_graph: Any,
    process_node_id: Any,
) -> dict[str, Any] | None:
    """
    Detect whether the parent of a process changed.
    """
    baseline_parent = _find_parent_from_relationship(
        baseline_graph,
        process_node_id,
    )

    current_parent = _find_parent_from_relationship(
        current_graph,
        process_node_id,
    )

    if baseline_parent == current_parent:
        return None

    if baseline_parent is None and current_parent is None:
        return None

    return {
        "process_node_id": process_node_id,
        "baseline_parent_node_id": baseline_parent,
        "current_parent_node_id": current_parent,
    }


def _build_changed_parent_evidence(
    baseline_graph: Any,
    current_graph: Any,
    process_node_id: Any,
) -> dict[str, Any]:
    """
    Build evidence for a process whose parent changed.
    """
    process = _build_process_reference(
        current_graph,
        process_node_id,
    )

    baseline_parent_node_id = _find_parent_from_relationship(
        baseline_graph,
        process_node_id,
    )

    current_parent_node_id = _find_parent_from_relationship(
        current_graph,
        process_node_id,
    )

    baseline_parent = _build_process_reference(
        baseline_graph,
        baseline_parent_node_id,
    )

    current_parent = _build_process_reference(
        current_graph,
        current_parent_node_id,
    )

    return {
        "relationship": RELATIONSHIP_PARENT_OF,
        "relationship_state": STATE_CHANGED,
        "process": process,
        "baseline_parent": baseline_parent,
        "current_parent": current_parent,
        "parent_changed": True,
        "parent_was_known": baseline_parent["known"],
        "current_parent_known": current_parent["known"],
        "evidence_strength": EVIDENCE_MODERATE,
        "context_assessment": _build_context_assessment(
            relationship_state=STATE_CHANGED,
            parent_known=current_parent["known"],
            child_known=process["known"],
        ),
    }


# ---------------------------------------------------------------------------
# Comparison-level analysis
# ---------------------------------------------------------------------------

def analyze_parent_child_changes(
    comparison_result: dict[str, Any],
    baseline_graph: Any,
    current_graph: Any,
) -> dict[str, Any]:
    """
    Analyze parent-child relationship changes between baseline and current
    graphs.

    The function consumes the Stage 4 comparison result but independently
    reads parent_of edges from the two graphs to describe the contextual
    relationship changes.
    """
    relationship_differences = _build_relationship_set_difference(
        baseline_graph,
        current_graph,
    )

    added_relationships = relationship_differences["added"]
    removed_relationships = relationship_differences["removed"]
    existing_relationships = relationship_differences["existing"]

    added_evidence = []
    removed_evidence = []
    existing_evidence = []
    changed_parent_evidence = []

    # ---------------------------------------------------------------
    # Added relationships
    # ---------------------------------------------------------------

    baseline_process_nodes = {
        node_id
        for node_id in (
            baseline_graph.nodes
            if baseline_graph is not None
            else []
        )
        if _is_process_node(
            baseline_graph,
            node_id,
        )
    }

    for parent_node_id, child_node_id in sorted(
        added_relationships,
        key=lambda item: (
            str(item[0]),
            str(item[1]),
        ),
    ):
        parent_was_existing = (
            parent_node_id in baseline_process_nodes
        )

        parent_known = (
            parent_node_id in current_graph
            if current_graph is not None
            else False
        )

        child_known = (
            child_node_id in current_graph
            if current_graph is not None
            else False
        )

        added_evidence.append(
            _build_relationship_evidence(
                graph=current_graph,
                parent_node_id=parent_node_id,
                child_node_id=child_node_id,
                relationship_state=STATE_NEW,
                parent_known=parent_known,
                child_known=child_known,
                parent_was_existing=parent_was_existing,
            )
        )

    # ---------------------------------------------------------------
    # Removed relationships
    # ---------------------------------------------------------------

    for parent_node_id, child_node_id in sorted(
        removed_relationships,
        key=lambda item: (
            str(item[0]),
            str(item[1]),
        ),
    ):
        removed_evidence.append(
            _build_relationship_evidence(
                graph=baseline_graph,
                parent_node_id=parent_node_id,
                child_node_id=child_node_id,
                relationship_state=STATE_REMOVED,
                parent_known=True,
                child_known=True,
                parent_was_existing=True,
            )
        )

    # ---------------------------------------------------------------
    # Existing relationships
    # ---------------------------------------------------------------

    for parent_node_id, child_node_id in sorted(
        existing_relationships,
        key=lambda item: (
            str(item[0]),
            str(item[1]),
        ),
    ):
        existing_evidence.append(
            _build_relationship_evidence(
                graph=current_graph,
                parent_node_id=parent_node_id,
                child_node_id=child_node_id,
                relationship_state=STATE_EXISTING,
                parent_known=True,
                child_known=True,
                parent_was_existing=True,
            )
        )

    # ---------------------------------------------------------------
    # Parent changes for changed processes
    # ---------------------------------------------------------------

    changed_processes = {
        node_id
        for node_id in _get_changed_node_ids(
            comparison_result
        )
        if _is_process_node(
            current_graph,
            node_id,
        )
    }

    for process_node_id in sorted(
        changed_processes,
        key=str,
    ):
        change = _detect_parent_change(
            baseline_graph,
            current_graph,
            process_node_id,
        )

        if change is not None:
            changed_parent_evidence.append(
                _build_changed_parent_evidence(
                    baseline_graph,
                    current_graph,
                    process_node_id,
                )
            )

    # ---------------------------------------------------------------
    # Summary
    # ---------------------------------------------------------------

    total_changes = (
        len(added_evidence)
        + len(removed_evidence)
        + len(changed_parent_evidence)
    )

    return {
        "summary": {
            "added_relationships": len(added_evidence),
            "removed_relationships": len(removed_evidence),
            "existing_relationships": len(existing_evidence),
            "changed_parents": len(changed_parent_evidence),
            "total_relationship_changes": total_changes,
        },
        "added_relationships": added_evidence,
        "removed_relationships": removed_evidence,
        "existing_relationships": existing_evidence,
        "changed_parents": changed_parent_evidence,
    }


# ---------------------------------------------------------------------------
# Convenience function for one changed process
# ---------------------------------------------------------------------------

def analyze_parent_child_change_for_process(
    comparison_result: dict[str, Any],
    baseline_graph: Any,
    current_graph: Any,
    process_node_id: Any,
) -> dict[str, Any]:
    """
    Analyze parent-child context specifically for one process.

    This is useful when another stage wants contextual evidence for a
    particular changed process rather than the entire graph.
    """
    changed_processes = _get_changed_node_ids(
        comparison_result
    )

    process_is_added = process_node_id in _get_comparison_set(
        comparison_result,
        "added_nodes",
    )

    process_is_removed = process_node_id in _get_comparison_set(
        comparison_result,
        "removed_nodes",
    )

    process_is_changed = process_node_id in changed_processes

    if process_is_removed:
        parent_node_id = _find_parent_from_relationship(
            baseline_graph,
            process_node_id,
        )

        return {
            "process": _build_process_reference(
                baseline_graph,
                process_node_id,
            ),
            "relationship_state": STATE_REMOVED,
            "parent": _build_process_reference(
                baseline_graph,
                parent_node_id,
            ),
            "evidence_strength": EVIDENCE_INFORMATIONAL,
            "context_assessment": (
                "The process was removed from the current graph together "
                "with its observed parent-child context."
            ),
        }

    if process_is_added:
        parent_node_id = _find_parent_from_relationship(
            current_graph,
            process_node_id,
        )

        if parent_node_id is None:
            parent_pid = _get_parent_pid(
                current_graph,
                process_node_id,
            )

            parent_node_id = _find_child_for_parent_pid(
                current_graph,
                parent_pid,
            )

        return analyze_parent_child_relationship(
            graph=current_graph,
            parent_node_id=parent_node_id,
            child_node_id=process_node_id,
            relationship_state=STATE_NEW,
            parent_was_existing=(
                parent_node_id is not None
                and parent_node_id in (
                    baseline_graph
                    if baseline_graph is not None
                    else {}
                )
            ),
        )

    if process_is_changed:
        parent_change = _detect_parent_change(
            baseline_graph,
            current_graph,
            process_node_id,
        )

        if parent_change is not None:
            return _build_changed_parent_evidence(
                baseline_graph,
                current_graph,
                process_node_id,
            )

        return analyze_process_parent_context(
            current_graph,
            process_node_id,
        )

    return {
        "process": _build_process_reference(
            current_graph,
            process_node_id,
        ),
        "relationship_state": STATE_EXISTING,
        "parent": _build_process_reference(
            current_graph,
            _find_parent_from_relationship(
                current_graph,
                process_node_id,
            ),
        ),
        "evidence_strength": EVIDENCE_INFORMATIONAL,
        "context_assessment": (
            "No parent-child change was reported for this process."
        ),
    }


__all__ = [
    "RELATIONSHIP_PARENT_OF",
    "STATE_EXISTING",
    "STATE_NEW",
    "STATE_REMOVED",
    "STATE_CHANGED",
    "STATE_UNAVAILABLE",
    "EVIDENCE_STRONG",
    "EVIDENCE_MODERATE",
    "EVIDENCE_INFORMATIONAL",
    "EVIDENCE_NONE",
    "analyze_parent_child_relationship",
    "analyze_process_parent_context",
    "analyze_all_parent_child_relationships",
    "analyze_parent_child_changes",
    "analyze_parent_child_change_for_process",
]