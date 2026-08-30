import networkx as nx


# Dynamic properties that may change during normal system operation
# and should not independently affect Digital DNA comparison.
DYNAMIC_PROPERTIES = {
    "status",
    "pid",
    "next_run_time",
    "last_run_time",
    "last_result",
}


def compare_properties(baseline_properties, current_properties):
    """
    Compare stable identity properties and return only
    meaningful differences.
    """

    changed_properties = {}

    all_keys = set(baseline_properties) | set(current_properties)

    for key in all_keys:
        # Ignore dynamic properties during Digital DNA comparison
        if key in DYNAMIC_PROPERTIES:
            continue

        baseline_value = baseline_properties.get(key)
        current_value = current_properties.get(key)

        if baseline_value != current_value:
            changed_properties[key] = {
                "baseline": baseline_value,
                "current": current_value,
            }

    return changed_properties


def get_edge_set(graph):
    """
    Convert graph edges into a comparable set containing
    source node, target node, and relationship type.
    """

    return {
        (
            source,
            target,
            data.get("relationship"),
        )
        for source, target, key, data in graph.edges(
            keys=True,
            data=True,
        )
    }


def compare_graphs(baseline_graph, current_graph):
    """
    Compare a baseline System Identity Graph with a current
    System Identity Graph and identify structural and
    meaningful property changes.
    """

    baseline_nodes = set(baseline_graph.nodes())
    current_nodes = set(current_graph.nodes())

    added_nodes = sorted(current_nodes - baseline_nodes)
    removed_nodes = sorted(baseline_nodes - current_nodes)
    common_nodes = baseline_nodes & current_nodes

    # Compare properties only for nodes that exist in both graphs
    changed_nodes = {}

    for node_id in common_nodes:
        baseline_properties = dict(baseline_graph.nodes[node_id])
        current_properties = dict(current_graph.nodes[node_id])

        changes = compare_properties(
            baseline_properties,
            current_properties,
        )

        if changes:
            changed_nodes[node_id] = changes

    # Compare graph relationships
    baseline_edges = get_edge_set(baseline_graph)
    current_edges = get_edge_set(current_graph)

    added_edges = sorted(current_edges - baseline_edges)
    removed_edges = sorted(baseline_edges - current_edges)
    common_edges = baseline_edges & current_edges

    return {
        "baseline_nodes": len(baseline_nodes),
        "current_nodes": len(current_nodes),
        "baseline_edges": len(baseline_edges),
        "current_edges": len(current_edges),
        "added_nodes": added_nodes,
        "removed_nodes": removed_nodes,
        "common_nodes": len(common_nodes),
        "changed_nodes": changed_nodes,
        "added_edges": added_edges,
        "removed_edges": removed_edges,
        "common_edges": len(common_edges),
    }


def calculate_change_metrics(comparison_result):
    """
    Calculate graph change metrics based on detected
    graph edit operations.

    In this implementation, the Graph Edit Distance represents
    the total number of detected node and edge edit operations
    between the baseline and current System Identity Graphs.
    """

    added_nodes = len(comparison_result["added_nodes"])
    removed_nodes = len(comparison_result["removed_nodes"])
    changed_nodes = len(comparison_result["changed_nodes"])

    added_edges = len(comparison_result["added_edges"])
    removed_edges = len(comparison_result["removed_edges"])

    graph_edit_distance = (
        added_nodes
        + removed_nodes
        + changed_nodes
        + added_edges
        + removed_edges
    )

    return {
        "added_nodes": added_nodes,
        "removed_nodes": removed_nodes,
        "changed_nodes": changed_nodes,
        "added_edges": added_edges,
        "removed_edges": removed_edges,
        "graph_edit_distance": graph_edit_distance,
        "total_changes": graph_edit_distance,
    }