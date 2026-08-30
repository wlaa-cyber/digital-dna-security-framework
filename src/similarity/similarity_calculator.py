"""
Similarity Calculation Engine
-----------------------------
Calculates structural similarity between a baseline System
Identity Graph and a current System Identity Graph.

The engine uses Jaccard Similarity to measure node and edge
similarity separately, then combines them using configurable
structural weights.

The resulting similarity report describes structural similarity
only. Security interpretation and anomaly decisions are deliberately
handled by the Context Analyzer in the next project stage.
"""


# Initial structural similarity weights.
#
# Edges receive a higher weight because the Digital DNA model
# represents system identity primarily through the structural
# relationships between system components. Nodes remain important
# because they represent the system's constituent entities.
#
# These weights are initial design parameters and will be
# empirically evaluated during the project evaluation phase.
DEFAULT_NODE_WEIGHT = 0.30
DEFAULT_EDGE_WEIGHT = 0.70


def calculate_jaccard_similarity(
    baseline_set,
    current_set,
):
    """
    Calculate Jaccard Similarity between two sets.

    Jaccard Similarity = |Intersection| / |Union|

    Returns a value between 0.0 and 1.0.
    """

    union = baseline_set | current_set

    # If both sets are empty, they are considered identical.
    if not union:
        return 1.0

    intersection = baseline_set & current_set

    return len(intersection) / len(union)


def get_node_set(graph):
    """
    Extract graph node identifiers as a comparable set.
    """

    return set(graph.nodes())


def get_edge_set(graph):
    """
    Extract graph edges as a comparable set containing the
    source node, target node, and relationship type.

    This representation preserves the semantic meaning of
    relationships during graph comparison.
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


def calculate_node_similarity(
    baseline_graph,
    current_graph,
):
    """
    Calculate Jaccard Similarity between graph nodes.
    """

    baseline_nodes = get_node_set(baseline_graph)
    current_nodes = get_node_set(current_graph)

    return calculate_jaccard_similarity(
        baseline_nodes,
        current_nodes,
    )


def calculate_edge_similarity(
    baseline_graph,
    current_graph,
):
    """
    Calculate Jaccard Similarity between graph edges.
    """

    baseline_edges = get_edge_set(baseline_graph)
    current_edges = get_edge_set(current_graph)

    return calculate_jaccard_similarity(
        baseline_edges,
        current_edges,
    )


def calculate_structural_similarity(
    baseline_graph,
    current_graph,
    node_weight=DEFAULT_NODE_WEIGHT,
    edge_weight=DEFAULT_EDGE_WEIGHT,
):
    """
    Calculate weighted structural similarity between two
    System Identity Graphs.

    Node similarity represents component continuity, while edge
    similarity receives greater emphasis because relationships
    represent the structural organization of the system.

    The result describes similarity only and does not make a
    security or anomaly decision.
    """

    if node_weight < 0 or edge_weight < 0:
        raise ValueError(
            "Similarity weights cannot be negative."
        )

    if abs(
        (node_weight + edge_weight) - 1.0
    ) > 1e-9:
        raise ValueError(
            "Node and edge weights must sum to 1.0."
        )

    node_similarity = calculate_node_similarity(
        baseline_graph,
        current_graph,
    )

    edge_similarity = calculate_edge_similarity(
        baseline_graph,
        current_graph,
    )

    structural_similarity = (
        node_weight * node_similarity
        + edge_weight * edge_similarity
    )

    return {
        "node_similarity": node_similarity,
        "edge_similarity": edge_similarity,
        "structural_similarity": structural_similarity,
        "weights": {
            "node_weight": node_weight,
            "edge_weight": edge_weight,
        },
    }


def calculate_similarity_report(
    baseline_graph,
    current_graph,
    node_weight=DEFAULT_NODE_WEIGHT,
    edge_weight=DEFAULT_EDGE_WEIGHT,
):
    """
    Calculate an interpretable structural similarity report.

    In addition to similarity scores, the report provides the
    intersection and union sizes used by Jaccard Similarity.
    These values support transparency and later contextual
    analysis without making a security decision.
    """

    baseline_nodes = get_node_set(baseline_graph)
    current_nodes = get_node_set(current_graph)

    baseline_edges = get_edge_set(baseline_graph)
    current_edges = get_edge_set(current_graph)

    node_intersection = (
        baseline_nodes & current_nodes
    )
    node_union = (
        baseline_nodes | current_nodes
    )

    edge_intersection = (
        baseline_edges & current_edges
    )
    edge_union = (
        baseline_edges | current_edges
    )

    similarity_result = calculate_structural_similarity(
        baseline_graph,
        current_graph,
        node_weight=node_weight,
        edge_weight=edge_weight,
    )

    return {
        "similarity": similarity_result,
        "nodes": {
            "baseline_count": len(baseline_nodes),
            "current_count": len(current_nodes),
            "intersection_count": len(node_intersection),
            "union_count": len(node_union),
        },
        "edges": {
            "baseline_count": len(baseline_edges),
            "current_count": len(current_edges),
            "intersection_count": len(edge_intersection),
            "union_count": len(edge_union),
        },
    }