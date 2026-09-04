"""
Unified Context Engine.

This module orchestrates the existing context-analysis modules and combines
their evidence into one unified context result.

Important:
- This module does not calculate SIS.
- This module does not classify malware.
- This module does not make security decisions.
- This module does not modify the trusted baseline.
"""

from .identity_context import analyze_identity_changes
from .trust_context import analyze_trust_changes
from .context_analyzer import analyze_location_changes
from .network_context import analyze_network_changes
from .parent_child_context import analyze_parent_child_changes
from .temporal_context import analyze_temporal_changes


def analyze_context(
    comparison_result,
    baseline_graph,
    current_graph,
    reference_time=None,
):
    """
    Run all existing context-analysis modules and return unified evidence.

    Parameters
    ----------
    comparison_result : dict
        Result produced by compare_graphs().

    baseline_graph : networkx graph
        Trusted/baseline system identity graph.

    current_graph : networkx graph
        Current system identity graph.

    reference_time : optional
        Reference time passed to the temporal context analyzer.

    Returns
    -------
    dict
        Unified context evidence from all context modules.
    """

    identity_result = analyze_identity_changes(
        comparison_result,
        baseline_graph=baseline_graph,
        current_graph=current_graph,
    )

    trust_result = analyze_trust_changes(
        comparison_result,
        baseline_graph=baseline_graph,
        current_graph=current_graph,
    )

    location_result = analyze_location_changes(
        comparison_result,
        baseline_graph=baseline_graph,
        current_graph=current_graph,
    )

    network_result = analyze_network_changes(
        comparison_result,
        baseline_graph=baseline_graph,
        current_graph=current_graph,
    )

    parent_child_result = analyze_parent_child_changes(
        comparison_result,
        baseline_graph=baseline_graph,
        current_graph=current_graph,
    )

    temporal_result = analyze_temporal_changes(
        comparison_result,
        baseline_graph=baseline_graph,
        current_graph=current_graph,
        reference_time=reference_time,
    )

    return {
        "context_engine": {
            "version": "1.0",
            "modules": [
                "identity",
                "trust",
                "location",
                "network",
                "parent_child",
                "temporal",
            ],
        },
        "identity": identity_result,
        "trust": trust_result,
        "location": location_result,
        "network": network_result,
        "parent_child": parent_child_result,
        "temporal": temporal_result,
    }