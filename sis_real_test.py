import json
from pathlib import Path

from src.normalization.normalizer import normalize_snapshot
from src.graph.graph_builder import build_system_identity_graph
from src.comparison.graph_comparator import compare_graphs
from src.similarity.similarity_calculator import calculate_similarity_report
from src.context.context_engine import analyze_context
from src.sis.sis_calculator import (
    calculate_structural_consistency,
    calculate_sis,
)
from src.sis.context_consistency import (
    build_context_evidence,
    correlate_context_evidence,
    calculate_context_consistency,
)


baseline = json.loads(
    Path(
        "data/system_snapshot_20260820T205710Z.json"
    ).read_text(encoding="utf-8")
)

current = json.loads(
    Path(
        "data/system_snapshot_20260820T220640Z.json"
    ).read_text(encoding="utf-8")
)


baseline_graph = build_system_identity_graph(
    normalize_snapshot(baseline)
)

current_graph = build_system_identity_graph(
    normalize_snapshot(current)
)


comparison = compare_graphs(
    baseline_graph,
    current_graph,
)


similarity = calculate_similarity_report(
    baseline_graph,
    current_graph,
)


structural = calculate_structural_consistency(
    similarity
)


context = analyze_context(
    comparison,
    baseline_graph,
    current_graph,
)


evidence = build_context_evidence(
    context
)


correlated = correlate_context_evidence(
    evidence
)


context_consistency = calculate_context_consistency(
    correlated
)


sis = calculate_sis(
    structural,
    context_consistency
)


print("=== REAL SIS TEST ===")

print()
print("Structural Consistency:")
print(
    "  Node Similarity:",
    structural["node_similarity"],
)

print(
    "  Edge Similarity:",
    structural["edge_similarity"],
)

print(
    "  Structural Similarity:",
    structural["structural_similarity"],
)

print()
print("Context Consistency:")
print(
    "  Correlated Units:",
    context_consistency["correlated_unit_count"],
)

print(
    "  Evaluated Units:",
    context_consistency["evaluated_unit_count"],
)

print(
    "  Context Coverage:",
    context_consistency["context_coverage"],
)

print(
    "  Average Unit Context Score:",
    context_consistency["average_unit_context_score"],
)

print(
    "  Context Consistency:",
    context_consistency["context_consistency"],
)

print()
print("SIS:")
print("  SIS:", sis["sis"])
print(
    "  Structural Component:",
    sis["structural_component"],
)

print(
    "  Context Component:",
    sis["context_component"],
)

print(
    "  Structural Weight:",
    sis["weights"]["structural_weight"],
)

print(
    "  Context Weight:",
    sis["weights"]["context_weight"],
)
