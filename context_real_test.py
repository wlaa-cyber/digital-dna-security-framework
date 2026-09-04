import json
from pathlib import Path

from src.normalization.normalizer import normalize_snapshot
from src.graph.graph_builder import build_system_identity_graph
from src.comparison.graph_comparator import compare_graphs
from src.context.context_engine import analyze_context
from src.sis.context_consistency import (
    build_context_evidence,
    correlate_context_evidence,
    calculate_context_consistency,
)

BASELINE = Path(
    "data/system_snapshot_20260820T205710Z.json"
)

CURRENT = Path(
    "data/system_snapshot_20260820T220640Z.json"
)

baseline_data = json.loads(
    BASELINE.read_text(encoding="utf-8")
)

current_data = json.loads(
    CURRENT.read_text(encoding="utf-8")
)

baseline_graph = build_system_identity_graph(
    normalize_snapshot(baseline_data)
)

current_graph = build_system_identity_graph(
    normalize_snapshot(current_data)
)

comparison = compare_graphs(
    baseline_graph,
    current_graph,
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

result = calculate_context_consistency(
    correlated
)

print("=== REAL CONTEXT TEST ===")
print(
    "Correlated units:",
    result["correlated_unit_count"]
)
print(
    "Evaluated units:",
    result["evaluated_unit_count"]
)
print(
    "Context coverage:",
    result["context_coverage"]
)
print(
    "Average score:",
    result["average_unit_context_score"]
)
print(
    "Context consistency:",
    result["context_consistency"]
)