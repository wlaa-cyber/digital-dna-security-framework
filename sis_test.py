from src.sis.sis_calculator import calculate_sis

structural = {
    "node_similarity": 0.8478561549100968,
    "edge_similarity": 0.7309417040358744,
    "structural_similarity": 0.7660160392981411,
    "weights": {
        "node_weight": 0.3,
        "edge_weight": 0.7,
    },
}

context = {
    "context_consistency": 0.6666666666666666,
    "correlated_unit_count": 1,
    "evaluated_unit_count": 1,
    "context_coverage": 1.0,
    "average_unit_context_score": 0.6666666666666666,
}

result = calculate_sis(
    structural,
    context,
)

print("=== SIS TEST ===")
print(result)