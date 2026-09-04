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


context_consistent = {
    "context_consistency": 1.0,
    "correlated_unit_count": 1,
    "evaluated_unit_count": 1,
    "context_coverage": 1.0,
    "average_unit_context_score": 1.0,
}


context_inconsistent = {
    "context_consistency": 0.6666666666666666,
    "correlated_unit_count": 1,
    "evaluated_unit_count": 1,
    "context_coverage": 1.0,
    "average_unit_context_score": 0.6666666666666666,
}


sis_consistent = calculate_sis(
    structural,
    context_consistent,
)

sis_inconsistent = calculate_sis(
    structural,
    context_inconsistent,
)


print("=== SIS CONTEXT SENSITIVITY TEST ===")

print("With consistent context:")
print(sis_consistent)

print()

print("With inconsistent context:")
print(sis_inconsistent)

print()

print("SIS difference:")
print(
    sis_consistent["sis"]
    - sis_inconsistent["sis"]
)