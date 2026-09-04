from src.sis.context_consistency import evaluate_context_unit


unit = {
    "node_id": "process:TEST",
    "dimensions": {
        "trust": [
            {
                "state": "VALID"
            }
        ],
        "location": [
            {
                "state": "SYSTEM32"
            },
            {
                "state": "TEMP"
            }
        ],
        "network": [
            {
                "state": "EXTERNAL"
            }
        ],
    },
}


result = evaluate_context_unit(unit)


print("=== CONTEXT UNIT TEST ===")
print("Context score:", result["context_score"])
print("Dimensions:", result["dimensions"])
print("Usable:", result["usable_dimension_count"])
print("Unknown:", result["unknown_dimension_count"])
print("Consistent:", result["consistent_dimension_count"])