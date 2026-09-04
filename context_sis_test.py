from src.sis.context_consistency import (
    calculate_context_consistency,
)


correlated = {
    "correlated_unit_count": 1,
    "units": [
        {
            "node_id": "process:TEST",
            "dimensions": {
                "trust": [
                    {
                        "state": "VALID",
                    }
                ],
                "location": [
                    {
                        "state": "SYSTEM32",
                    },
                    {
                        "state": "TEMP",
                    }
                ],
                "network": [
                    {
                        "state": "EXTERNAL",
                    }
                ],
            },
        }
    ],
}


result = calculate_context_consistency(correlated)

print("=== CONTEXT SIS INPUT TEST ===")
print("Context Consistency:", result["context_consistency"])
print("Evaluated Units:", result["evaluated_unit_count"])
print("Coverage:", result["context_coverage"])

for unit in result["unit_evaluations"]:
    print("Node:", unit["node_id"])
    print("Score:", unit["context_score"])
    print("Usable:", unit["usable_dimension_count"])
    print("Consistent:", unit["consistent_dimension_count"])