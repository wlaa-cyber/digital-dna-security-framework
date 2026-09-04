import json
from pathlib import Path

from src.normalization.normalizer import normalize_snapshot
from src.graph.graph_builder import build_system_identity_graph
from src.comparison.graph_comparator import compare_graphs
from src.context.context_engine import analyze_context
from src.sis.context_consistency import (
    build_context_evidence,
    correlate_context_evidence,
)


BASELINE = Path(
    "data/system_snapshot_20260820T205710Z.json"
)

CURRENT = Path(
    "data/system_snapshot_20260820T220640Z.json"
)


def main():

    baseline = json.loads(
        BASELINE.read_text(
            encoding="utf-8"
        )
    )

    current = json.loads(
        CURRENT.read_text(
            encoding="utf-8"
        )
    )

    baseline_graph = build_system_identity_graph(
        normalize_snapshot(baseline)
    )

    current_graph = build_system_identity_graph(
        normalize_snapshot(current)
    )

    comparison = compare_graphs(
        baseline_graph,
        current_graph
    )

    context = analyze_context(
        comparison,
        baseline_graph,
        current_graph
    )

    evidence = build_context_evidence(
        context
    )

    records = [
        record
        for record in evidence.get("evidence", [])
        if record.get("dimension") == "network"
    ]

    correlated = correlate_context_evidence(
        evidence
    )

    network_units = [
        unit
        for unit in correlated.get("units", [])
        if "network" in unit.get("dimensions", {})
    ]

    known_states = 0
    unknown_states = 0

    for record in records:

        connection = record.get(
            "connection"
        )

        state = record.get(
            "state"
        )

        if state is None:
            remote = (
                connection.get("remote_endpoint", {})
                if isinstance(connection, dict)
                else {}
            )

            state = remote.get(
                "classification"
            )

        if state is None:
            unknown_states += 1
        else:
            known_states += 1

    print("=== NETWORK CHECK ===")
    print("Network evidence:", len(records))
    print("Network correlated units:", len(network_units))
    print("Known network states:", known_states)
    print("Unknown network states:", unknown_states)

    print("\nFIRST NETWORK RECORD:")

    if records:
        record = records[0]

        print(
            "connection_node_id:",
            record.get("connection_node_id")
        )

        print(
            "process_node_id:",
            record.get("process_node_id")
        )

        connection = record.get(
            "connection"
        )

        if isinstance(connection, dict):

            print(
                "nested process_node_id:",
                connection.get("process_node_id")
            )

            remote = connection.get(
                "remote_endpoint",
                {}
            )

            if isinstance(remote, dict):

                print(
                    "remote classification:",
                    remote.get("classification")
                )

        print(
            "state:",
            record.get("state")
        )


if __name__ == "__main__":
    main()