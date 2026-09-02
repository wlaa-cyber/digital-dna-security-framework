"""
Trust Context
-------------
Evidence-based trust analysis for the
Digital DNA Security Framework.

This module analyzes digital-signature evidence already
present in the System Identity Graph.

It does NOT:
    - determine whether a file is malware
    - calculate a risk score
    - make a final security decision
    - recollect digital signatures from Windows

It only produces structured trust evidence.
"""

from typing import Any


# ----------------------------------------------------------------------
# Signature status categories
# ----------------------------------------------------------------------

VALID_STATUS = "VALID"

EXPLICIT_UNTRUSTED_STATUSES = {
    "UNSIGNED",
    "HASHMISMATCH",
    "NOTTRUSTED",
}

UNKNOWN_STATUS = "UNKNOWN"

SIGNATURE_NOT_AVAILABLE = "SIGNATURE_NOT_AVAILABLE"


# ----------------------------------------------------------------------
# Status normalization
# ----------------------------------------------------------------------

def _normalize_signature_status(
    status: Any,
) -> str:
    """
    Normalize a digital-signature status into a stable
    internal representation.

    The original status is preserved separately in the
    evidence output.
    """

    if not isinstance(status, str):
        return UNKNOWN_STATUS

    normalized = status.strip().upper()

    if not normalized:
        return UNKNOWN_STATUS

    compact = normalized.replace("_", "").replace(" ", "")

    if compact == "VALID":
        return VALID_STATUS

    if compact in {
        "UNSIGNED",
        "NOSIGNATURE",
    }:
        return "UNSIGNED"

    if compact in {
        "HASHMISMATCH",
    }:
        return "HASHMISMATCH"

    if compact in {
        "NOTTRUSTED",
        "TRUSTEENOTTRUSTED",
        "TRUSTFAILURE",
    }:
        return "NOTTRUSTED"

    return UNKNOWN_STATUS


# ----------------------------------------------------------------------
# Publisher normalization
# ----------------------------------------------------------------------

def _normalize_publisher(
    publisher: Any,
) -> str | None:
    """
    Normalize publisher information without attempting
    to interpret or classify the publisher as trusted
    or untrusted.
    """

    if not isinstance(publisher, str):
        return None

    value = publisher.strip()

    if not value:
        return None

    return value


# ----------------------------------------------------------------------
# Single signature analysis
# ----------------------------------------------------------------------

def analyze_signature(
    signature: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Analyze one digital-signature record.

    This function produces evidence only.

    It does not determine whether the signed file is
    safe or malicious.
    """

    # --------------------------------------------------------------
    # No signature record
    # --------------------------------------------------------------

    if not isinstance(signature, dict):
        return {
            "signature_available": False,
            "signature_status": SIGNATURE_NOT_AVAILABLE,
            "original_status": None,
            "status_code": None,
            "status_message": None,
            "publisher": None,
            "subject": None,
            "issuer": None,
            "serial_number": None,
            "trust_assessment": (
                "Digital signature evidence is unavailable"
            ),
            "evidence_strength": "None",
        }

    original_status = signature.get("status")

    normalized_status = _normalize_signature_status(
        original_status
    )

    publisher = _normalize_publisher(
        signature.get("publisher")
    )

    evidence: dict[str, Any] = {
        "signature_available": True,
        "signature_status": normalized_status,
        "original_status": original_status,
        "status_code": signature.get("status_code"),
        "status_message": signature.get("status_message"),
        "publisher": publisher,
        "subject": signature.get("subject"),
        "issuer": signature.get("issuer"),
        "serial_number": signature.get("serial_number"),
        "path": signature.get("path"),
    }

    # --------------------------------------------------------------
    # Evidence interpretation
    # --------------------------------------------------------------

    if normalized_status == VALID_STATUS:

        evidence["trust_assessment"] = (
            "A valid digital signature was observed"
        )

        evidence["evidence_strength"] = "Informational"

    elif normalized_status == "UNSIGNED":

        evidence["trust_assessment"] = (
            "No valid digital signature was observed"
        )

        evidence["evidence_strength"] = "Informational"

    elif normalized_status == "HASHMISMATCH":

        evidence["trust_assessment"] = (
            "Digital signature verification reported "
            "a hash mismatch"
        )

        evidence["evidence_strength"] = "High"

    elif normalized_status == "NOTTRUSTED":

        evidence["trust_assessment"] = (
            "Digital signature verification reported "
            "that the signature is not trusted"
        )

        evidence["evidence_strength"] = "High"

    else:

        evidence["trust_assessment"] = (
            "Digital signature status is unknown"
        )

        evidence["evidence_strength"] = "Informational"

    return evidence


# ----------------------------------------------------------------------
# Find signature connected to a process
# ----------------------------------------------------------------------

def get_process_signature(
    graph: Any,
    process_node_id: Any,
) -> dict[str, Any] | None:
    """
    Find the digital-signature node connected to a process
    through a 'has_signature' relationship.

    Returns:
        Signature node attributes when available,
        otherwise None.
    """

    if graph is None:
        return None

    if process_node_id not in graph:
        return None

    for _, target, edge_data in graph.out_edges(
        process_node_id,
        data=True,
    ):

        if edge_data.get("relationship") != "has_signature":
            continue

        if target not in graph:
            continue

        target_attributes = graph.nodes[target]

        if (
            target_attributes.get("entity_type")
            != "digital_signature"
        ):
            continue

        return dict(target_attributes)

    return None


# ----------------------------------------------------------------------
# Analyze one process trust context
# ----------------------------------------------------------------------

def analyze_process_trust(
    graph: Any,
    process_node_id: Any,
) -> dict[str, Any]:
    """
    Produce trust evidence for one process node.

    The function uses the existing graph relationship:

        process --has_signature--> digital_signature

    It does not recollect signature information.
    """

    if graph is None or process_node_id not in graph:

        return {
            "node_id": process_node_id,
            "entity_type": None,
            "signature": analyze_signature(None),
        }

    process_attributes = graph.nodes[
        process_node_id
    ]

    signature = get_process_signature(
        graph,
        process_node_id,
    )

    evidence = analyze_signature(
        signature
    )

    return {
        "node_id": process_node_id,
        "entity_type": process_attributes.get(
            "entity_type"
        ),
        "name": process_attributes.get("name"),
        "path": process_attributes.get("path"),
        "signature": evidence,
    }


# ----------------------------------------------------------------------
# Compare signature trust identity/state
# ----------------------------------------------------------------------

def _signature_state_changed(
    baseline_signature: dict[str, Any],
    current_signature: dict[str, Any],
) -> bool:
    """
    Determine whether the trust-related signature evidence
    changed between baseline and current.

    The filesystem path is intentionally excluded.

    Location changes are handled separately by Location Context.

    Compared fields:
        - signature_status
        - publisher
        - subject
        - issuer
        - serial_number
    """

    trust_fields = (
        "signature_status",
        "publisher",
        "subject",
        "issuer",
        "serial_number",
    )

    for field in trust_fields:

        if (
            baseline_signature.get(field)
            != current_signature.get(field)
        ):
            return True

    return False


# ----------------------------------------------------------------------
# Analyze trust context for graph changes
# ----------------------------------------------------------------------

def analyze_trust_changes(
    comparison_result: dict[str, Any],
    baseline_graph: Any,
    current_graph: Any,
) -> dict[str, Any]:
    """
    Analyze trust context for changed process nodes.

    Supported change types:
        - ADDED
        - CHANGED
        - REMOVED

    Trust analysis is performed using the graph's existing
    process -> digital_signature relationship.

    No security decision is made.
    """

    evidence: dict[str, Any] = {
        "added": [],
        "changed": [],
        "removed": [],
        "summary": {
            "added_count": 0,
            "changed_count": 0,
            "removed_count": 0,
            "signature_available_count": 0,
            "signature_not_available_count": 0,
        },
    }

    # --------------------------------------------------------------
    # Helper for counting signature availability
    # --------------------------------------------------------------

    def update_availability_count(
        record: dict[str, Any],
    ) -> None:

        signature = record.get("signature", {})

        if signature.get("signature_available") is True:

            evidence["summary"][
                "signature_available_count"
            ] += 1

        else:

            evidence["summary"][
                "signature_not_available_count"
            ] += 1

    # --------------------------------------------------------------
    # Added processes
    # --------------------------------------------------------------

    for node_id in comparison_result.get(
        "added_nodes",
        [],
    ):

        if node_id not in current_graph:
            continue

        attributes = current_graph.nodes[node_id]

        if attributes.get("entity_type") != "process":
            continue

        record = {
            "node_id": node_id,
            "change_type": "ADDED",
            "current": analyze_process_trust(
                current_graph,
                node_id,
            ),
        }

        evidence["added"].append(record)

        update_availability_count(
            record["current"]
        )

    # --------------------------------------------------------------
    # Changed processes
    # --------------------------------------------------------------

    for node_id, changed_properties in comparison_result.get(
        "changed_nodes",
        {},
    ).items():

        if node_id not in baseline_graph:
            continue

        if node_id not in current_graph:
            continue

        baseline_attributes = baseline_graph.nodes[
            node_id
        ]

        current_attributes = current_graph.nodes[
            node_id
        ]

        if (
            baseline_attributes.get("entity_type")
            != "process"
            and current_attributes.get("entity_type")
            != "process"
        ):
            continue

        baseline_trust = analyze_process_trust(
            baseline_graph,
            node_id,
        )

        current_trust = analyze_process_trust(
            current_graph,
            node_id,
        )

        baseline_signature = baseline_trust[
            "signature"
        ]

        current_signature = current_trust[
            "signature"
        ]

        signature_changed = _signature_state_changed(
            baseline_signature,
            current_signature,
        )

        record = {
            "node_id": node_id,
            "change_type": "CHANGED",
            "changed_properties": changed_properties,
            "signature_changed": signature_changed,
            "baseline": baseline_trust,
            "current": current_trust,
        }

        evidence["changed"].append(record)

        update_availability_count(
            current_trust
        )

    # --------------------------------------------------------------
    # Removed processes
    # --------------------------------------------------------------

    for node_id in comparison_result.get(
        "removed_nodes",
        [],
    ):

        if node_id not in baseline_graph:
            continue

        attributes = baseline_graph.nodes[node_id]

        if attributes.get("entity_type") != "process":
            continue

        record = {
            "node_id": node_id,
            "change_type": "REMOVED",
            "baseline": analyze_process_trust(
                baseline_graph,
                node_id,
            ),
        }

        evidence["removed"].append(record)

        update_availability_count(
            record["baseline"]
        )

    # --------------------------------------------------------------
    # Final summary
    # --------------------------------------------------------------

    evidence["summary"].update(
        {
            "added_count": len(
                evidence["added"]
            ),
            "changed_count": len(
                evidence["changed"]
            ),
            "removed_count": len(
                evidence["removed"]
            ),
        }
    )

    return evidence