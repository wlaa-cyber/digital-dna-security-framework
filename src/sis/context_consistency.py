"""
Context Consistency and Evidence Correlation
============================================

Production implementation for the Digital DNA / SIS pipeline.

Pipeline:
    Context Engine
        -> build_context_evidence()
        -> correlate_context_evidence()
        -> evaluate_context_unit()
        -> calculate_context_consistency()

Design rules:
- Missing/unknown telemetry is not a contradiction.
- Nested Context Engine evidence is normalized into usable states.
- Network evidence is correlated with its owning process.
- A process may legitimately own multiple network connections with
  different endpoint classifications; this is NOT an internal conflict.
- Other contextual dimensions are inconsistent only when distinct
  usable states conflict within the same correlated unit.
- The module does not calculate structural similarity, malware
  classification, security decisions, or baseline evolution.
"""

from collections import defaultdict


# =====================================================================
# Constants
# =====================================================================

UNKNOWN_STATES = {
    None,
    "",
    "UNKNOWN",
    "UNAVAILABLE",
    "NOT_AVAILABLE",
    "TEMPORAL_NOT_AVAILABLE",
}

CONTEXT_DIMENSIONS = (
    "identity",
    "trust",
    "location",
    "network",
    "parent_child",
    "temporal",
)

# Backward-compatible alias used by older tests/code.
DIMENSIONS = CONTEXT_DIMENSIONS


# =====================================================================
# State Helpers
# =====================================================================

def _normalize_state(value):
    """Return a stable comparable state, or None when unavailable."""
    if value is None:
        return None

    if isinstance(value, str):
        value = value.strip()

        if not value:
            return None

        unknown_strings = {
            str(item).strip().upper()
            for item in UNKNOWN_STATES
            if item is not None
        }

        if value.upper() in unknown_strings:
            return None

        return value.upper()

    value = str(value).strip()

    if not value:
        return None

    return value.upper()


def _is_unknown_state(state):
    """Return True when a state is unavailable or unknown."""
    return _normalize_state(state) is None


def _normalize_bool(value):
    """Normalize a boolean value without guessing string meanings."""
    if value is True:
        return True

    if value is False:
        return False

    return None


# =====================================================================
# Record Helpers
# =====================================================================

def _extract_records(value):
    """
    Normalize a dimension value into a list of evidence dictionaries.

    Supported forms:
        [record, record, ...]
        {record}
        {"records": [...]}
        {"evidence": [...]}
        {"added_connections": [...], "removed_connections": [...]}
    """
    if value is None:
        return []

    if isinstance(value, list):
        return [
            item
            for item in value
            if isinstance(item, dict)
        ]

    if isinstance(value, dict):
        # Check for records/evidence first
        records = value.get("records")
        if isinstance(records, list):
            return [
                item
                for item in records
                if isinstance(item, dict)
            ]

        evidence = value.get("evidence")
        if isinstance(evidence, list):
            return [
                item
                for item in evidence
                if isinstance(item, dict)
            ]

        # Handle network connections format
        connection_keys = ["added_connections", "removed_connections", "changed_connections"]
        has_connections = any(key in value for key in connection_keys)

        if has_connections:
            all_records = []
            for key in connection_keys:
                connections = value.get(key, [])
                if isinstance(connections, list):
                    for conn in connections:
                        if isinstance(conn, dict):
                            conn_copy = dict(conn)
                            if "change_type" not in conn_copy:
                                if key == "added_connections":
                                    conn_copy["change_type"] = "added"
                                elif key == "removed_connections":
                                    conn_copy["change_type"] = "removed"
                                elif key == "changed_connections":
                                    conn_copy["change_type"] = "changed"
                            all_records.append(conn_copy)
            return all_records

        # Single record
        return [value]

    return []


def _get_dimension_items(dimensions):
    """
    Support both production dimension dictionaries and lists of
    already-evaluated dimension records.
    """
    if dimensions is None:
        return []

    if isinstance(dimensions, dict):
        return list(dimensions.items())

    if isinstance(dimensions, list):
        result = []

        for item in dimensions:
            if not isinstance(item, dict):
                continue

            dimension = item.get("dimension")

            if dimension is not None:
                result.append((dimension, item))

        return result

    return []


# =====================================================================
# State Derivation
# =====================================================================

def _derive_state(dimension, record):
    """
    Derive the actual contextual state from an evidence record.

    The Context Engine may place the meaningful state in:
        - record["state"]
        - record["current"]
        - nested signature/endpoint structures

    The function never invents a state.
    """

    if not isinstance(record, dict):
        return None

    # -------------------------------------------------------------
    # 1. Explicit state always has priority.
    # -------------------------------------------------------------

    state = _normalize_state(
        record.get("state")
    )

    if state is not None:
        return state

    current = record.get("current")

    if not isinstance(current, dict):
        current = {}

    # -------------------------------------------------------------
    # 2. TRUST
    # -------------------------------------------------------------

    if dimension == "trust":

        signature = current.get("signature")

        if isinstance(signature, dict):

            for key in (
                "signature_status",
                "original_status",
                "trust_assessment",
            ):
                state = _normalize_state(
                    signature.get(key)
                )

                if state is not None:
                    return state

        for source in (
            current,
            record,
        ):

            for key in (
                "trust_assessment",
                "signature_status",
            ):
                state = _normalize_state(
                    source.get(key)
                )

                if state is not None:
                    return state

    # -------------------------------------------------------------
    # 3. LOCATION
    # -------------------------------------------------------------

    elif dimension == "location":

        for source in (
            current,
            record,
        ):

            for key in (
                "location_class",
                "location_assessment",
            ):
                state = _normalize_state(
                    source.get(key)
                )

                if state is not None:
                    return state

    # -------------------------------------------------------------
    # 4. NETWORK
    # -------------------------------------------------------------

    elif dimension == "network":

        # Check for state in the record itself
        direct_state = record.get("state")
        if direct_state is not None:
            state = _normalize_state(direct_state)
            if state is not None:
                return state

        # Check for classification in the record
        classification = record.get("classification")
        if classification is not None:
            state = _normalize_state(classification)
            if state is not None:
                return state

        # Get the connection object
        connection = record.get("connection")
        if not isinstance(connection, dict):
            connection = record

        # Try remote_endpoint classification first
        remote = connection.get("remote_endpoint")
        if isinstance(remote, dict):
            classification = remote.get("classification")
            if classification is not None:
                state = _normalize_state(classification)
                if state is not None:
                    return state

        # Fall back to local_endpoint classification
        local = connection.get("local_endpoint")
        if isinstance(local, dict):
            classification = local.get("classification")
            if classification is not None:
                state = _normalize_state(classification)
                if state is not None:
                    return state

        # Try direct classification in connection
        classification = connection.get("classification")
        if classification is not None:
            state = _normalize_state(classification)
            if state is not None:
                return state

        # Check in current object
        current_classification = current.get("classification")
        if current_classification is not None:
            state = _normalize_state(current_classification)
            if state is not None:
                return state

        # Check for endpoint classification directly in record
        endpoint = record.get("endpoint")
        if isinstance(endpoint, dict):
            classification = endpoint.get("classification")
            if classification is not None:
                state = _normalize_state(classification)
                if state is not None:
                    return state

        # Alternative explicit network classifications
        for source in (connection, current, record):
            if not isinstance(source, dict):
                continue
            for key in ("network_class", "connection_class"):
                state = _normalize_state(source.get(key))
                if state is not None:
                    return state

    # -------------------------------------------------------------
    # 5. PARENT / CHILD
    # -------------------------------------------------------------

    elif dimension == "parent_child":

        for source in (
            current,
            record,
        ):

            for key in (
                "relation",
                "relationship",
                "relationship_state",
            ):
                state = _normalize_state(
                    source.get(key)
                )

                if state is not None:
                    return state

    # -------------------------------------------------------------
    # 6. TEMPORAL
    # -------------------------------------------------------------

    elif dimension == "temporal":

        for source in (
            record,
            current,
        ):

            state = _normalize_state(
                source.get("relation")
            )

            if state is not None:
                return state

        # No temporal relation is invented.

    # -------------------------------------------------------------
    # 7. IDENTITY
    # -------------------------------------------------------------

    elif dimension == "identity":

        for source in (
            current,
            record,
        ):

            for key in (
                "identity_state",
                "identity_class",
                "classification",
            ):
                state = _normalize_state(
                    source.get(key)
                )

                if state is not None:
                    return state

    return None


# =====================================================================
# Evidence Preparation
# =====================================================================

def _prepare_record(dimension, record):
    """
    Prepare one normalized evidence record while preserving all original
    fields.
    """
    if not isinstance(record, dict):
        return None

    prepared = dict(record)

    prepared["dimension"] = dimension

    prepared["state"] = _derive_state(
        dimension,
        record,
    )

    # Network specific handling
    if dimension == "network":
        # Set node_id from connection_node_id if available
        if prepared.get("node_id") is None:
            connection_node_id = prepared.get("connection_node_id")
            if connection_node_id is not None:
                prepared["node_id"] = connection_node_id

        # Get process_node_id from the connection object
        connection = prepared.get("connection")
        if isinstance(connection, dict):
            process_node_id = connection.get("process_node_id")
            if process_node_id is not None and prepared.get("process_node_id") is None:
                prepared["process_node_id"] = process_node_id

            # Also try to get from process.node_id
            if process_node_id is None:
                process = connection.get("process")
                if isinstance(process, dict):
                    process_node_id = process.get("node_id")
                    if process_node_id is not None:
                        prepared["process_node_id"] = process_node_id

            connection_node_id = connection.get("connection_node_id")
            if connection_node_id is not None and prepared.get("connection_node_id") is None:
                prepared["connection_node_id"] = connection_node_id

    return prepared


# =====================================================================
# Context Evidence Construction
# =====================================================================

def build_context_evidence(context):
    """
    Flatten Context Engine output into normalized evidence records.

    Returns:
        {
            "evidence_count": int,
            "evidence": [...]
        }
    """
    if not isinstance(context, dict):
        return {
            "evidence_count": 0,
            "evidence": [],
        }

    evidence = []

    for dimension in CONTEXT_DIMENSIONS:

        module = context.get(
            dimension
        )

        if not isinstance(module, dict):
            continue

        for value in module.values():

            for record in _extract_records(
                value
            ):

                prepared = _prepare_record(
                    dimension,
                    record,
                )

                if prepared is not None:
                    evidence.append(
                        prepared
                    )

    return {
        "evidence_count": len(evidence),
        "evidence": evidence,
    }


# =====================================================================
# Evidence Correlation - FIXED
# =====================================================================

def correlate_context_evidence(evidence_result):
    """
    Correlate evidence by the owning System Identity unit.

    Network:
        connection -> owning process

    Parent/child:
        evidence -> child process

    Other dimensions:
        evidence -> own node_id
    """

    if not isinstance(evidence_result, dict):
        return {
            "correlated_unit_count": 0,
            "units": [],
        }

    evidence = evidence_result.get("evidence", [])

    if not isinstance(evidence, list):
        return {
            "correlated_unit_count": 0,
            "units": [],
        }

    # Use a dictionary to group by correlation_id
    grouped = defaultdict(lambda: defaultdict(list))

    for record in evidence:
        if not isinstance(record, dict):
            continue

        node_id = record.get("node_id")
        dimension = record.get("dimension")

        if node_id is None or dimension is None:
            continue

        # ---------------------------------------------------------
        # CRITICAL FIX: Determine correlation_id
        # ---------------------------------------------------------

        correlation_id = None

        # 1. Check if record has explicit correlation_node_id
        correlation_id = record.get("correlation_node_id")

        # 2. If not, try to get process_node_id
        if correlation_id is None:
            correlation_id = record.get("process_node_id")

        # 3. For network, try to extract from connection
        if correlation_id is None and dimension == "network":
            connection = record.get("connection")
            if isinstance(connection, dict):
                correlation_id = connection.get("process_node_id")
                if correlation_id is None:
                    process = connection.get("process")
                    if isinstance(process, dict):
                        correlation_id = process.get("node_id")

        # 4. For trust/location/temporal/identity, node_id already starts with "process:"
        if correlation_id is None:
            # Check if node_id starts with "process:"
            if isinstance(node_id, str) and node_id.startswith("process:"):
                correlation_id = node_id
            else:
                # Try to extract from current.node_id
                current = record.get("current")
                if isinstance(current, dict):
                    current_node_id = current.get("node_id")
                    if isinstance(current_node_id, str) and current_node_id.startswith("process:"):
                        correlation_id = current_node_id

        # 5. Last resort: use node_id
        if correlation_id is None:
            correlation_id = node_id

        if correlation_id is None:
            continue

        grouped[correlation_id][dimension].append(dict(record))

    units = []

    for node_id, dimensions in grouped.items():
        units.append({
            "node_id": node_id,
            "dimensions": {
                dimension: records
                for dimension, records in dimensions.items()
            },
        })

    return {
        "correlated_unit_count": len(units),
        "units": units,
    }


# =====================================================================
# Correlated Input Normalization
# =====================================================================

def _normalize_correlated_input(correlated_context):
    """
    Normalize supported correlated-context input forms.

    Supported:
        1. {"units": [...]}
        2. [...]
        3. {"node_id": "...", "dimensions": {...}}
        4. {"process:123": {"dimensions": {...}}}
    """

    if isinstance(
        correlated_context,
        list
    ):

        return [
            unit
            for unit in correlated_context
            if isinstance(
                unit,
                dict
            )
        ]

    if not isinstance(
        correlated_context,
        dict
    ):

        return []

    # Standard production format.
    units = correlated_context.get(
        "units"
    )

    if isinstance(
        units,
        list
    ):

        return [
            unit
            for unit in units
            if isinstance(
                unit,
                dict
            )
        ]

    # Single unit.
    if (
        "node_id" in correlated_context
        and "dimensions" in correlated_context
    ):

        return [
            correlated_context
        ]

    # Direct node -> unit mapping.
    result = []

    for node_id, value in correlated_context.items():

        if not isinstance(
            value,
            dict
        ):
            continue

        if "dimensions" not in value:
            continue

        unit = dict(
            value
        )

        if unit.get(
            "node_id"
        ) is None:

            unit["node_id"] = node_id

        result.append(
            unit
        )

    return result


# =====================================================================
# Dimension Evaluation
# =====================================================================

def _evaluate_dimension(dimension, records):
    """
    Evaluate one contextual dimension.

    Normal dimensions:
        Multiple distinct usable states = inconsistency.

    Network:
        Multiple states are expected because one process can own
        multiple simultaneous connections. Different endpoint
        classifications therefore do not constitute a contradiction.

    Unknown/unavailable states are ignored.
    """

    records = _extract_records(
        records
    )

    states = []

    for record in records:

        if not isinstance(
            record,
            dict
        ):
            continue

        state = _derive_state(
            dimension,
            record,
        )

        state = _normalize_state(
            state
        )

        if _is_unknown_state(
            state
        ):
            continue

        states.append(
            state
        )

    if not states:

        return {
            "dimension": dimension,
            "usable": False,
            "internally_consistent": None,
            "states": [],
            "record_count": len(records),
        }

    unique_states = list(
        dict.fromkeys(
            states
        )
    )

    # Network is explicitly one-to-many.
    if dimension == "network":

        internally_consistent = True

    else:

        internally_consistent = (
            len(unique_states) == 1
        )

    return {
        "dimension": dimension,
        "usable": True,
        "internally_consistent":
            internally_consistent,
        "states": unique_states,
        "record_count": len(records),
    }


# =====================================================================
# Context Unit Evaluation
# =====================================================================

def evaluate_context_unit(unit):
    """
    Evaluate contextual consistency for one correlated unit.

    Formula:

        Context Score =
            consistent usable dimensions
            --------------------------------
                 usable dimensions

    Unknown dimensions are excluded from the denominator.

    A unit with no usable dimensions receives the neutral score 1.0
    but is not counted as an evaluated unit.
    """

    if not isinstance(
        unit,
        dict
    ):

        return {
            "node_id": None,
            "context_score": 1.0,
            "dimension_count": len(
                CONTEXT_DIMENSIONS
            ),
            "usable_dimension_count": 0,
            "unknown_dimension_count": len(
                CONTEXT_DIMENSIONS
            ),
            "consistent_dimension_count": 0,
            "dimensions": [],
        }

    node_id = unit.get(
        "node_id"
    )

    raw_dimensions = unit.get(
        "dimensions",
        {}
    )

    items = _get_dimension_items(
        raw_dimensions
    )

    evaluations = []

    usable = 0
    unknown = 0
    consistent = 0
    supplied = set()

    for dimension, value in items:

        if dimension in supplied:
            continue

        supplied.add(
            dimension
        )

        # Compatibility with already-evaluated dimension objects.
        if (
            isinstance(value, dict)
            and "usable" in value
            and "internally_consistent" in value
        ):

            is_usable = bool(
                value.get(
                    "usable"
                )
            )

            states = value.get(
                "states",
                []
            )

            if not isinstance(
                states,
                list
            ):

                states = [
                    states
                ]

            normalized_states = []

            for state in states:

                state = _normalize_state(
                    state
                )

                if not _is_unknown_state(
                    state
                ):

                    normalized_states.append(
                        state
                    )

            internal = value.get(
                "internally_consistent"
            )

            # Preserve the semantic network rule even for
            # pre-evaluated input.
            if (
                dimension == "network"
                and is_usable
            ):

                internal = True

            evaluation = {
                "dimension": dimension,
                "usable": is_usable,
                "internally_consistent": internal,
                "states": list(
                    dict.fromkeys(
                        normalized_states
                    )
                ),
                "record_count": value.get(
                    "record_count",
                    len(states),
                ),
            }

        else:

            evaluation = _evaluate_dimension(
                dimension,
                value,
            )

        evaluations.append(
            evaluation
        )

        if evaluation.get(
            "usable"
        ):

            usable += 1

            if evaluation.get(
                "internally_consistent"
            ) is True:

                consistent += 1

        else:

            unknown += 1

    # Always expose all standard dimensions.
    for dimension in CONTEXT_DIMENSIONS:

        if dimension in supplied:
            continue

        evaluations.append(
            {
                "dimension": dimension,
                "usable": False,
                "internally_consistent": None,
                "states": [],
                "record_count": 0,
            }
        )

        unknown += 1

    if usable > 0:

        score = (
            consistent / usable
        )

    else:

        score = 1.0

    score = max(
        0.0,
        min(
            1.0,
            float(score)
        )
    )

    return {
        "node_id": node_id,
        "context_score": score,
        "dimension_count": len(
            evaluations
        ),
        "usable_dimension_count": usable,
        "unknown_dimension_count": unknown,
        "consistent_dimension_count": consistent,
        "dimensions": evaluations,
    }


# =====================================================================
# Global Context Consistency
# =====================================================================

def calculate_context_consistency(correlated_context):
    """
    Calculate aggregate Context Consistency and Context Coverage.

    Context Coverage:
        evaluated units / correlated units

    Context Consistency:
        average Context Score over evaluated units

    Missing telemetry is not treated as contradiction and therefore
    does not directly reduce Context Consistency.
    """

    units = _normalize_correlated_input(
        correlated_context
    )

    correlated_count = len(
        units
    )

    evaluations = []

    for unit in units:

        evaluation = evaluate_context_unit(
            unit
        )

        if (
            evaluation[
                "usable_dimension_count"
            ] > 0
        ):

            evaluations.append(
                evaluation
            )

    evaluated_count = len(
        evaluations
    )

    if correlated_count > 0:

        coverage = (
            evaluated_count
            / correlated_count
        )

    else:

        coverage = 0.0

    if evaluated_count > 0:

        average = (
            sum(
                evaluation[
                    "context_score"
                ]
                for evaluation in evaluations
            )
            / evaluated_count
        )

    else:

        average = 1.0

    average = max(
        0.0,
        min(
            1.0,
            float(average)
        )
    )

    coverage = max(
        0.0,
        min(
            1.0,
            float(coverage)
        )
    )

    return {
        "context_consistency": average,
        "correlated_unit_count": correlated_count,
        "evaluated_unit_count": evaluated_count,
        "context_coverage": coverage,
        "average_unit_context_score": average,
        "unit_evaluations": evaluations,
    }
