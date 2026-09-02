from datetime import datetime, timezone
from typing import Any


# ============================================================
# Configuration
# ============================================================

LOCAL_TIMEZONE = datetime.now().astimezone().tzinfo


# ============================================================
# Constants
# ============================================================

TEMPORAL_NOT_AVAILABLE = "TEMPORAL_NOT_AVAILABLE"

RELATION_BEFORE = "BEFORE"
RELATION_AFTER = "AFTER"
RELATION_SAME_TIME = "SAME_TIME"

EVIDENCE_STRONG = "Strong"
EVIDENCE_MODERATE = "Moderate"
EVIDENCE_INFORMATIONAL = "Informational"
EVIDENCE_NONE = None

PRECISION_DATETIME = "DATETIME"
PRECISION_DATE_ONLY = "DATE_ONLY"


# ============================================================
# Scheduled Task Sentinel Values
# ============================================================

# Windows Scheduled Tasks may use these values when there is
# no meaningful previous execution time.
#
# These values are handled ONLY in the Scheduled Task context.
# They are NOT globally treated as invalid timestamps.

SCHEDULED_TASK_UNAVAILABLE_TIMESTAMPS = {
    "11/30/1999 12:00:00 AM",
    "11/30/1999 12:00 AM",
}


# ============================================================
# Generic Helpers
# ============================================================

def _safe_value(value: Any) -> Any:
    """
    Convert empty or meaningless values to None.

    Old dates are NOT treated as invalid here because genuinely
    old timestamps may be valid historical events.
    """

    if value is None:
        return None

    if isinstance(value, str):

        normalized = " ".join(
            value.strip().lower().split()
        )

        invalid_values = {
            "",
            "n/a",
            "na",
            "none",
            "null",
            "unknown",
            "not available",
            "not_available",
            "-",
        }

        if normalized in invalid_values:
            return None

    return value


def _is_scheduled_task_unavailable_timestamp(
    value: Any,
) -> bool:
    """
    Determine whether a timestamp is a known Scheduled Task
    sentinel value rather than a real execution timestamp.
    """

    if value is None:
        return False

    if not isinstance(value, str):
        return False

    normalized = " ".join(
        value.strip().lower().split()
    )

    normalized_sentinels = {
        " ".join(
            sentinel.strip().lower().split()
        )
        for sentinel in SCHEDULED_TASK_UNAVAILABLE_TIMESTAMPS
    }

    return normalized in normalized_sentinels


# ============================================================
# Timestamp Parsing
# ============================================================

def _parse_datetime(
    value: Any,
    assume_local_for_naive: bool = True,
) -> datetime | None:
    """
    Parse a timestamp into a timezone-aware UTC datetime.

    Supported formats include:

    - ISO 8601
    - Windows schtasks timestamps
    - Standard date/time strings
    """

    value = _safe_value(value)

    if value is None:
        return None

    # --------------------------------------------------------
    # datetime object
    # --------------------------------------------------------

    if isinstance(value, datetime):

        dt = value

    # --------------------------------------------------------
    # String value
    # --------------------------------------------------------

    elif isinstance(value, str):

        text = value.strip()

        dt = None

        # ----------------------------------------------------
        # Windows schtasks formats
        # ----------------------------------------------------

        windows_formats = [
            "%m/%d/%Y %I:%M:%S %p",
            "%m/%d/%Y %I:%M %p",
            "%m/%d/%Y",
        ]

        for fmt in windows_formats:

            try:

                dt = datetime.strptime(
                    text,
                    fmt,
                )

                break

            except ValueError:
                continue

        # ----------------------------------------------------
        # ISO 8601
        # ----------------------------------------------------

        if dt is None:

            iso_text = text

            if iso_text.endswith("Z"):
                iso_text = (
                    iso_text[:-1] + "+00:00"
                )

            try:

                dt = datetime.fromisoformat(
                    iso_text
                )

            except ValueError:

                dt = None

        if dt is None:
            return None

    else:

        return None

    # --------------------------------------------------------
    # Timezone handling
    # --------------------------------------------------------

    if dt.tzinfo is None:

        if assume_local_for_naive:

            dt = dt.replace(
                tzinfo=LOCAL_TIMEZONE
            )

        else:

            dt = dt.replace(
                tzinfo=timezone.utc
            )

    return dt.astimezone(
        timezone.utc
    )


# ============================================================
# Timestamp Normalization
# ============================================================

def normalize_timestamp(
    value: Any,
    precision: str | None = None,
) -> dict[str, Any]:
    """
    Normalize a temporal value.

    DATETIME values are converted to UTC.

    DATE_ONLY values are normalized to UTC midnight without
    shifting the calendar date.
    """

    original = value

    value = _safe_value(value)

    if value is None:

        return {
            "available": False,
            "original": original,
            "normalized": None,
            "precision": (
                precision
                or PRECISION_DATETIME
            ),
        }

    # --------------------------------------------------------
    # DATE_ONLY
    # --------------------------------------------------------

    if precision == PRECISION_DATE_ONLY:

        text = str(value).strip()

        date_formats = [
            "%Y%m%d",
            "%Y-%m-%d",
        ]

        parsed_date = None

        for fmt in date_formats:

            try:

                parsed_date = datetime.strptime(
                    text,
                    fmt,
                ).date()

                break

            except ValueError:
                continue

        if parsed_date is not None:

            normalized = datetime(
                parsed_date.year,
                parsed_date.month,
                parsed_date.day,
                tzinfo=timezone.utc,
            )

            return {
                "available": True,
                "original": original,
                "normalized": normalized.isoformat(),
                "precision": PRECISION_DATE_ONLY,
            }

    # --------------------------------------------------------
    # DATETIME
    # --------------------------------------------------------

    parsed = _parse_datetime(value)

    if parsed is None:

        return {
            "available": False,
            "original": original,
            "normalized": None,
            "precision": (
                precision
                or PRECISION_DATETIME
            ),
        }

    return {
        "available": True,
        "original": original,
        "normalized": parsed.isoformat(),
        "precision": (
            precision
            or PRECISION_DATETIME
        ),
    }


# ============================================================
# Time Difference
# ============================================================

def calculate_time_difference(
    first_timestamp: Any,
    second_timestamp: Any,
) -> float | None:
    """
    Return the absolute difference between two timestamps
    in seconds.
    """

    first = _parse_datetime(
        first_timestamp
    )

    second = _parse_datetime(
        second_timestamp
    )

    if first is None or second is None:
        return None

    return abs(
        (
            first - second
        ).total_seconds()
    )


# ============================================================
# Temporal Relation
# ============================================================

def determine_temporal_relation(
    first_timestamp: Any,
    second_timestamp: Any,
) -> str:
    """
    Determine the temporal relationship between two events.
    """

    first = _parse_datetime(
        first_timestamp
    )

    second = _parse_datetime(
        second_timestamp
    )

    if first is None or second is None:
        return TEMPORAL_NOT_AVAILABLE

    if first < second:
        return RELATION_BEFORE

    if first > second:
        return RELATION_AFTER

    return RELATION_SAME_TIME


# ============================================================
# Snapshot Collection Time
# ============================================================

def get_snapshot_collection_time(
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    """
    Extract and normalize the main snapshot collection time.
    """

    snapshot_metadata = snapshot.get(
        "snapshot",
        {},
    )

    collected_at = snapshot_metadata.get(
        "collected_at"
    )

    normalized = normalize_timestamp(
        collected_at
    )

    return {
        "available": normalized["available"],
        "value": collected_at,
        "normalized": normalized[
            "normalized"
        ],
    }


# ============================================================
# Collector Collection Time
# ============================================================

def get_collector_collection_time(
    snapshot: dict[str, Any],
    collector_name: str,
) -> dict[str, Any]:
    """
    Extract and normalize the collection time for a collector.
    """

    collectors = snapshot.get(
        "collectors",
        {},
    )

    collector = collectors.get(
        collector_name,
        {},
    )

    collected_at = collector.get(
        "collected_at"
    )

    normalized = normalize_timestamp(
        collected_at
    )

    return {
        "collector": collector_name,
        "available": normalized[
            "available"
        ],
        "value": collected_at,
        "normalized": normalized[
            "normalized"
        ],
    }


# ============================================================
# Entity Temporal Fields
# ============================================================

def extract_entity_temporal_fields(
    entity: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Extract supported temporal fields from a normalized entity.

    Supported entity types:

    - process
    - scheduled_task
    - startup_item
    - installed_application
    - network_connection
    """

    entity_type = entity.get("type")

    properties = entity.get(
        "properties",
        {},
    )

    if not isinstance(properties, dict):
        properties = {}

    temporal_fields: list[
        tuple[str, Any, str]
    ] = []

    # --------------------------------------------------------
    # Process
    # --------------------------------------------------------

    if entity_type == "process":

        temporal_fields = [
            (
                "create_time",
                properties.get(
                    "create_time"
                ),
                PRECISION_DATETIME,
            ),
        ]

    # --------------------------------------------------------
    # Scheduled Task
    # --------------------------------------------------------

    elif entity_type == "scheduled_task":

        temporal_fields = [
            (
                "last_run_time",
                properties.get(
                    "last_run_time"
                ),
                PRECISION_DATETIME,
            ),
            (
                "next_run_time",
                properties.get(
                    "next_run_time"
                ),
                PRECISION_DATETIME,
            ),
            (
                "start_time",
                properties.get(
                    "start_time"
                ),
                PRECISION_DATETIME,
            ),
            (
                "start_date",
                properties.get(
                    "start_date"
                ),
                PRECISION_DATE_ONLY,
            ),
            (
                "end_date",
                properties.get(
                    "end_date"
                ),
                PRECISION_DATE_ONLY,
            ),
        ]

    # --------------------------------------------------------
    # Startup Item
    # --------------------------------------------------------

    elif entity_type == "startup_item":

        temporal_fields = [
            (
                "modified_at",
                properties.get(
                    "modified_at"
                ),
                PRECISION_DATETIME,
            ),
        ]

    # --------------------------------------------------------
    # Installed Application
    # --------------------------------------------------------

    elif entity_type == "installed_application":

        temporal_fields = [
            (
                "install_date",
                properties.get(
                    "install_date"
                ),
                PRECISION_DATE_ONLY,
            ),
        ]

    # --------------------------------------------------------
    # Network Connection
    # --------------------------------------------------------

    elif entity_type == "network_connection":

        temporal_fields = [
            (
                "timestamp",
                properties.get(
                    "timestamp"
                ),
                PRECISION_DATETIME,
            ),
            (
                "created_at",
                properties.get(
                    "created_at"
                ),
                PRECISION_DATETIME,
            ),
            (
                "connected_at",
                properties.get(
                    "connected_at"
                ),
                PRECISION_DATETIME,
            ),
            (
                "last_seen",
                properties.get(
                    "last_seen"
                ),
                PRECISION_DATETIME,
            ),
        ]

    # --------------------------------------------------------
    # Normalize fields
    # --------------------------------------------------------

    records = []

    for field_name, value, precision in temporal_fields:

        # ----------------------------------------------------
        # Scheduled Task sentinel
        # ----------------------------------------------------

        if (
            entity_type == "scheduled_task"
            and field_name == "last_run_time"
            and _is_scheduled_task_unavailable_timestamp(
                value
            )
        ):

            normalized = {
                "available": False,
                "original": value,
                "normalized": None,
                "precision": precision,
            }

        else:

            normalized = normalize_timestamp(
                value,
                precision=precision,
            )

        records.append(
            {
                "entity_id": entity.get(
                    "id"
                ),
                "entity_type": entity_type,
                "field": field_name,
                "original": value,
                "available": normalized[
                    "available"
                ],
                "normalized": normalized[
                    "normalized"
                ],
                "precision": normalized[
                    "precision"
                ],
            }
        )

    return records


# ============================================================
# Snapshot Temporal Evidence
# ============================================================

def extract_snapshot_temporal_evidence(
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    """
    Extract temporal evidence from the complete snapshot.

    Important:
    The entity_type is taken from the collector metadata because
    individual raw collector items do not contain entity_type.
    """

    collectors = snapshot.get(
        "collectors",
        {},
    )

    all_records: list[
        dict[str, Any]
    ] = []

    # --------------------------------------------------------
    # List-based collectors
    # --------------------------------------------------------

    list_collectors = [
        "processes",
        "scheduled_tasks",
        "startup",
        "installed_applications",
    ]

    for collector_name in list_collectors:

        collector = collectors.get(
            collector_name,
            {},
        )

        items = collector.get(
            "items",
            [],
        )

        if not isinstance(items, list):
            continue

        # ----------------------------------------------------
        # FIX:
        # entity_type belongs to the collector, not the item.
        # ----------------------------------------------------

        collector_entity_type = collector.get(
            "entity_type"
        )

        for item in items:

            if not isinstance(item, dict):
                continue

            entity = {
                "id": item.get(
                    "id"
                ),
                "type": collector_entity_type,
                "properties": item,
            }

            records = extract_entity_temporal_fields(
                entity
            )

            for record in records:

                record["collector"] = (
                    collector_name
                )

                all_records.append(
                    record
                )

    # --------------------------------------------------------
    # Network collector
    # --------------------------------------------------------

    network_collector = collectors.get(
        "network",
        {},
    )

    network_items = network_collector.get(
        "items",
        {},
    )

    if isinstance(network_items, dict):

        connections = network_items.get(
            "connections",
            [],
        )

        if isinstance(connections, list):

            for item in connections:

                if not isinstance(item, dict):
                    continue

                entity = {
                    "id": item.get(
                        "id"
                    ),
                    "type": "network_connection",
                    "properties": item,
                }

                records = extract_entity_temporal_fields(
                    entity
                )

                for record in records:

                    record["collector"] = (
                        "network"
                    )

                    all_records.append(
                        record
                    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    available_records = [
        record
        for record in all_records
        if record.get("available")
    ]

    unavailable_records = [
        record
        for record in all_records
        if not record.get("available")
    ]

    return {
        "snapshot_collection_time": (
            get_snapshot_collection_time(
                snapshot
            )
        ),
        "entities": all_records,
        "summary": {
            "total_temporal_records": len(
                all_records
            ),
            "available_temporal_records": len(
                available_records
            ),
            "unavailable_temporal_records": len(
                unavailable_records
            ),
        },
    }


# ============================================================
# Temporal Event Builder
# ============================================================

def _build_temporal_event(
    event_time: Any,
    reference_time: Any,
    event_name: str | None = None,
    reference_name: str | None = None,
) -> dict[str, Any]:
    """
    Build temporal evidence between two events.

    Evidence strength represents temporal proximity only.
    It is NOT a security risk score.
    """

    event = normalize_timestamp(
        event_time
    )

    reference = normalize_timestamp(
        reference_time
    )

    if (
        not event["available"]
        or not reference["available"]
    ):

        return {
            "available": False,
            "event": event_name,
            "reference": reference_name,
            "event_time": event,
            "reference_time": reference,
            "relation": TEMPORAL_NOT_AVAILABLE,
            "difference_seconds": None,
            "evidence_strength": EVIDENCE_NONE,
        }

    difference = calculate_time_difference(
        event_time,
        reference_time,
    )

    relation = determine_temporal_relation(
        event_time,
        reference_time,
    )

    if difference is None:

        strength = EVIDENCE_NONE

    elif difference <= 60:

        strength = EVIDENCE_STRONG

    elif difference <= 3600:

        strength = EVIDENCE_MODERATE

    else:

        strength = EVIDENCE_INFORMATIONAL

    return {
        "available": True,
        "event": event_name,
        "reference": reference_name,
        "event_time": event,
        "reference_time": reference,
        "relation": relation,
        "difference_seconds": difference,
        "evidence_strength": strength,
    }


# ============================================================
# Event Against Snapshot
# ============================================================

def analyze_event_against_snapshot(
    event_time: Any,
    snapshot: dict[str, Any],
    event_name: str | None = None,
) -> dict[str, Any]:
    """
    Compare an event timestamp with the snapshot collection time.
    """

    snapshot_time = get_snapshot_collection_time(
        snapshot
    )

    if not snapshot_time["available"]:

        return {
            "available": False,
            "event": event_name,
            "reference": "snapshot_collection",
            "relation": TEMPORAL_NOT_AVAILABLE,
            "difference_seconds": None,
            "evidence_strength": EVIDENCE_NONE,
        }

    return _build_temporal_event(
        event_time=event_time,
        reference_time=snapshot_time[
            "normalized"
        ],
        event_name=event_name,
        reference_name="snapshot_collection",
    )


# ============================================================
# Graph Node Event Time
# ============================================================

def _get_node_event_time(
    graph: Any,
    node_id: Any,
) -> dict[str, Any]:
    """
    Extract the most useful temporal field from a graph node.

    For Scheduled Tasks, a sentinel last_run_time is skipped so
    that next_run_time or another valid temporal field can be used.
    """

    if graph is None:

        return {
            "available": False,
            "field": None,
            "value": None,
            "normalized": None,
            "precision": None,
        }

    if node_id not in graph.nodes:

        return {
            "available": False,
            "field": None,
            "value": None,
            "normalized": None,
            "precision": None,
        }

    node_data = graph.nodes[
        node_id
    ]

    entity_type = node_data.get(
        "entity_type"
    )

    # --------------------------------------------------------
    # Process
    # --------------------------------------------------------

    if entity_type == "process":

        fields = [
            (
                "create_time",
                PRECISION_DATETIME,
            ),
        ]

    # --------------------------------------------------------
    # Scheduled Task
    # --------------------------------------------------------

    elif entity_type == "scheduled_task":

        fields = [
            (
                "last_run_time",
                PRECISION_DATETIME,
            ),
            (
                "next_run_time",
                PRECISION_DATETIME,
            ),
            (
                "start_time",
                PRECISION_DATETIME,
            ),
            (
                "start_date",
                PRECISION_DATE_ONLY,
            ),
            (
                "end_date",
                PRECISION_DATE_ONLY,
            ),
        ]

    # --------------------------------------------------------
    # Startup Item
    # --------------------------------------------------------

    elif entity_type == "startup_item":

        fields = [
            (
                "modified_at",
                PRECISION_DATETIME,
            ),
        ]

    # --------------------------------------------------------
    # Installed Application
    # --------------------------------------------------------

    elif entity_type == "installed_application":

        fields = [
            (
                "install_date",
                PRECISION_DATE_ONLY,
            ),
        ]

    # --------------------------------------------------------
    # Network Connection
    # --------------------------------------------------------

    elif entity_type == "network_connection":

        fields = [
            (
                "timestamp",
                PRECISION_DATETIME,
            ),
            (
                "created_at",
                PRECISION_DATETIME,
            ),
            (
                "connected_at",
                PRECISION_DATETIME,
            ),
            (
                "last_seen",
                PRECISION_DATETIME,
            ),
        ]

    else:

        return {
            "available": False,
            "field": None,
            "value": None,
            "normalized": None,
            "precision": None,
        }

    # --------------------------------------------------------
    # Find first valid temporal field
    # --------------------------------------------------------

    for field_name, precision in fields:

        value = node_data.get(
            field_name
        )

        # ----------------------------------------------------
        # Skip Scheduled Task sentinel
        # ----------------------------------------------------

        if (
            entity_type == "scheduled_task"
            and field_name == "last_run_time"
            and _is_scheduled_task_unavailable_timestamp(
                value
            )
        ):
            continue

        normalized = normalize_timestamp(
            value,
            precision=precision,
        )

        if normalized["available"]:

            return {
                "available": True,
                "field": field_name,
                "value": value,
                "normalized": normalized[
                    "normalized"
                ],
                "precision": normalized[
                    "precision"
                ],
            }

    return {
        "available": False,
        "field": None,
        "value": None,
        "normalized": None,
        "precision": None,
    }


# ============================================================
# Node Temporal Context
# ============================================================

def analyze_node_temporal_context(
    graph: Any,
    node_id: Any,
    reference_time: Any,
) -> dict[str, Any]:
    """
    Analyze the temporal relationship of a graph node
    against a reference time.
    """

    node_event = _get_node_event_time(
        graph,
        node_id,
    )

    if not node_event["available"]:

        return {
            "node_id": node_id,
            "temporal_available": False,
            "event_field": None,
            "event_time": None,
            "reference_time": normalize_timestamp(
                reference_time
            ),
            "relation": TEMPORAL_NOT_AVAILABLE,
            "difference_seconds": None,
            "evidence_strength": EVIDENCE_NONE,
        }

    temporal_event = _build_temporal_event(
        event_time=node_event[
            "normalized"
        ],
        reference_time=reference_time,
        event_name=str(node_id),
        reference_name="reference",
    )

    return {
        "node_id": node_id,
        "temporal_available": True,
        "event_field": node_event[
            "field"
        ],
        "event_time": {
            "available": True,
            "original": node_event[
                "value"
            ],
            "normalized": node_event[
                "normalized"
            ],
            "precision": node_event[
                "precision"
            ],
        },
        "reference_time": temporal_event[
            "reference_time"
        ],
        "relation": temporal_event[
            "relation"
        ],
        "difference_seconds": temporal_event[
            "difference_seconds"
        ],
        "evidence_strength": temporal_event[
            "evidence_strength"
        ],
    }


# ============================================================
# Temporal Changes
# ============================================================

def analyze_temporal_changes(
    comparison_result: dict[str, Any],
    baseline_graph: Any,
    current_graph: Any,
    reference_time: Any | None = None,
) -> dict[str, Any]:
    """
    Analyze temporal evidence for graph changes.

    Added nodes are analyzed in the current graph.
    Changed nodes are analyzed in the current graph.
    Removed nodes are analyzed in the baseline graph.
    """

    changed_nodes = comparison_result.get(
        "changed_nodes",
        [],
    )

    added_nodes = comparison_result.get(
        "added_nodes",
        [],
    )

    removed_nodes = comparison_result.get(
        "removed_nodes",
        [],
    )

    if reference_time is None:

        reference_time = (
            datetime.now(
                timezone.utc
            ).isoformat()
        )

    records = []

    # --------------------------------------------------------
    # Added nodes
    # --------------------------------------------------------

    for node_id in added_nodes:

        analysis = analyze_node_temporal_context(
            current_graph,
            node_id,
            reference_time,
        )

        analysis["change_type"] = "ADDED"

        records.append(
            analysis
        )

    # --------------------------------------------------------
    # Changed nodes
    # --------------------------------------------------------

    for node_id in changed_nodes:

        analysis = analyze_node_temporal_context(
            current_graph,
            node_id,
            reference_time,
        )

        analysis["change_type"] = "CHANGED"

        records.append(
            analysis
        )

    # --------------------------------------------------------
    # Removed nodes
    # --------------------------------------------------------

    for node_id in removed_nodes:

        analysis = analyze_node_temporal_context(
            baseline_graph,
            node_id,
            reference_time,
        )

        analysis["change_type"] = "REMOVED"

        records.append(
            analysis
        )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    available = [
        record
        for record in records
        if record.get(
            "temporal_available"
        )
    ]

    unavailable = [
        record
        for record in records
        if not record.get(
            "temporal_available"
        )
    ]

    return {
        "records": records,
        "summary": {
            "total_changed_elements": len(
                records
            ),
            "temporal_available": len(
                available
            ),
            "temporal_unavailable": len(
                unavailable
            ),
        },
    }


# ============================================================
# Installation Event Correlation
# ============================================================

def correlate_installation_events(
    installation_time: Any,
    event_time: Any,
) -> dict[str, Any]:
    """
    Correlate an event with an installed application.

    Installation dates have DATE_ONLY precision, therefore
    same-day events do not establish exact ordering.
    """

    installation = normalize_timestamp(
        installation_time,
        precision=PRECISION_DATE_ONLY,
    )

    event = normalize_timestamp(
        event_time,
        precision=PRECISION_DATETIME,
    )

    if (
        not installation["available"]
        or not event["available"]
    ):

        return {
            "available": False,
            "relation": TEMPORAL_NOT_AVAILABLE,
            "difference_seconds": None,
            "evidence_strength": EVIDENCE_NONE,
            "interpretation": (
                "Installation or event time is unavailable."
            ),
        }

    installation_dt = datetime.fromisoformat(
        installation["normalized"]
    )

    event_dt = datetime.fromisoformat(
        event["normalized"]
    )

    installation_date = (
        installation_dt.date()
    )

    event_date = event_dt.date()

    # --------------------------------------------------------
    # Event before installation
    # --------------------------------------------------------

    if event_date < installation_date:

        return {
            "available": True,
            "relation": RELATION_BEFORE,
            "difference_seconds": (
                event_dt - installation_dt
            ).total_seconds(),
            "evidence_strength": (
                EVIDENCE_INFORMATIONAL
            ),
            "interpretation": (
                "The event occurred on a calendar "
                "day before the installation date."
            ),
        }

    # --------------------------------------------------------
    # Event after installation
    # --------------------------------------------------------

    if event_date > installation_date:

        return {
            "available": True,
            "relation": RELATION_AFTER,
            "difference_seconds": (
                event_dt - installation_dt
            ).total_seconds(),
            "evidence_strength": (
                EVIDENCE_INFORMATIONAL
            ),
            "interpretation": (
                "The event occurred on a calendar "
                "day after the installation date."
            ),
        }

    # --------------------------------------------------------
    # Same calendar day
    # --------------------------------------------------------

    return {
        "available": True,
        "relation": RELATION_SAME_TIME,
        "difference_seconds": None,
        "evidence_strength": (
            EVIDENCE_INFORMATIONAL
        ),
        "interpretation": (
            "The event and installation occurred "
            "on the same calendar day; exact ordering "
            "cannot be established because the "
            "installation date has DATE_ONLY precision."
        ),
    }


# ============================================================
# Public API
# ============================================================

__all__ = [
    "TEMPORAL_NOT_AVAILABLE",
    "RELATION_BEFORE",
    "RELATION_AFTER",
    "RELATION_SAME_TIME",
    "EVIDENCE_STRONG",
    "EVIDENCE_MODERATE",
    "EVIDENCE_INFORMATIONAL",
    "EVIDENCE_NONE",
    "PRECISION_DATETIME",
    "PRECISION_DATE_ONLY",
    "normalize_timestamp",
    "calculate_time_difference",
    "determine_temporal_relation",
    "get_snapshot_collection_time",
    "get_collector_collection_time",
    "extract_entity_temporal_fields",
    "extract_snapshot_temporal_evidence",
    "analyze_event_against_snapshot",
    "analyze_node_temporal_context",
    "analyze_temporal_changes",
    "correlate_installation_events",
]