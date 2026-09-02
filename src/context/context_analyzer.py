"""
Context Analyzer
----------------
Evidence-based contextual analysis for the
Digital DNA Security Framework.

This module currently implements Location Context only.

The Location Context classifies filesystem paths and produces
contextual evidence without making a security decision.
"""

from typing import Any


WINDOWS_SYSTEM_PREFIXES = (
    r"c:\windows",
)

PROGRAM_FILES_PREFIXES = (
    r"c:\program files",
    r"c:\program files (x86)",
)

PROGRAM_DATA_PREFIX = r"c:\programdata"

USER_PROFILE_PREFIX = r"c:\users"


def _normalize_path(path: Any) -> str | None:
    """
    Normalize a value only when it represents a Windows
    filesystem path.

    Non-filesystem values are treated as unavailable.

    Returns:
        A normalized lowercase Windows filesystem path,
        or None when the value is not a usable filesystem path.
    """

    if not isinstance(path, str):
        return None

    value = path.strip()

    if not value:
        return None

    if value.lower() in {
        "registry",
        "com handler",
        "n/a",
    }:
        return None

    if not (
        len(value) >= 3
        and value[0].isalpha()
        and value[1] == ":"
        and value[2] in ("\\", "/")
    ):
        return None

    try:
        return value.replace("/", "\\").lower()

    except (OSError, ValueError):
        return None


def _path_matches_prefix(
    normalized_path: str,
    prefix: str,
) -> bool:
    """
    Match a path against a directory prefix while respecting
    directory boundaries.
    """

    normalized_prefix = prefix.lower().rstrip("\\")

    return (
        normalized_path == normalized_prefix
        or normalized_path.startswith(
            normalized_prefix + "\\"
        )
    )


def _is_temporary_path(normalized_path: str) -> bool:
    """
    Determine whether a normalized filesystem path belongs
    to a known temporary-file location.

    Temporary locations are evaluated before broader location
    classes because their contextual meaning is more specific.
    """

    if _path_matches_prefix(
        normalized_path,
        r"c:\windows\temp",
    ):
        return True

    if (
        _path_matches_prefix(
            normalized_path,
            USER_PROFILE_PREFIX,
        )
        and (
            r"\appdata\local\temp" in normalized_path
            or r"\appdata\local\temporary internet files"
            in normalized_path
        )
    ):
        return True

    return False


def _is_user_profile_path(normalized_path: str) -> bool:
    """
    Determine whether a path belongs to a specific Windows
    user profile.

    Shared or default profile locations are excluded.
    """

    prefix = USER_PROFILE_PREFIX + "\\"

    if not normalized_path.startswith(prefix):
        return False

    remainder = normalized_path[len(prefix):]

    if not remainder:
        return False

    username = remainder.split("\\", 1)[0]

    if username.lower() in {
        "public",
        "default",
        "default user",
        "all users",
    }:
        return False

    return True


def classify_location(path: Any) -> str:
    """
    Classify a filesystem path into a contextual
    location class.

    This function does NOT determine whether a file
    is malicious.

    Returns:
        WINDOWS_SYSTEM
        PROGRAM_FILES
        PROGRAM_DATA
        USER_PROFILE
        TEMPORARY
        OTHER
        INVALID_OR_UNAVAILABLE
    """

    normalized = _normalize_path(path)

    if normalized is None:
        return "INVALID_OR_UNAVAILABLE"

    # Specific temporary locations are evaluated first.
    if _is_temporary_path(normalized):
        return "TEMPORARY"

    # Windows system locations.
    if any(
        _path_matches_prefix(
            normalized,
            prefix,
        )
        for prefix in WINDOWS_SYSTEM_PREFIXES
    ):
        return "WINDOWS_SYSTEM"

    # Standard application installation locations.
    if any(
        _path_matches_prefix(
            normalized,
            prefix,
        )
        for prefix in PROGRAM_FILES_PREFIXES
    ):
        return "PROGRAM_FILES"

    # Shared application/system data.
    if _path_matches_prefix(
        normalized,
        PROGRAM_DATA_PREFIX,
    ):
        return "PROGRAM_DATA"

    # Individual user profile locations.
    if _is_user_profile_path(normalized):
        return "USER_PROFILE"

    # A valid filesystem path outside the known standard
    # location classes.
    return "OTHER"


def analyze_location(
    path: Any,
    entity_type: str | None = None,
) -> dict[str, Any]:
    """
    Produce location evidence for one entity.

    The result is evidence only.

    No risk score and no security decision are produced.
    """

    normalized_path = _normalize_path(path)

    location_class = classify_location(
        path
    )

    evidence: dict[str, Any] = {
        "path": path,
        "normalized_path": normalized_path,
        "entity_type": entity_type,
        "location_class": location_class,
    }

    if location_class == "WINDOWS_SYSTEM":
        evidence["location_assessment"] = (
            "Expected system location"
        )
        evidence["evidence_strength"] = "Low"

    elif location_class == "PROGRAM_FILES":
        evidence["location_assessment"] = (
            "Expected application location"
        )
        evidence["evidence_strength"] = "Low"

    elif location_class == "PROGRAM_DATA":
        evidence["location_assessment"] = (
            "Application/system data location"
        )
        evidence["evidence_strength"] = "Low"

    elif location_class == "USER_PROFILE":
        evidence["location_assessment"] = (
            "Specific user profile location"
        )
        evidence["evidence_strength"] = "Informational"

    elif location_class == "TEMPORARY":
        evidence["location_assessment"] = (
            "Temporary-file location"
        )
        evidence["evidence_strength"] = "Medium"

    elif location_class == "OTHER":
        evidence["location_assessment"] = (
            "Filesystem location outside known "
            "standard classes"
        )
        evidence["evidence_strength"] = "Informational"

    else:
        evidence["location_assessment"] = (
            "Filesystem path unavailable "
            "or not applicable"
        )
        evidence["evidence_strength"] = "None"

    return evidence


def analyze_location_changes(
    comparison_result: dict[str, Any],
    baseline_graph: Any,
    current_graph: Any,
) -> dict[str, Any]:
    """
    Analyze location context for nodes affected by graph
    comparison.

    The function handles:
        - added nodes
        - changed nodes
        - removed nodes

    It produces contextual evidence only and does not make
    a security decision.
    """

    evidence: dict[str, Any] = {
        "added": [],
        "changed": [],
        "removed": [],
        "summary": {
            "added_count": 0,
            "changed_count": 0,
            "removed_count": 0,
        },
    }

    # ---------------------------------------------------------
    # Added nodes
    # ---------------------------------------------------------

    for node_id in comparison_result.get(
        "added_nodes",
        [],
    ):
        if node_id not in current_graph:
            continue

        attributes = current_graph.nodes[node_id]

        location_evidence = analyze_location(
            attributes.get("path"),
            attributes.get("entity_type"),
        )

        record = {
            "node_id": node_id,
            "change_type": "ADDED",
            "current": location_evidence,
        }

        evidence["added"].append(record)

    # ---------------------------------------------------------
    # Changed nodes
    # ---------------------------------------------------------

    for node_id, changed_properties in comparison_result.get(
        "changed_nodes",
        {},
    ).items():

        if node_id not in baseline_graph:
            continue

        if node_id not in current_graph:
            continue

        baseline_attributes = baseline_graph.nodes[node_id]
        current_attributes = current_graph.nodes[node_id]

        baseline_location = analyze_location(
            baseline_attributes.get("path"),
            baseline_attributes.get("entity_type"),
        )

        current_location = analyze_location(
            current_attributes.get("path"),
            current_attributes.get("entity_type"),
        )

        location_changed = (
            baseline_location["location_class"]
            != current_location["location_class"]
        )

        path_changed = "path" in changed_properties

        record = {
            "node_id": node_id,
            "change_type": "CHANGED",
            "path_changed": path_changed,
            "location_changed": location_changed,
            "baseline": baseline_location,
            "current": current_location,
        }

        evidence["changed"].append(record)

    # ---------------------------------------------------------
    # Removed nodes
    # ---------------------------------------------------------

    for node_id in comparison_result.get(
        "removed_nodes",
        [],
    ):
        if node_id not in baseline_graph:
            continue

        attributes = baseline_graph.nodes[node_id]

        location_evidence = analyze_location(
            attributes.get("path"),
            attributes.get("entity_type"),
        )

        record = {
            "node_id": node_id,
            "change_type": "REMOVED",
            "baseline": location_evidence,
        }

        evidence["removed"].append(record)

    # ---------------------------------------------------------
    # Summary
    # ---------------------------------------------------------

    evidence["summary"] = {
        "added_count": len(evidence["added"]),
        "changed_count": len(evidence["changed"]),
        "removed_count": len(evidence["removed"]),
    }

    return evidence