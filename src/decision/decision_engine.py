"""Decision Engine for the Digital DNA Security Framework."""


SIS_THRESHOLDS = {
    "healthy": 0.95,
    "normal": 0.80,
    "warning": 0.60,
    "suspicious": 0.40,
}


def _validate_score(sis):
    if not isinstance(sis, (int, float)):
        raise TypeError("sis must be numeric.")

    sis = float(sis)

    if not 0.0 <= sis <= 1.0:
        raise ValueError("sis must be between 0.0 and 1.0.")

    return sis


def classify_sis(sis):
    sis = _validate_score(sis)

    if sis >= SIS_THRESHOLDS["healthy"]:
        return "healthy"

    if sis >= SIS_THRESHOLDS["normal"]:
        return "normal"

    if sis >= SIS_THRESHOLDS["warning"]:
        return "warning"

    if sis >= SIS_THRESHOLDS["suspicious"]:
        return "suspicious"

    return "critical"


def _extract_context_summary(context_result):
    if context_result is None:
        return {}

    if not isinstance(context_result, dict):
        raise TypeError("context_result must be a dictionary.")

    summary = {}

    for dimension, result in context_result.items():
        if dimension == "context_engine":
            continue

        if not isinstance(result, dict):
            continue

        dimension_summary = result.get("summary")

        if isinstance(dimension_summary, dict):
            summary[dimension] = dict(dimension_summary)

    return summary


def _extract_context_evidence(context_result):
    if context_result is None:
        return []

    if not isinstance(context_result, dict):
        raise TypeError("context_result must be a dictionary.")

    evidence = []

    for dimension, result in context_result.items():
        if dimension == "context_engine":
            continue

        if not isinstance(result, dict):
            continue

        summary = result.get("summary")

        if isinstance(summary, dict):
            for indicator, value in summary.items():
                if isinstance(value, (int, float)) and value != 0:
                    evidence.append({
                        "dimension": dimension,
                        "indicator": indicator,
                        "value": value,
                    })

        for field in (
            "added",
            "changed",
            "removed",
            "added_connections",
            "removed_connections",
            "changed_connections",
            "added_relationships",
            "removed_relationships",
            "existing_relationships",
            "changed_parents",
            "records",
        ):
            value = result.get(field)

            if isinstance(value, list) and value:
                evidence.append({
                    "dimension": dimension,
                    "indicator": field,
                    "count": len(value),
                })

    return evidence


def make_decision(sis, context_result=None):
    sis = _validate_score(sis)

    sis_status = classify_sis(sis)

    context_summary = _extract_context_summary(
        context_result
    )

    context_evidence = _extract_context_evidence(
        context_result
    )

    reasons = [
        f"SIS classified the system as {sis_status}."
    ]

    if context_evidence:
        reasons.append(
            "Contextual evidence is available from the previous analysis stage."
        )

    return {
        "sis": sis,
        "status": sis_status,
        "sis_status": sis_status,
        "reasons": reasons,
        "context_summary": context_summary,
        "context_evidence": context_evidence,
        "decision_method": "threshold_rules",
    }