"""Decision Evolution for the Digital DNA Security Framework.

Tracks SIS and decision-status changes across Stage 8 analyses.
"""

import hashlib
import json
import math
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_STAGE8_PATH = Path("data/results/stage_8_decision.json")
DEFAULT_HISTORY_PATH = Path("data/results/decision_evolution_history.json")
DEFAULT_REPORT_PATH = Path("data/results/decision_evolution_latest.json")

SIS_CHANGE_EPSILON = 0.01

STATUS_RANK = {
    "healthy": 4,
    "normal": 3,
    "warning": 2,
    "suspicious": 1,
    "critical": 0,
}


def _validate_score(value, field_name="sis"):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{field_name} must be numeric.")

    value = float(value)

    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise ValueError(f"{field_name} must be finite and between 0.0 and 1.0.")

    return value


def _read_json(path):
    path = Path(path)

    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        raise
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON file: {path}") from exc


def _atomic_write_json(path, data):
    """Write JSON atomically to avoid partially written history files."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temp_file:
            temp_path = Path(temp_file.name)
            json.dump(data, temp_file, indent=2, ensure_ascii=False)
            temp_file.write("\n")
            temp_file.flush()
            os.fsync(temp_file.fileno())

        os.replace(temp_path, path)

    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()


def _validate_stage8_result(stage8_data):
    if not isinstance(stage8_data, dict):
        raise TypeError("Stage 8 result must be a dictionary.")

    sis_result = stage8_data.get("sis_result")
    decision = stage8_data.get("decision")
    structural_result = stage8_data.get("structural_result")
    context_result = stage8_data.get("context_result")

    if not isinstance(sis_result, dict):
        raise ValueError("Stage 8 result must contain sis_result.")

    if not isinstance(decision, dict):
        raise ValueError("Stage 8 result must contain decision.")

    if not isinstance(structural_result, dict):
        raise ValueError("Stage 8 result must contain structural_result.")

    if not isinstance(context_result, dict):
        raise ValueError("Stage 8 result must contain context_result.")

    sis = _validate_score(sis_result.get("sis"), "sis_result.sis")

    decision_sis = _validate_score(decision.get("sis"), "decision.sis")

    if not math.isclose(sis, decision_sis, abs_tol=1e-9):
        raise ValueError("SIS values in sis_result and decision do not match.")

    status = decision.get("status")

    if status not in STATUS_RANK:
        raise ValueError(f"Unknown decision status: {status!r}")

    structural_similarity = _validate_score(
        structural_result.get("structural_similarity"),
        "structural_similarity",
    )

    context_consistency = _validate_score(
        context_result.get("context_consistency"),
        "context_consistency",
    )

    context_coverage = _validate_score(
        context_result.get("context_coverage"),
        "context_coverage",
    )

    return {
        "sis": sis,
        "status": status,
        "structural_similarity": structural_similarity,
        "context_consistency": context_consistency,
        "context_coverage": context_coverage,
    }


def _load_history(history_path):
    path = Path(history_path)

    if not path.exists():
        return {"schema_version": 1, "records": []}

    data = _read_json(path)

    if not isinstance(data, dict):
        raise ValueError("History file must contain a JSON object.")

    if data.get("schema_version") != 1:
        raise ValueError("Unsupported history schema_version.")

    records = data.get("records")

    if not isinstance(records, list):
        raise ValueError("History records must be a list.")

    for record in records:
        if not isinstance(record, dict):
            raise ValueError("Each history record must be a dictionary.")

        if "source_hash" not in record or "sis" not in record:
            raise ValueError("History record is missing required fields.")

        _validate_score(record["sis"], "history.sis")

        if record.get("status") not in STATUS_RANK:
            raise ValueError("History record contains an unknown status.")

    return data


def _calculate_trend(current, previous):
    delta = current - previous

    if delta > SIS_CHANGE_EPSILON:
        direction = "improving"
    elif delta < -SIS_CHANGE_EPSILON:
        direction = "degrading"
    else:
        direction = "stable"

    return {
        "direction": direction,
        "sis_delta": round(delta, 6),
        "previous_sis": previous,
        "current_sis": current,
    }


def _compare_status(current_status, previous_status):
    current_rank = STATUS_RANK[current_status]
    previous_rank = STATUS_RANK[previous_status]

    if current_rank > previous_rank:
        return "improved"

    if current_rank < previous_rank:
        return "degraded"

    return "unchanged"


def _component_changes(current, previous):
    changes = {}

    for field in (
        "structural_similarity",
        "context_consistency",
        "context_coverage",
    ):
        current_value = current[field]
        previous_value = previous[field]

        changes[field] = {
            "previous": previous_value,
            "current": current_value,
            "delta": round(current_value - previous_value, 6),
        }

    return changes


def analyze_evolution(stage8_data, history_data):
    """Analyze current Stage 8 data against previously recorded decisions."""
    current = _validate_stage8_result(stage8_data)

    if not isinstance(history_data, dict):
        raise TypeError("history_data must be a dictionary.")

    records = history_data.get("records")

    if not isinstance(records, list):
        raise ValueError("history_data.records must be a list.")

    if not records:
        return {
            "stage": "stage_9",
            "module": "decision_evolution",
            "evolution_status": "baseline",
            "trend": {
                "direction": "baseline",
                "sis_delta": None,
                "previous_sis": None,
                "current_sis": current["sis"],
            },
            "status_change": {
                "previous": None,
                "current": current["status"],
                "change": "baseline",
            },
            "component_changes": {},
            "history_count": 0,
            "interpretation": (
                "No previous decision is available. "
                "This result establishes the initial baseline."
            ),
        }

    previous_record = records[-1]

    previous = {
        "sis": _validate_score(previous_record["sis"], "history.sis"),
        "status": previous_record["status"],
        "structural_similarity": _validate_score(
            previous_record["structural_similarity"],
            "history.structural_similarity",
        ),
        "context_consistency": _validate_score(
            previous_record["context_consistency"],
            "history.context_consistency",
        ),
        "context_coverage": _validate_score(
            previous_record["context_coverage"],
            "history.context_coverage",
        ),
    }

    trend = _calculate_trend(current["sis"], previous["sis"])
    status_change = _compare_status(current["status"], previous["status"])

    if trend["direction"] == "improving":
        evolution_status = "improving"
        interpretation = "SIS increased compared with the previous decision."
    elif trend["direction"] == "degrading":
        evolution_status = "degrading"
        interpretation = "SIS decreased compared with the previous decision."
    else:
        evolution_status = "stable"
        interpretation = "SIS remained within the configured stability tolerance."

    return {
        "stage": "stage_9",
        "module": "decision_evolution",
        "evolution_status": evolution_status,
        "trend": trend,
        "status_change": {
            "previous": previous["status"],
            "current": current["status"],
            "change": status_change,
        },
        "component_changes": _component_changes(current, previous),
        "history_count": len(records),
        "interpretation": interpretation,
    }


def run_stage9(
    stage8_path=DEFAULT_STAGE8_PATH,
    history_path=DEFAULT_HISTORY_PATH,
    report_path=DEFAULT_REPORT_PATH,
):
    """Read Stage 8, analyze evolution, persist history, and write report."""
    stage8_path = Path(stage8_path)
    history_path = Path(history_path)
    report_path = Path(report_path)

    stage8_data = _read_json(stage8_path)
    current = _validate_stage8_result(stage8_data)
    history = _load_history(history_path)

    source_hash = hashlib.sha256(
        stage8_path.read_bytes()
    ).hexdigest()

    existing_record = next(
        (
            record
            for record in history["records"]
            if record["source_hash"] == source_hash
        ),
        None,
    )

    if existing_record is not None:
        report = dict(existing_record["evolution_report"])
        report["duplicate_input"] = True
        _atomic_write_json(report_path, report)
        return report

    report = analyze_evolution(stage8_data, history)

    record = {
        "source_hash": source_hash,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "sis": current["sis"],
        "status": current["status"],
        "structural_similarity": current["structural_similarity"],
        "context_consistency": current["context_consistency"],
        "context_coverage": current["context_coverage"],
        "evolution_report": report,
    }

    history["records"].append(record)

    report["duplicate_input"] = False

    _atomic_write_json(history_path, history)
    _atomic_write_json(report_path, report)
    return report
