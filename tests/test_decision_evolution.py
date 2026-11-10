import json
from pathlib import Path

import pytest

from src.decision.decision_evolution import analyze_evolution, run_stage9


def sample_stage8(sis=0.80, status="normal"):
    return {
        "stage": "stage_8",
        "structural_result": {"structural_similarity": 0.75},
        "context_result": {
            "context_consistency": 0.90,
            "context_coverage": 0.70,
        },
        "sis_result": {"sis": sis},
        "decision": {
            "sis": sis,
            "status": status,
            "sis_status": status,
        },
    }


def test_baseline_without_history():
    result = analyze_evolution(sample_stage8(), {"schema_version": 1, "records": []})
    assert result["evolution_status"] == "baseline"


def test_improving_trend():
    history = {
        "schema_version": 1,
        "records": [{"sis": 0.70, "status": "warning", "structural_similarity": 0.65, "context_consistency": 0.80, "context_coverage": 0.60}],
    }
    result = analyze_evolution(sample_stage8(0.85, "normal"), history)
    assert result["trend"]["direction"] == "improving"


def test_degrading_trend():
    history = {
        "schema_version": 1,
        "records": [{"sis": 0.90, "status": "healthy", "structural_similarity": 0.90, "context_consistency": 0.95, "context_coverage": 0.85}],
    }
    result = analyze_evolution(sample_stage8(0.65, "warning"), history)
    assert result["trend"]["direction"] == "degrading"


def test_stable_trend():
    history = {
        "schema_version": 1,
        "records": [{"sis": 0.80, "status": "normal", "structural_similarity": 0.75, "context_consistency": 0.90, "context_coverage": 0.70}],
    }
    result = analyze_evolution(sample_stage8(0.805, "normal"), history)
    assert result["trend"]["direction"] == "stable"


def test_run_stage9_writes_outputs(tmp_path):
    stage8_path = tmp_path / "stage_8_decision.json"
    history_path = tmp_path / "history.json"
    report_path = tmp_path / "report.json"

    stage8_path.write_text(json.dumps(sample_stage8()), encoding="utf-8")

    result = run_stage9(
        stage8_path=stage8_path,
        history_path=history_path,
        report_path=report_path,
    )

    assert result["evolution_status"] == "baseline"
    assert history_path.exists()
    assert report_path.exists()


def test_duplicate_input_is_idempotent(tmp_path):
    stage8_path = tmp_path / "stage_8_decision.json"
    history_path = tmp_path / "history.json"
    report_path = tmp_path / "report.json"

    stage8_path.write_text(json.dumps(sample_stage8()), encoding="utf-8")

    first = run_stage9(
        stage8_path=stage8_path,
        history_path=history_path,
        report_path=report_path,
    )
    second = run_stage9(
        stage8_path=stage8_path,
        history_path=history_path,
        report_path=report_path,
    )

    assert first["evolution_status"] == second["evolution_status"]
    assert second["duplicate_input"] is True

    history = json.loads(history_path.read_text(encoding="utf-8"))
    assert len(history["records"]) == 1


def test_invalid_sis_is_rejected():
    data = sample_stage8(1.5, "normal")
    with pytest.raises(ValueError):
        analyze_evolution(data, {"schema_version": 1, "records": []})
