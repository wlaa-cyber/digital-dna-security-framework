"""
Scheduled Task Collector
------------------------
Collects Windows Scheduled Task information.

This module is part of the Data Collection Layer of the
Digital DNA Security Framework.
"""

import csv
import io
import subprocess
from datetime import datetime, timezone
from typing import Any


def _run_schtasks() -> str:
    """
    Execute the Windows schtasks command and return its output.

    A timeout is used to prevent the collector from waiting
    indefinitely if the command becomes unresponsive.
    """

    try:
        result = subprocess.run(
            [
                "schtasks",
                "/query",
                "/fo",
                "CSV",
                "/v",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=30,
        )

    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            "schtasks timed out after 30 seconds."
        ) from exc

    if result.returncode != 0:
        raise RuntimeError(
            f"schtasks failed with exit code "
            f"{result.returncode}: "
            f"{result.stderr.strip()}"
        )

    return result.stdout


def _normalize_task(
    row: dict[str, str],
) -> dict[str, Any]:
    """
    Normalize a raw schtasks record into a stable task structure.
    """

    return {
        "host_name": row.get("HostName"),
        "task_name": row.get("TaskName"),
        "next_run_time": row.get("Next Run Time"),
        "status": row.get("Status"),
        "logon_mode": row.get("Logon Mode"),
        "last_run_time": row.get("Last Run Time"),
        "last_result": row.get("Last Result"),
        "author": row.get("Author"),
        "task_to_run": row.get("Task To Run"),
        "start_in": row.get("Start In"),
        "comment": row.get("Comment"),
        "state": row.get("Scheduled Task State"),
        "run_as_user": row.get("Run As User"),
        "schedule_type": row.get("Schedule Type"),
        "start_time": row.get("Start Time"),
        "start_date": row.get("Start Date"),
        "end_date": row.get("End Date"),
        "days": row.get("Days"),
        "months": row.get("Months"),
        "repeat_every": row.get("Repeat: Every"),
        "repeat_until_time": row.get(
            "Repeat: Until: Time"
        ),
        "repeat_until_duration": row.get(
            "Repeat: Until: Duration"
        ),
        "repeat_stop_if_running": row.get(
            "Repeat: Stop If Still Running"
        ),
    }


def _collect_tasks() -> list[dict[str, Any]]:
    """
    Execute schtasks and collect valid scheduled task records.
    """

    output = _run_schtasks()

    tasks: list[dict[str, Any]] = []

    reader = csv.DictReader(
        io.StringIO(output)
    )

    for row in reader:
        task_name = row.get("TaskName")

        # schtasks may repeat its CSV header in the output.
        if not task_name or task_name == "TaskName":
            continue

        tasks.append(
            _normalize_task(row)
        )

    tasks.sort(
        key=lambda item: (
            item["task_name"] or ""
        ).lower()
    )

    return tasks


def collect_scheduled_tasks() -> dict[str, Any]:
    """
    Collect Windows Scheduled Tasks.

    Returns:
        A structured dictionary containing collection metadata,
        the number of tasks, and normalized task records.
    """

    collected_at = datetime.now(
        timezone.utc
    ).isoformat()

    tasks = _collect_tasks()

    return {
        "collector": "scheduled_task_collector",
        "entity_type": "scheduled_task",
        "collected_at": collected_at,
        "count": len(tasks),
        "items": tasks,
    }