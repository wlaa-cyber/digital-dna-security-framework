"""
Digital Signature Collector
---------------------------
Collects Authenticode digital signature information for
selected Windows executable files.

This module is part of the Data Collection Layer of the
Digital DNA Security Framework.
"""

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _signature_result(
    path: str,
    status: str,
    status_code: int | None = None,
    status_message: str | None = None,
    publisher: str | None = None,
    subject: str | None = None,
    issuer: str | None = None,
    serial_number: str | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    """
    Build a normalized digital signature record.
    """

    result = {
        "path": path,
        "status": status,
        "status_code": status_code,
        "status_message": status_message,
        "publisher": publisher,
        "subject": subject,
        "issuer": issuer,
        "serial_number": serial_number,
    }

    if error:
        result["error"] = error

    return result


def _get_signature_information(
    file_path: str,
) -> dict[str, Any]:
    """
    Verify the Authenticode signature of a single file.
    """

    path = Path(file_path)

    if not path.is_file():
        return _signature_result(
            path=str(path),
            status="FileNotFound",
        )

    escaped_path = str(path).replace(
        "'",
        "''",
    )

    command = [
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        (
            "$s = Get-AuthenticodeSignature "
            f"-LiteralPath '{escaped_path}'; "
            "$result = [PSCustomObject]@{"
            "Status=[int]$s.Status;"
            "StatusMessage=$s.StatusMessage;"
            "Subject=$s.SignerCertificate.Subject;"
            "Issuer=$s.SignerCertificate.Issuer;"
            "SerialNumber=$s.SignerCertificate.SerialNumber"
            "}; "
            "$result | ConvertTo-Json -Compress"
        ),
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=15,
        )

    except subprocess.TimeoutExpired:
        return _signature_result(
            path=str(path),
            status="Timeout",
            status_message=(
                "Signature verification timed out."
            ),
        )

    except OSError as error:
        return _signature_result(
            path=str(path),
            status="VerificationError",
            error=str(error),
        )

    if result.returncode != 0:
        return _signature_result(
            path=str(path),
            status="VerificationError",
            error=result.stderr.strip(),
        )

    try:
        information = json.loads(
            result.stdout
        )

    except json.JSONDecodeError:
        return _signature_result(
            path=str(path),
            status="VerificationError",
            error=result.stdout.strip(),
        )

    status_code = information.get("Status")

    if status_code == 0:
        status = "Valid"
    elif status_code is None:
        status = "Unknown"
    else:
        status = str(status_code)

    subject = information.get("Subject")

    return _signature_result(
        path=str(path),
        status=status,
        status_code=status_code,
        status_message=information.get(
            "StatusMessage"
        ),
        publisher=subject,
        subject=subject,
        issuer=information.get(
            "Issuer"
        ),
        serial_number=information.get(
            "SerialNumber"
        ),
    )


def _get_signature_information_batch(
    file_paths: list[str],
) -> list[dict[str, Any]]:
    """
    Verify multiple executable files using one PowerShell process.

    Batch verification reduces process creation overhead and
    prevents the collector from launching PowerShell once
    for every executable.
    """

    valid_paths: list[str] = []

    for file_path in sorted(
        set(file_paths)
    ):
        path = Path(file_path)

        if (
            path.is_file()
            and path.suffix.lower() == ".exe"
        ):
            valid_paths.append(
                str(path)
            )

    if not valid_paths:
        return []

    paths_json = json.dumps(
        valid_paths,
        ensure_ascii=False,
    )

    powershell_script = f"""
$paths = ConvertFrom-Json @'
{paths_json}
'@

$results = foreach ($path in $paths) {{
    try {{
        $s = Get-AuthenticodeSignature -LiteralPath $path

        [PSCustomObject]@{{
            Path = $path
            Status = [int]$s.Status
            StatusMessage = $s.StatusMessage
            Subject = $s.SignerCertificate.Subject
            Issuer = $s.SignerCertificate.Issuer
            SerialNumber = $s.SignerCertificate.SerialNumber
        }}
    }}
    catch {{
        [PSCustomObject]@{{
            Path = $path
            Status = $null
            StatusMessage = $_.Exception.Message
            Subject = $null
            Issuer = $null
            SerialNumber = $null
        }}
    }}
}}

$results | ConvertTo-Json -Compress
"""

    command = [
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        powershell_script,
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=60,
        )

    except subprocess.TimeoutExpired:
        return [
            _signature_result(
                path=path,
                status="Timeout",
                status_message=(
                    "Batch signature verification "
                    "timed out after 60 seconds."
                ),
            )
            for path in valid_paths
        ]

    except OSError as error:
        return [
            _signature_result(
                path=path,
                status="VerificationError",
                error=str(error),
            )
            for path in valid_paths
        ]

    if result.returncode != 0:
        return [
            _signature_result(
                path=path,
                status="VerificationError",
                error=result.stderr.strip(),
            )
            for path in valid_paths
        ]

    try:
        data = json.loads(
            result.stdout
        )

    except json.JSONDecodeError:
        return [
            _signature_result(
                path=path,
                status="VerificationError",
                error=result.stdout.strip(),
            )
            for path in valid_paths
        ]

    if isinstance(data, dict):
        data = [data]

    signatures: list[dict[str, Any]] = []

    for item in data:
        status_code = item.get(
            "Status"
        )

        if status_code == 0:
            status = "Valid"
        elif status_code is None:
            status = "Unknown"
        else:
            status = str(status_code)

        subject = item.get(
            "Subject"
        )

        signatures.append(
            _signature_result(
                path=item.get(
                    "Path"
                ),
                status=status,
                status_code=status_code,
                status_message=item.get(
                    "StatusMessage"
                ),
                publisher=subject,
                subject=subject,
                issuer=item.get(
                    "Issuer"
                ),
                serial_number=item.get(
                    "SerialNumber"
                ),
            )
        )

    signatures.sort(
        key=lambda item: (
            item["path"] or ""
        ).lower()
    )

    return signatures


def collect_digital_signatures(
    file_paths: list[str] | None = None,
) -> dict[str, Any]:
    """
    Collect Authenticode signature information.

    Args:
        file_paths:
            Executable files to verify.

    Returns:
        Structured digital signature information.
    """

    collected_at = datetime.now(
        timezone.utc
    ).isoformat()

    signatures = _get_signature_information_batch(
        file_paths or []
    )

    return {
        "collector": "digital_signature_collector",
        "entity_type": "digital_signature",
        "collected_at": collected_at,
        "count": len(signatures),
        "items": signatures,
    }