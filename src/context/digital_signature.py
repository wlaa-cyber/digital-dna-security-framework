from __future__ import annotations

import json
import subprocess
from pathlib import Path


def _extract_certificate_field(
    certificate: str | None,
    field: str,
) -> str | None:
    """
    Extract a field from a certificate Subject/Issuer string.

    Example:
        CN=Microsoft Windows, O=Microsoft Corporation, ...

    Returns:
        Microsoft Windows
    """

    if not certificate:
        return None

    prefix = f"{field}="

    for part in certificate.split(","):
        part = part.strip()

        if part.startswith(prefix):
            value = part[len(prefix):].strip()
            return value or None

    return None


def get_signature_evidence(file_path: str) -> dict:
    """
    Collect Windows Authenticode signature evidence for a file.

    This function collects evidence only.
    It does not decide whether the file is malicious or legitimate.
    """

    path = Path(file_path)

    if not path.is_file():
        return {
            "path": str(path),
            "exists": False,
            "signature_present": False,
            "signature_valid": False,
            "signature_status": "FILE_NOT_FOUND",
        }

    escaped_path = str(path).replace("'", "''")

    command = (
        "$s = Get-AuthenticodeSignature -LiteralPath "
        f"'{escaped_path}'; "
        "$cert = $s.SignerCertificate; "
        "$result = [PSCustomObject]@{"
        "Status = [string]$s.Status;"
        "SignatureType = [string]$s.SignatureType;"
        "IsOSBinary = [bool]$s.IsOSBinary;"
        "Subject = if ($cert) { [string]$cert.Subject } else { $null };"
        "Issuer = if ($cert) { [string]$cert.Issuer } else { $null };"
        "Thumbprint = if ($cert) { [string]$cert.Thumbprint } else { $null }"
        "}; "
        "$result | ConvertTo-Json -Compress"
    )

    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )

    except subprocess.TimeoutExpired:
        return {
            "path": str(path),
            "exists": True,
            "signature_present": False,
            "signature_valid": False,
            "signature_status": "VERIFICATION_TIMEOUT",
        }

    if result.returncode != 0:
        return {
            "path": str(path),
            "exists": True,
            "signature_present": False,
            "signature_valid": False,
            "signature_status": "VERIFICATION_ERROR",
            "error": result.stderr.strip(),
        }

    output = result.stdout.strip()

    if not output:
        return {
            "path": str(path),
            "exists": True,
            "signature_present": False,
            "signature_valid": False,
            "signature_status": "NO_RESULT",
        }

    try:
        data = json.loads(output)

    except json.JSONDecodeError:
        return {
            "path": str(path),
            "exists": True,
            "signature_present": False,
            "signature_valid": False,
            "signature_status": "INVALID_RESPONSE",
            "raw_output": output,
        }

    status = data.get("Status")
    signature_type = data.get("SignatureType")

    # "None" means that Windows found no signature.
    signature_present = signature_type not in (None, "", "None")

    # A signature is valid only when Windows reports "Valid".
    signature_valid = status == "Valid"

    subject = data.get("Subject")
    issuer = data.get("Issuer")

    publisher = _extract_certificate_field(
        subject,
        "CN",
    )

    return {
        "path": str(path),
        "exists": True,
        "signature_present": signature_present,
        "signature_valid": signature_valid,
        "signature_status": status,
        "signature_type": signature_type,
        "is_os_binary": data.get("IsOSBinary"),
        "publisher": publisher,
        "subject": subject,
        "issuer": issuer,
        "thumbprint": data.get("Thumbprint"),
    }