from pathlib import Path

from src.context.digital_signature import get_signature_evidence


WINDOWS_NOTEPAD = Path(r"C:\Windows\System32\notepad.exe")
WINDOWS_MPSIGSTUB = Path(r"C:\Windows\System32\MpSigStub.exe")

UNSIGNED_FILE = Path("tests/unsigned_test.txt")
TAMPERED_FILE = Path("tests/tampered_test.exe")
RENAMED_FILE = Path("tests/renamed_test.exe")
UNUSUAL_LOCATION_FILE = Path(
    "tests/unusual_location/suspicious_name.exe"
)


def test_windows_catalog_signature():
    """Windows system file with a Catalog signature."""

    result = get_signature_evidence(str(WINDOWS_NOTEPAD))

    assert result["exists"] is True
    assert result["signature_present"] is True
    assert result["signature_valid"] is True
    assert result["signature_status"] == "Valid"
    assert result["signature_type"] == "Catalog"
    assert result["is_os_binary"] is True
    assert result["publisher"] == "Microsoft Windows"


def test_embedded_authenticode_signature():
    """Windows executable with an embedded Authenticode signature."""

    result = get_signature_evidence(str(WINDOWS_MPSIGSTUB))

    assert result["exists"] is True
    assert result["signature_present"] is True
    assert result["signature_valid"] is True
    assert result["signature_status"] == "Valid"
    assert result["signature_type"] == "Authenticode"
    assert result["publisher"] == "Microsoft Corporation"


def test_unsigned_file():
    """Unsigned test file."""

    result = get_signature_evidence(str(UNSIGNED_FILE))

    assert result["exists"] is True
    assert result["signature_present"] is False
    assert result["signature_valid"] is False
    assert result["signature_type"] == "None"
    assert result["publisher"] is None


def test_missing_file():
    """Non-existent file."""

    missing_file = Path("tests/file_that_does_not_exist.exe")

    result = get_signature_evidence(str(missing_file))

    assert result["exists"] is False
    assert result["signature_present"] is False
    assert result["signature_valid"] is False
    assert result["signature_status"] == "FILE_NOT_FOUND"


def test_tampered_signed_file():
    """
    Signed file whose content was modified after signing.

    The signature remains present, but Windows detects a hash mismatch.
    """

    result = get_signature_evidence(str(TAMPERED_FILE))

    assert result["exists"] is True
    assert result["signature_present"] is True
    assert result["signature_valid"] is False
    assert result["signature_status"] == "HashMismatch"
    assert result["signature_type"] == "Authenticode"
    assert result["publisher"] == "Microsoft Corporation"


def test_renamed_signed_file():
    """
    Signed executable copied under a different filename.

    Renaming alone must not invalidate the signature.
    """

    result = get_signature_evidence(str(RENAMED_FILE))

    assert result["exists"] is True
    assert result["signature_present"] is True
    assert result["signature_valid"] is True
    assert result["signature_status"] == "Valid"
    assert result["signature_type"] == "Authenticode"
    assert result["publisher"] == "Microsoft Corporation"


def test_valid_signature_in_unusual_location():
    """
    A validly signed executable located outside its original location.

    Signature validation must remain independent from location analysis.
    """

    result = get_signature_evidence(str(UNUSUAL_LOCATION_FILE))

    assert result["exists"] is True
    assert result["signature_present"] is True
    assert result["signature_valid"] is True
    assert result["signature_status"] == "Valid"
    assert result["signature_type"] == "Authenticode"
    assert result["publisher"] == "Microsoft Corporation"


def test_valid_third_party_signature():
    """Valid Authenticode signature from a non-Microsoft publisher."""

    third_party_file = Path(
        r"C:\Program Files\Git\bin\git.exe"
    )

    result = get_signature_evidence(str(third_party_file))

    assert result["exists"] is True
    assert result["signature_present"] is True
    assert result["signature_valid"] is True
    assert result["signature_status"] == "Valid"
    assert result["signature_type"] == "Authenticode"
    assert result["publisher"] == "Johannes Schindelin"