"""IoC Extraction Engine — extracts IPs, domains, and file hashes from raw logs."""

import re

from .models import IoC, IoCType

# -- Compiled regex patterns --------------------------------------------------
# IPv4: stricter octet validation (0-255 per octet)
IPV4_OCTET = r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
IPV4_PATTERN = re.compile(
    rf"\b(?:{IPV4_OCTET}\.){{3}}{IPV4_OCTET}\b"
)

# Domain: label-dot-label with valid TLD
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}\b"
)

# Extensions that are NEVER valid TLDs — reject single-label FQDN matches
# that end with these (e.g. "svchost.exe" is a file, not a domain).
# NOTE: "com", "net", "org" are intentionally excluded — they are valid TLDs.
_EXECUTABLE_EXTENSIONS: set[str] = {
    "exe", "dll", "sys", "ps1", "bat", "cmd", "vbs", "vbe",
    "scr", "msi", "drv", "ocx", "cpl", "pif", "wsf", "wsh",
}

# MD5: 32 hex characters (must be word-bounded to avoid matching part of SHA256)
MD5_PATTERN = re.compile(r"\b(?<![A-Fa-f0-9])([a-fA-F0-9]{32})(?![A-Fa-f0-9])\b")

# SHA256: 64 hex characters
SHA256_PATTERN = re.compile(r"\b([a-fA-F0-9]{64})\b")


def _is_valid_ipv4(value: str) -> bool:
    """Check each octet is in range 0-255."""
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _is_valid_domain(value: str) -> bool:
    """Additional domain checks beyond regex: length limits, looks-like-IP filter,
    and executable extension denylist."""
    if len(value) > 253:
        return False
    # Reject raw IPv4 strings that the domain pattern might accidentally catch
    if _is_valid_ipv4(value):
        return False
    # Reject if the "TLD" (last label) is a known executable extension
    labels = value.rstrip(".").split(".")
    tld = labels[-1].lower() if labels else ""
    if tld in _EXECUTABLE_EXTENSIONS:
        return False
    # Each label max 63 chars
    return all(1 <= len(label) <= 63 for label in labels)


def extract_iocs(text: str, deduplicate: bool = True) -> list[IoC]:
    """Extract all Indicators of Compromise from raw text.

    Args:
        text: Raw log text to parse.
        deduplicate: If True (default), return only unique IoCs.

    Returns:
        List of IoC objects found in the text.
    """
    iocs: list[IoC] = []

    # ---- IPv4 addresses ----
    for match in IPV4_PATTERN.finditer(text):
        value = match.group(0)
        if _is_valid_ipv4(value):
            # Avoid classing common private/reserved ranges as noise —
            # we still extract them but they get scored later.
            iocs.append(IoC(ioc_type=IoCType.IPV4, value=value))

    # ---- Domains ----
    for match in DOMAIN_PATTERN.finditer(text):
        value = match.group(0).rstrip(".")
        if _is_valid_domain(value):
            iocs.append(IoC(ioc_type=IoCType.DOMAIN, value=value.lower()))

    # ---- SHA256 (extract BEFORE MD5 so we don't match the first 32 chars) ----
    sha256_values: set[str] = set()
    for match in SHA256_PATTERN.finditer(text):
        sha256_values.add(match.group(1))
    for v in sha256_values:
        iocs.append(IoC(ioc_type=IoCType.SHA256, value=v.lower()))

    # ---- MD5 (exclude strings already matched as SHA256) ----
    md5_values: set[str] = set()
    for match in MD5_PATTERN.finditer(text):
        md5_values.add(match.group(1))
    # Remove any MD5 that is also a SHA256
    md5_values -= sha256_values
    for v in md5_values:
        iocs.append(IoC(ioc_type=IoCType.MD5, value=v.lower()))

    if deduplicate:
        iocs = _deduplicate(iocs)

    return iocs


def _deduplicate(iocs: list[IoC]) -> list[IoC]:
    """Remove duplicate IoCs, preserving insertion order."""
    seen: set[tuple[IoCType, str]] = set()
    result: list[IoC] = []
    for ioc in iocs:
        key = (ioc.ioc_type, ioc.value)
        if key not in seen:
            seen.add(key)
            result.append(ioc)
    return result


def extract_iocs_from_file(filepath: str) -> list[IoC]:
    """Extract IoCs from a log file on disk.

    Args:
        filepath: Path to the log file.

    Returns:
        List of IoC objects found in the file content.
    """
    with open(filepath, "r", encoding="utf-8") as f:
        text = f.read()
    return extract_iocs(text)
