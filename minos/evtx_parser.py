"""EVTX / Sysmon Structured Parser — parses Windows .evtx event logs.

Routes records by EventID through field-level extraction, reusing the
existing regex-based extractor for text-heavy fields (command lines,
process paths) and directly constructing IoC objects for IP fields.
"""

import logging
import re

from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view

from .extractor import extract_iocs, _is_valid_ipv4
from .models import IoC, IoCType

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# EventID → IoC-bearing field mapping
# ---------------------------------------------------------------------------
# Each entry is a dict of: field_name → extraction_mode
#   "ip"     → direct IPv4 IoC
#   "text"   → run regex extractor on the field value
#   "domain" → treat as domain name if FQDN-like (contains dot), else skip

EVENTID_FIELD_MAP: dict[int, dict[str, str]] = {
    # 4688 — Process Creation
    4688: {
        "NewProcessName": "text",
        "CommandLine": "text",
    },
    # 5156 — Windows Filtering Platform Connection
    5156: {
        "SourceAddress": "ip",
        "DestAddress": "ip",
        "Application": "text",
    },
    # 4624 — Successful Logon
    4624: {
        "IpAddress": "ip",
        "WorkstationName": "domain",
        "ProcessName": "text",
    },
    # 4648 — Explicit Credential Logon
    4648: {
        "IpAddress": "ip",
        "TargetServerName": "domain",
        "ProcessName": "text",
    },
    # 1102 — Security Log Cleared (no IoC data)
    # Explicitly empty — we log its presence for audit trail
    1102: {},
}


def _parse_data_fields(xml_fragment: str) -> dict[str, str]:
    """Extract all <Data Name="X">value</Data> pairs from an EVTX XML record.

    Uses regex rather than ElementTree because EVTX XML can contain
    malformed elements or encoding quirks that trip up strict parsers.

    Args:
        xml_fragment: Raw XML string of a single Event record.

    Returns:
        Dict mapping Data field Name → value.
    """
    fields: dict[str, str] = {}
    # Match <Data Name="FieldName">value</Data>
    pattern = re.compile(r'<Data\s+Name="([^"]+)"[^>]*>(.*?)</Data>', re.DOTALL)
    for match in pattern.finditer(xml_fragment):
        name = match.group(1)
        value = match.group(2).strip()
        if value:
            fields[name] = value
    return fields


def _extract_eventid(xml_fragment: str) -> int:
    """Pull the EventID qualifier from a record's XML."""
    # <EventID Qualifiers="...">5156</EventID>
    m = re.search(r"<EventID[^>]*>(\d+)</EventID>", xml_fragment)
    if m:
        return int(m.group(1))
    return 0


def _is_fqdn(value: str) -> bool:
    """Return True if the string looks like a fully qualified domain name."""
    value = value.strip().rstrip(".")
    if not value:
        return False
    # Must contain at least one dot, and each label must be valid
    labels = value.split(".")
    if len(labels) <= 1:
        return False  # bare hostname like DESKTOP-ABC123
    return all(1 <= len(label) <= 63 for label in labels)


def parse_evtx_file(filepath: str) -> list[IoC]:
    """Parse a Windows .evtx event log and extract IoCs.

    Uses structured EventID-to-field mapping rather than blind regex.
    For text-heavy fields (command lines, process paths), delegates to
    the regex-based extract_iocs().

    Args:
        filepath: Path to a .evtx file.

    Returns:
        Deduplicated list of IoC objects found across all records.
    """
    seen: set[tuple] = set()
    iocs: list[IoC] = []
    stats: dict[int, int] = {}  # EventID → record count for logging

    with Evtx(filepath) as evtx:
        for xml_record, _ in evtx_file_xml_view(evtx):
            eid = _extract_eventid(xml_record)
            stats[eid] = stats.get(eid, 0) + 1

            field_map = EVENTID_FIELD_MAP.get(eid)
            if field_map is None:
                logger.debug("EventID %s — no mapping, skipping", eid)
                continue

            if not field_map:
                # e.g. EventID 1102 — registered but no IoC fields
                logger.debug("EventID %s — known event, no IoC fields", eid)
                continue

            data = _parse_data_fields(xml_record)

            for field_name, mode in field_map.items():
                value = data.get(field_name)
                if not value:
                    continue

                if mode == "ip":
                    # Direct IPv4 — the field IS the IP address.
                    # Validate: reject placeholders, IPv6, and non-IP strings.
                    if ":" in value:
                        continue  # IPv6 — not yet supported
                    if not _is_valid_ipv4(value):
                        continue
                    ioc = IoC(ioc_type=IoCType.IPV4, value=value)
                    key = (IoCType.IPV4, value)
                    if key not in seen:
                        seen.add(key)
                        iocs.append(ioc)

                elif mode == "domain":
                    # Only capture FQDNs (e.g. SRV01.corp.local),
                    # skip bare hostnames (e.g. DESKTOP-ABC123)
                    if _is_fqdn(value):
                        ioc = IoC(ioc_type=IoCType.DOMAIN, value=value.lower())
                        key = (IoCType.DOMAIN, value.lower())
                        if key not in seen:
                            seen.add(key)
                            iocs.append(ioc)

                elif mode == "text":
                    # Run the regex extractor on this field's text value
                    # e.g. CommandLine or Application path
                    nested = extract_iocs(value, deduplicate=True)
                    for ioc in nested:
                        key = (ioc.ioc_type, ioc.value)
                        if key not in seen:
                            seen.add(key)
                            iocs.append(ioc)

    # ── Audit trail ──────────────────────────────────────────────────
    total_records = sum(stats.values())
    logger.info(
        "Parsed %d records from %s. Mapped EventIDs: %s",
        total_records,
        filepath,
        sorted(stats.items()),
    )
    logger.info("Extracted %d unique IoCs from EVTX structured fields.", len(iocs))

    return iocs
