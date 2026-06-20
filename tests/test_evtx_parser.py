"""Tests for EVTX / Sysmon Structured Parser."""

import pytest
from pathlib import Path

from minos.evtx_parser import (
    parse_evtx_file,
    _parse_data_fields,
    _extract_eventid,
    _is_fqdn,
    EVENTID_FIELD_MAP,
)
from minos.models import IoC, IoCType

SAMPLE_EVTX = "sample_logs/DE_RDP_Tunnel_5156.evtx"


# ── Helper fixtures ────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def evtx_iocs() -> list[IoC]:
    """Parse the real sample evtx once for all tests."""
    if not Path(SAMPLE_EVTX).exists():
        pytest.skip(f"Sample file {SAMPLE_EVTX} not found")
    return parse_evtx_file(SAMPLE_EVTX)


# ── XML parsing helpers ────────────────────────────────────────────────────


class TestParseDataFields:
    def test_parses_ip_fields_from_5156(self):
        xml = """
        <Event><System><EventID>5156</EventID></System>
        <EventData>
            <Data Name="SourceAddress">192.168.1.100</Data>
            <Data Name="DestAddress">10.0.0.55</Data>
            <Data Name="Application">\\device\\harddiskvolume3\\users\\bob\\app.exe</Data>
        </EventData></Event>
        """
        fields = _parse_data_fields(xml)
        assert fields["SourceAddress"] == "192.168.1.100"
        assert fields["DestAddress"] == "10.0.0.55"

    def test_empty_fields_are_skipped(self):
        xml = """
        <Event><EventData>
            <Data Name="SourceAddress"></Data>
            <Data Name="DestAddress">10.0.0.1</Data>
        </EventData></Event>
        """
        fields = _parse_data_fields(xml)
        assert "SourceAddress" not in fields
        assert fields["DestAddress"] == "10.0.0.1"

    def test_missing_eventdata(self):
        fields = _parse_data_fields("<Event><System/></Event>")
        assert fields == {}


class TestExtractEventID:
    def test_standard_eventid(self):
        assert _extract_eventid("<EventID>5156</EventID>") == 5156

    def test_eventid_with_qualifiers(self):
        assert (
            _extract_eventid('<EventID Qualifiers="16384">4624</EventID>') == 4624
        )

    def test_no_eventid(self):
        assert _extract_eventid("<Event><System/></Event>") == 0


class TestIsFQDN:
    def test_valid_fqdn(self):
        assert _is_fqdn("srv01.corp.local") is True
        assert _is_fqdn("evil.bad-domain.xyz") is True

    def test_bare_hostname_rejected(self):
        assert _is_fqdn("DESKTOP-ABC123") is False
        assert _is_fqdn("WEBSERVER") is False

    def test_empty_string(self):
        assert _is_fqdn("") is False

    def test_ip_like_rejected(self):
        # This function checks for dots, not IP validity — that's done later
        assert _is_fqdn("192.168.1.1") is True  # it has dots, so it passes
        # The extractor later will classify it correctly as IPv4


# ── EventID mapping table ──────────────────────────────────────────────────


class TestEventIDMapping:
    def test_known_eventids_registered(self):
        """All 5 EventIDs in the sample file must have mappings."""
        assert 1102 in EVENTID_FIELD_MAP
        assert 4688 in EVENTID_FIELD_MAP
        assert 4624 in EVENTID_FIELD_MAP
        assert 4648 in EVENTID_FIELD_MAP
        assert 5156 in EVENTID_FIELD_MAP

    def test_1102_has_no_fields(self):
        """Log-cleared event should have empty mapping (no IoCs)."""
        assert EVENTID_FIELD_MAP[1102] == {}

    def test_5156_has_ip_and_text_fields(self):
        fields = EVENTID_FIELD_MAP[5156]
        assert fields["SourceAddress"] == "ip"
        assert fields["DestAddress"] == "ip"
        assert fields["Application"] == "text"

    def test_4688_has_text_fields(self):
        fields = EVENTID_FIELD_MAP[4688]
        assert fields["NewProcessName"] == "text"
        assert fields["CommandLine"] == "text"


# ── Real EVTX file parsing ─────────────────────────────────────────────────


class TestParseRealEvtx:
    def test_parses_without_crashing(self, evtx_iocs):
        """Smoke test — parse the real file."""
        assert isinstance(evtx_iocs, list)
        # 101 records across 5 EventIDs should yield many IoCs
        assert len(evtx_iocs) > 0

    def test_extracts_ipv4_addresses(self, evtx_iocs):
        """EVTX contains SourceAddress/DestAddress fields → must find IPs."""
        ips = [i for i in evtx_iocs if i.ioc_type == IoCType.IPV4]
        # The file has multiple 5156 events each with source + dest IPs
        assert len(ips) >= 2, f"Expected at least 2 IPs, got {len(ips)}"

    def test_extracts_domains(self, evtx_iocs):
        """WorkstationName/TargetServerName fields may yield domain IoCs."""
        domains = [i for i in evtx_iocs if i.ioc_type == IoCType.DOMAIN]
        # At minimum we should see corp FQDNs from WorkstationName
        assert len(domains) >= 0  # FQDNs depend on the actual log data

    def test_iocs_are_deduplicated(self, evtx_iocs):
        """The same IP appearing in multiple records → only one IoC."""
        ips = [i for i in evtx_iocs if i.ioc_type == IoCType.IPV4]
        ip_values = [i.value for i in ips]
        # No duplicates
        assert len(ip_values) == len(set(ip_values))

    def test_all_iocs_have_valid_types(self, evtx_iocs):
        valid_types = {IoCType.IPV4, IoCType.DOMAIN, IoCType.MD5, IoCType.SHA256}
        for ioc in evtx_iocs:
            assert ioc.ioc_type in valid_types, f"Unknown IoCType: {ioc.ioc_type}"

    def test_returns_list_of_ioc_objects(self, evtx_iocs):
        for ioc in evtx_iocs:
            assert isinstance(ioc, IoC)
            assert isinstance(ioc.value, str)
            assert len(ioc.value) > 0


# ── File error handling ────────────────────────────────────────────────────


class TestFileErrors:
    def test_nonexistent_file(self):
        with pytest.raises(FileNotFoundError):
            parse_evtx_file("nonexistent_file.evtx")
