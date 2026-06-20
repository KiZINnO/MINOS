"""Tests for Threat Intelligence Integration — using aiohttp mocks."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from minos.models import IoC, IoCType, ThreatIntelResult
from minos.threat_intel import (
    _vt_lookup,
    _abuse_lookup_ip,
    query_virustotal,
    query_abuseipdb,
    query_all,
)


# ── Sample API response fixtures ──────────────────────────────────────────

VT_IP_RESPONSE = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 5,
                "suspicious": 2,
                "harmless": 80,
                "undetected": 3,
                "timeout": 0,
            }
        }
    }
}

VT_DOMAIN_RESPONSE = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 1,
                "suspicious": 0,
                "harmless": 40,
                "undetected": 5,
                "timeout": 0,
            }
        }
    }
}

VT_HASH_RESPONSE = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 20,
                "suspicious": 3,
                "harmless": 50,
                "undetected": 2,
                "timeout": 1,
            }
        }
    }
}

ABUSEIPDB_RESPONSE = {
    "data": {
        "abuseConfidenceScore": 85,
        "totalReports": 12,
    }
}


# ── Helpers ────────────────────────────────────────────────────────────────


def _make_mock_get(json_body, status=200):
    """Return an async mock for aiohttp.ClientSession.get."""
    mock_resp = MagicMock()
    mock_resp.status = status
    mock_resp.json = AsyncMock(return_value=json_body)
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=None)

    mock_session = MagicMock()
    mock_session.get.return_value = mock_resp
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    return mock_session


# ── VirusTotal tests ───────────────────────────────────────────────────────


class TestVirusTotalIP:
    @pytest.mark.asyncio
    async def test_lookup_ip(self):
        session = _make_mock_get(VT_IP_RESPONSE)
        ioc = IoC(ioc_type=IoCType.IPV4, value="8.8.8.8")
        result = await _vt_lookup(session, ioc, "test-key")
        assert result.source == "VirusTotal"
        assert result.ioc.ioc_type == IoCType.IPV4
        assert result.ioc.value == "8.8.8.8"
        assert result.malicious_count == 5
        assert result.total_count == 90  # 5+2+80+3+0
        assert result.confidence_score == pytest.approx(5.56, rel=0.1)

    @pytest.mark.asyncio
    async def test_lookup_ip_rate_limited(self):
        session = _make_mock_get({}, status=429)
        ioc = IoC(ioc_type=IoCType.IPV4, value="8.8.8.8")
        result = await _vt_lookup(session, ioc, "test-key")
        assert result.error == "Rate limited"


class TestVirusTotalDomain:
    @pytest.mark.asyncio
    async def test_lookup_domain(self):
        session = _make_mock_get(VT_DOMAIN_RESPONSE)
        ioc = IoC(ioc_type=IoCType.DOMAIN, value="evil.com")
        result = await _vt_lookup(session, ioc, "test-key")
        assert result.source == "VirusTotal"
        assert result.ioc.ioc_type == IoCType.DOMAIN
        assert result.ioc.value == "evil.com"


class TestVirusTotalHash:
    @pytest.mark.asyncio
    async def test_lookup_md5(self):
        session = _make_mock_get(VT_HASH_RESPONSE)
        ioc = IoC(ioc_type=IoCType.MD5, value="d41d8cd98f00b204e9800998ecf8427e")
        result = await _vt_lookup(session, ioc, "test-key")
        assert result.source == "VirusTotal"
        assert result.ioc.ioc_type == IoCType.MD5

    @pytest.mark.asyncio
    async def test_lookup_sha256(self):
        session = _make_mock_get(VT_HASH_RESPONSE)
        sha = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        ioc = IoC(ioc_type=IoCType.SHA256, value=sha)
        result = await _vt_lookup(session, ioc, "test-key")
        assert result.source == "VirusTotal"
        assert result.ioc.ioc_type == IoCType.SHA256


# ── AbuseIPDB tests ────────────────────────────────────────────────────────


class TestAbuseIPDB:
    @pytest.mark.asyncio
    async def test_lookup_ip(self):
        session = _make_mock_get(ABUSEIPDB_RESPONSE)
        result = await _abuse_lookup_ip(session, "45.33.32.156", "test-key")
        assert result.source == "AbuseIPDB"
        assert result.confidence_score == 85.0
        assert result.malicious_count == 12

    @pytest.mark.asyncio
    async def test_lookup_ip_rate_limited(self):
        session = _make_mock_get({}, status=429)
        result = await _abuse_lookup_ip(session, "45.33.32.156", "test-key")
        assert result.error == "Rate limited"


# ── Batch query tests ──────────────────────────────────────────────────────


class TestBatchQueries:
    @pytest.mark.asyncio
    async def test_query_virustotal_batch(self, monkeypatch):
        monkeypatch.setattr("minos.threat_intel._get_vt_key", lambda: "test-key")
        iocs = [
            IoC(ioc_type=IoCType.IPV4, value="8.8.8.8"),
            IoC(ioc_type=IoCType.DOMAIN, value="evil.com"),
            IoC(ioc_type=IoCType.MD5, value="d41d8cd98f00b204e9800998ecf8427e"),
        ]
        with patch("aiohttp.ClientSession") as mock_cls:
            mock_session = _make_mock_get(VT_IP_RESPONSE)
            mock_cls.return_value = mock_session
            results = await query_virustotal(iocs)
            assert len(results) == 3
            assert all(isinstance(r, ThreatIntelResult) for r in results)
            assert all(r.source == "VirusTotal" for r in results)

    @pytest.mark.asyncio
    async def test_query_virustotal_no_api_key(self, monkeypatch):
        monkeypatch.setattr("minos.threat_intel._get_vt_key", lambda: "")
        iocs = [IoC(ioc_type=IoCType.IPV4, value="8.8.8.8")]
        results = await query_virustotal(iocs)
        assert len(results) == 1
        assert "No API key" in (results[0].error or "")

    @pytest.mark.asyncio
    async def test_query_abuseipdb_no_api_key(self, monkeypatch):
        monkeypatch.setattr("minos.threat_intel._get_abuse_key", lambda: "")
        iocs = [IoC(ioc_type=IoCType.IPV4, value="8.8.8.8")]
        results = await query_abuseipdb(iocs)
        assert len(results) == 1
        assert "No API key" in (results[0].error or "")

    @pytest.mark.asyncio
    async def test_query_abuseipdb_batch(self, monkeypatch):
        monkeypatch.setattr("minos.threat_intel._get_abuse_key", lambda: "test-key")
        iocs = [
            IoC(ioc_type=IoCType.IPV4, value="8.8.8.8"),
            IoC(ioc_type=IoCType.IPV4, value="1.2.3.4"),
            IoC(ioc_type=IoCType.DOMAIN, value="evil.com"),  # should be skipped
        ]
        with patch("aiohttp.ClientSession") as mock_cls:
            mock_session = _make_mock_get(ABUSEIPDB_RESPONSE)
            mock_cls.return_value = mock_session
            results = await query_abuseipdb(iocs)
            assert len(results) == 2

    @pytest.mark.asyncio
    async def test_query_all(self):
        iocs = [IoC(ioc_type=IoCType.IPV4, value="8.8.8.8")]
        with patch("minos.threat_intel.query_virustotal") as mock_vt, \
             patch("minos.threat_intel.query_abuseipdb") as mock_abuse:
            mock_vt.return_value = [
                ThreatIntelResult(ioc=iocs[0], source="VirusTotal", confidence_score=50.0)
            ]
            mock_abuse.return_value = [
                ThreatIntelResult(ioc=iocs[0], source="AbuseIPDB", confidence_score=85.0)
            ]
            results = await query_all(iocs)
            assert len(results) == 2
            sources = {r.source for r in results}
            assert sources == {"VirusTotal", "AbuseIPDB"}

    @pytest.mark.asyncio
    async def test_query_all_populates_sources(self):
        """IoC.sources should be populated from successful results."""
        ioc = IoC(ioc_type=IoCType.IPV4, value="8.8.8.8")
        with patch("minos.threat_intel.query_virustotal") as mock_vt, \
             patch("minos.threat_intel.query_abuseipdb") as mock_abuse:
            mock_vt.return_value = [
                ThreatIntelResult(ioc=ioc, source="VirusTotal", confidence_score=50.0)
            ]
            mock_abuse.return_value = [
                ThreatIntelResult(ioc=ioc, source="AbuseIPDB", confidence_score=85.0)
            ]
            await query_all([ioc])
            assert "VirusTotal" in ioc.sources
            assert "AbuseIPDB" in ioc.sources
