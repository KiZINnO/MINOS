"""Threat Intelligence Integration — async API clients for VirusTotal & AbuseIPDB."""

import asyncio
import logging
import os

import aiohttp

from .models import IoC, IoCType, ThreatIntelResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# API configuration
# ---------------------------------------------------------------------------

VT_BASE = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"

DEFAULT_TIMEOUT = aiohttp.ClientTimeout(total=30)
DEFAULT_CONCURRENCY = 10


def _get_vt_key() -> str:
    """Return the VirusTotal API key at call time (not import time)."""
    return os.getenv("VIRUSTOTAL_API_KEY", "")


def _get_abuse_key() -> str:
    """Return the AbuseIPDB API key at call time (not import time)."""
    return os.getenv("ABUSEIPDB_API_KEY", "")


# ---------------------------------------------------------------------------
# VirusTotal — unified lookup
# ---------------------------------------------------------------------------


def _vt_endpoint_for(ioc: IoC) -> str:
    """Return the VirusTotal API path segment for an IoC."""
    if ioc.ioc_type == IoCType.IPV4:
        return f"ip_addresses/{ioc.value}"
    if ioc.ioc_type == IoCType.DOMAIN:
        return f"domains/{ioc.value}"
    # MD5 or SHA256
    return f"files/{ioc.value}"


def _parse_vt_stats(data: dict) -> tuple[int, int, float]:
    """Extract (malicious, total, score) from a VT response body."""
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values()) if stats else 0
    score = (malicious / total * 100) if total > 0 else 0.0
    return malicious, total, score


async def _vt_lookup(
    session: aiohttp.ClientSession,
    ioc: IoC,
    api_key: str,
) -> ThreatIntelResult:
    """Query VirusTotal for a single IoC (IP, domain, or hash)."""
    url = f"{VT_BASE}/{_vt_endpoint_for(ioc)}"
    headers = {"x-apikey": api_key, "Accept": "application/json"}

    try:
        async with session.get(url, headers=headers) as resp:
            if resp.status == 429:
                return ThreatIntelResult(ioc=ioc, source="VirusTotal", error="Rate limited")
            data = await resp.json()
            malicious, total, score = _parse_vt_stats(data)
            return ThreatIntelResult(
                ioc=ioc,
                source="VirusTotal",
                malicious_count=malicious,
                total_count=total,
                confidence_score=score,
                raw_response=data,
            )
    except asyncio.TimeoutError:
        return ThreatIntelResult(ioc=ioc, source="VirusTotal", error="Request timed out")
    except Exception as e:
        return ThreatIntelResult(ioc=ioc, source="VirusTotal", error=str(e))


async def query_virustotal(
    iocs: list[IoC],
    *,
    semaphore: asyncio.Semaphore | None = None,
) -> list[ThreatIntelResult]:
    """Query VirusTotal for a list of IoCs concurrently.

    Args:
        iocs: List of IoC objects to look up.
        semaphore: Optional concurrency limiter.

    Returns:
        List of ThreatIntelResult objects, one per IoC.
    """
    api_key = _get_vt_key()
    if not api_key:
        logger.warning("VIRUSTOTAL_API_KEY not set — skipping VirusTotal queries")
        return [
            ThreatIntelResult(ioc=ioc, source="VirusTotal", error="No API key")
            for ioc in iocs
        ]

    sem = semaphore or asyncio.Semaphore(DEFAULT_CONCURRENCY)

    async def _bounded_lookup(session: aiohttp.ClientSession, ioc: IoC) -> ThreatIntelResult:
        async with sem:
            return await _vt_lookup(session, ioc, api_key)

    async with aiohttp.ClientSession(timeout=DEFAULT_TIMEOUT) as session:
        tasks = [_bounded_lookup(session, ioc) for ioc in iocs]
        results = await asyncio.gather(*tasks, return_exceptions=False)
        return list(results)


# ---------------------------------------------------------------------------
# AbuseIPDB
# ---------------------------------------------------------------------------


async def _abuse_lookup_ip(
    session: aiohttp.ClientSession,
    ip: str,
    api_key: str,
) -> ThreatIntelResult:
    """Query AbuseIPDB for an IP address."""
    url = f"{ABUSEIPDB_BASE}/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    ioc = IoC(ioc_type=IoCType.IPV4, value=ip)

    try:
        async with session.get(url, headers=headers, params=params) as resp:
            if resp.status == 429:
                return ThreatIntelResult(ioc=ioc, source="AbuseIPDB", error="Rate limited")
            data = await resp.json()
            abuse_data = data.get("data", {})
            abuse_score = abuse_data.get("abuseConfidenceScore", 0)
            total_reports = abuse_data.get("totalReports", 0)
            return ThreatIntelResult(
                ioc=ioc,
                source="AbuseIPDB",
                malicious_count=total_reports,
                total_count=1,
                confidence_score=float(abuse_score),
                raw_response=data,
            )
    except asyncio.TimeoutError:
        return ThreatIntelResult(ioc=ioc, source="AbuseIPDB", error="Request timed out")
    except Exception as e:
        return ThreatIntelResult(ioc=ioc, source="AbuseIPDB", error=str(e))


async def query_abuseipdb(
    iocs: list[IoC],
    *,
    semaphore: asyncio.Semaphore | None = None,
) -> list[ThreatIntelResult]:
    """Query AbuseIPDB for a list of IP IoCs concurrently.

    Non-IP IoCs are skipped (AbuseIPDB only handles IPs).

    Args:
        iocs: List of IoC objects to look up.
        semaphore: Optional concurrency limiter.

    Returns:
        List of ThreatIntelResult objects (only for IP IoCs).
    """
    ip_iocs = [ioc for ioc in iocs if ioc.ioc_type == IoCType.IPV4]
    if not ip_iocs:
        return []

    api_key = _get_abuse_key()
    if not api_key:
        logger.warning("ABUSEIPDB_API_KEY not set — skipping AbuseIPDB queries")
        return [
            ThreatIntelResult(ioc=ioc, source="AbuseIPDB", error="No API key")
            for ioc in ip_iocs
        ]

    sem = semaphore or asyncio.Semaphore(DEFAULT_CONCURRENCY)

    async def _bounded_lookup(session: aiohttp.ClientSession, ip: str) -> ThreatIntelResult:
        async with sem:
            return await _abuse_lookup_ip(session, ip, api_key)

    async with aiohttp.ClientSession(timeout=DEFAULT_TIMEOUT) as session:
        tasks = [_bounded_lookup(session, ioc.value) for ioc in ip_iocs]
        results = await asyncio.gather(*tasks, return_exceptions=False)
        return list(results)


# ---------------------------------------------------------------------------
# Unified query entry point
# ---------------------------------------------------------------------------


async def query_all(iocs: list[IoC]) -> list[ThreatIntelResult]:
    """Query all configured Threat Intel sources for the given IoCs.

    Runs VirusTotal and AbuseIPDB queries concurrently.  After results
    are collected, populates each IoC's ``sources`` list with the names
    of the providers that returned data for it.

    Args:
        iocs: List of IoC objects to look up.

    Returns:
        Combined list of ThreatIntelResult objects from all sources.
    """
    sem = asyncio.Semaphore(DEFAULT_CONCURRENCY)
    vt_task = query_virustotal(iocs, semaphore=sem)
    abuse_task = query_abuseipdb(iocs, semaphore=sem)
    vt_results, abuse_results = await asyncio.gather(vt_task, abuse_task)

    all_results = vt_results + abuse_results

    # Populate IoC.sources from successful results
    source_map: dict[tuple[IoCType, str], set[str]] = {}
    for r in all_results:
        if not r.error:
            key = (r.ioc.ioc_type, r.ioc.value)
            source_map.setdefault(key, set()).add(r.source)

    for ioc in iocs:
        key = (ioc.ioc_type, ioc.value)
        ioc.sources = sorted(source_map.get(key, []))

    return all_results
