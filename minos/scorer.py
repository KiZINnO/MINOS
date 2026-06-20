"""Risk Scoring Engine — assigns risk levels to IoCs and computes overall report score."""

import logging
from collections import Counter

from .models import IoC, RiskLevel, ThreatIntelResult, TriageReport

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Per-source scoring thresholds
# ---------------------------------------------------------------------------

# VirusTotal: confidence = malicious / total * 100
VT_CRITICAL = 50.0   # >50% of engines flag it → critical
VT_HIGH = 25.0       # >25% → high
VT_MEDIUM = 10.0     # >10% → medium

# AbuseIPDB: confidence score directly from API (0-100)
ABUSE_CRITICAL = 80  # >80 confidence → critical
ABUSE_HIGH = 50       # >50 → high
ABUSE_MEDIUM = 25     # >25 → medium


def score_ioc_from_result(result: ThreatIntelResult) -> RiskLevel:
    """Determine the risk level for a single ThreatIntelResult.

    Args:
        result: The result from querying a threat intel source.

    Returns:
        RiskLevel enum value.
    """
    if result.error:
        # If the lookup failed, we can't score — return NONE
        return RiskLevel.NONE

    score = result.confidence_score
    source = result.source

    if source == "VirusTotal":
        if score > VT_CRITICAL:
            return RiskLevel.CRITICAL
        elif score > VT_HIGH:
            return RiskLevel.HIGH
        elif score > VT_MEDIUM:
            return RiskLevel.MEDIUM
        elif score > 0:
            return RiskLevel.LOW
        return RiskLevel.NONE

    elif source == "AbuseIPDB":
        if score > ABUSE_CRITICAL:
            return RiskLevel.CRITICAL
        elif score > ABUSE_HIGH:
            return RiskLevel.HIGH
        elif score > ABUSE_MEDIUM:
            return RiskLevel.LOW
        return RiskLevel.NONE

    return RiskLevel.NONE


def score_ioc(results: list[ThreatIntelResult]) -> RiskLevel:
    """Aggregate multiple source results for a single IoC into one risk level.

    Takes the MAXIMUM risk level across all sources for an IoC.

    Args:
        results: All ThreatIntelResult objects for a single IoC.

    Returns:
        The worst (highest) RiskLevel across all sources.
    """
    if not results:
        return RiskLevel.NONE

    levels = [score_ioc_from_result(r) for r in results]
    # Risk levels are ordered by severity (NONE < LOW < MEDIUM < HIGH < CRITICAL)
    severity_order = {
        RiskLevel.NONE: 0,
        RiskLevel.LOW: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.HIGH: 3,
        RiskLevel.CRITICAL: 4,
    }
    return max(levels, key=lambda l: severity_order[l])


def compute_overall_risk(iocs: list[IoC]) -> RiskLevel:
    """Compute the overall risk level for a set of IoCs.

    Uses a weighted approach based on the count of IoCs at each level.

    Args:
        iocs: List of IoC objects with their risk_level fields set.

    Returns:
        Overall RiskLevel for the report.
    """
    if not iocs:
        return RiskLevel.NONE

    counts = Counter(ioc.risk_level for ioc in iocs)

    # If any IoC is CRITICAL, overall is CRITICAL
    if counts.get(RiskLevel.CRITICAL, 0) > 0:
        return RiskLevel.CRITICAL

    # If multiple HIGH or combination of HIGH + many MEDIUM, escalate
    if counts.get(RiskLevel.HIGH, 0) >= 2:
        return RiskLevel.CRITICAL
    if counts.get(RiskLevel.HIGH, 0) >= 1:
        return RiskLevel.HIGH

    # Medium count determines escalation
    if counts.get(RiskLevel.MEDIUM, 0) >= 3:
        return RiskLevel.HIGH
    if counts.get(RiskLevel.MEDIUM, 0) >= 1:
        return RiskLevel.MEDIUM

    if counts.get(RiskLevel.LOW, 0) >= 5:
        return RiskLevel.MEDIUM
    if counts.get(RiskLevel.LOW, 0) >= 1:
        return RiskLevel.LOW

    return RiskLevel.NONE


def score_report(report: TriageReport) -> TriageReport:
    """Score all IoCs in a report and compute the overall risk level.

    This mutates the IoC objects in-place by assigning risk_level,
    and sets report.overall_risk.

    Args:
        report: TriageReport with populated iocs and results.

    Returns:
        The same report, with risk levels assigned.
    """
    if not report.iocs or not report.results:
        report.overall_risk = RiskLevel.NONE
        return report

    # Group results by IoC
    results_by_ioc: dict[str, list[ThreatIntelResult]] = {}
    for r in report.results:
        key = f"{r.ioc.ioc_type.value}:{r.ioc.value}"
        results_by_ioc.setdefault(key, []).append(r)

    # Score each IoC
    for ioc in report.iocs:
        key = f"{ioc.ioc_type.value}:{ioc.value}"
        ioc_results = results_by_ioc.get(key, [])
        ioc.risk_level = score_ioc(ioc_results)

    report.overall_risk = compute_overall_risk(report.iocs)
    return report
