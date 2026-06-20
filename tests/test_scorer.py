"""Tests for the Risk Scoring Engine."""

import pytest
from minos.models import IoC, IoCType, RiskLevel, ThreatIntelResult
from minos.scorer import (
    score_ioc_from_result,
    score_ioc,
    compute_overall_risk,
    score_report,
)
from minos.models import TriageReport


class TestScoreIoCFromResult:
    def test_vt_critical(self):
        result = ThreatIntelResult(
            ioc=IoC(ioc_type=IoCType.IPV4, value="1.2.3.4"),
            source="VirusTotal",
            confidence_score=75.0,
        )
        assert score_ioc_from_result(result) == RiskLevel.CRITICAL

    def test_vt_high(self):
        result = ThreatIntelResult(
            ioc=IoC(ioc_type=IoCType.IPV4, value="1.2.3.4"),
            source="VirusTotal",
            confidence_score=30.0,
        )
        assert score_ioc_from_result(result) == RiskLevel.HIGH

    def test_vt_medium(self):
        result = ThreatIntelResult(
            ioc=IoC(ioc_type=IoCType.IPV4, value="1.2.3.4"),
            source="VirusTotal",
            confidence_score=15.0,
        )
        assert score_ioc_from_result(result) == RiskLevel.MEDIUM

    def test_vt_low(self):
        result = ThreatIntelResult(
            ioc=IoC(ioc_type=IoCType.IPV4, value="1.2.3.4"),
            source="VirusTotal",
            confidence_score=5.0,
        )
        assert score_ioc_from_result(result) == RiskLevel.LOW

    def test_vt_none(self):
        result = ThreatIntelResult(
            ioc=IoC(ioc_type=IoCType.IPV4, value="1.2.3.4"),
            source="VirusTotal",
            confidence_score=0.0,
        )
        assert score_ioc_from_result(result) == RiskLevel.NONE

    def test_abuseipdb_critical(self):
        result = ThreatIntelResult(
            ioc=IoC(ioc_type=IoCType.IPV4, value="1.2.3.4"),
            source="AbuseIPDB",
            confidence_score=95.0,
        )
        assert score_ioc_from_result(result) == RiskLevel.CRITICAL

    def test_abuseipdb_high(self):
        result = ThreatIntelResult(
            ioc=IoC(ioc_type=IoCType.IPV4, value="1.2.3.4"),
            source="AbuseIPDB",
            confidence_score=60.0,
        )
        assert score_ioc_from_result(result) == RiskLevel.HIGH

    def test_abuseipdb_low(self):
        result = ThreatIntelResult(
            ioc=IoC(ioc_type=IoCType.IPV4, value="1.2.3.4"),
            source="AbuseIPDB",
            confidence_score=30.0,
        )
        assert score_ioc_from_result(result) == RiskLevel.LOW

    def test_error_result_returns_none(self):
        result = ThreatIntelResult(
            ioc=IoC(ioc_type=IoCType.IPV4, value="1.2.3.4"),
            source="VirusTotal",
            error="Rate limited",
        )
        assert score_ioc_from_result(result) == RiskLevel.NONE


class TestScoreIoC:
    def test_aggregate_picks_max(self):
        """When multiple sources, take the WORST risk level."""
        results = [
            ThreatIntelResult(
                ioc=IoC(ioc_type=IoCType.IPV4, value="1.2.3.4"),
                source="VirusTotal",
                confidence_score=5.0,  # LOW
            ),
            ThreatIntelResult(
                ioc=IoC(ioc_type=IoCType.IPV4, value="1.2.3.4"),
                source="AbuseIPDB",
                confidence_score=95.0,  # CRITICAL
            ),
        ]
        assert score_ioc(results) == RiskLevel.CRITICAL

    def test_empty_results(self):
        assert score_ioc([]) == RiskLevel.NONE


class TestComputeOverallRisk:
    def test_critical_dominates(self):
        iocs = [
            IoC(ioc_type=IoCType.IPV4, value="1.1.1.1", risk_level=RiskLevel.CRITICAL),
            IoC(ioc_type=IoCType.DOMAIN, value="safe.com", risk_level=RiskLevel.NONE),
        ]
        assert compute_overall_risk(iocs) == RiskLevel.CRITICAL

    def test_two_high_escalates_to_critical(self):
        iocs = [
            IoC(ioc_type=IoCType.IPV4, value="1.1.1.1", risk_level=RiskLevel.HIGH),
            IoC(ioc_type=IoCType.IPV4, value="2.2.2.2", risk_level=RiskLevel.HIGH),
        ]
        assert compute_overall_risk(iocs) == RiskLevel.CRITICAL

    def test_single_high(self):
        iocs = [
            IoC(ioc_type=IoCType.IPV4, value="1.1.1.1", risk_level=RiskLevel.HIGH),
            IoC(ioc_type=IoCType.DOMAIN, value="safe.com", risk_level=RiskLevel.LOW),
        ]
        assert compute_overall_risk(iocs) == RiskLevel.HIGH

    def test_three_medium_escalates(self):
        iocs = [
            IoC(ioc_type=IoCType.IPV4, value="1.1.1.1", risk_level=RiskLevel.MEDIUM),
            IoC(ioc_type=IoCType.IPV4, value="2.2.2.2", risk_level=RiskLevel.MEDIUM),
            IoC(ioc_type=IoCType.IPV4, value="3.3.3.3", risk_level=RiskLevel.MEDIUM),
        ]
        assert compute_overall_risk(iocs) == RiskLevel.HIGH

    def test_single_medium(self):
        iocs = [
            IoC(ioc_type=IoCType.IPV4, value="1.1.1.1", risk_level=RiskLevel.MEDIUM),
        ]
        assert compute_overall_risk(iocs) == RiskLevel.MEDIUM

    def test_five_low_escalates(self):
        iocs = [
            IoC(ioc_type=IoCType.IPV4, value=f"1.1.1.{i}", risk_level=RiskLevel.LOW)
            for i in range(1, 6)
        ]
        assert compute_overall_risk(iocs) == RiskLevel.MEDIUM

    def test_all_none(self):
        iocs = [
            IoC(ioc_type=IoCType.IPV4, value="1.1.1.1", risk_level=RiskLevel.NONE),
            IoC(ioc_type=IoCType.DOMAIN, value="safe.com", risk_level=RiskLevel.NONE),
        ]
        assert compute_overall_risk(iocs) == RiskLevel.NONE

    def test_empty_list(self):
        assert compute_overall_risk([]) == RiskLevel.NONE


class TestScoreReport:
    def test_full_report_scoring(self):
        ioc_ip = IoC(ioc_type=IoCType.IPV4, value="45.33.32.156")
        ioc_domain = IoC(ioc_type=IoCType.DOMAIN, value="evil.com")

        report = TriageReport(
            iocs=[ioc_ip, ioc_domain],
            results=[
                ThreatIntelResult(
                    ioc=ioc_ip, source="AbuseIPDB", confidence_score=85.0, malicious_count=10
                ),
                ThreatIntelResult(
                    ioc=ioc_domain, source="VirusTotal", confidence_score=30.0, malicious_count=3, total_count=90
                ),
            ],
            total_iocs=2,
            unique_iocs=2,
        )

        scored = score_report(report)
        assert ioc_ip.risk_level == RiskLevel.CRITICAL  # 85 AbuseIPDB
        assert ioc_domain.risk_level == RiskLevel.HIGH    # 30 VT
        assert scored.overall_risk == RiskLevel.CRITICAL  # at least one CRITICAL
