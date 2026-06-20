"""Tests for the Output Formatter."""

import json
from minos.models import (
    IoC,
    IoCType,
    RiskLevel,
    ThreatIntelResult,
    TriageReport,
)
from minos.formatter import format_markdown, format_json


class TestMarkdownFormatter:
    def test_basic_report(self):
        ioc = IoC(ioc_type=IoCType.IPV4, value="45.33.32.156", risk_level=RiskLevel.CRITICAL)
        report = TriageReport(
            iocs=[ioc],
            results=[
                ThreatIntelResult(
                    ioc=ioc,
                    source="AbuseIPDB",
                    confidence_score=85.0,
                    malicious_count=12,
                )
            ],
            overall_risk=RiskLevel.CRITICAL,
            total_iocs=1,
            unique_iocs=1,
        )
        md = format_markdown(report)
        assert "# 🛡️ MINOS Triage Report" in md
        assert "CRITICAL" in md
        assert "45.33.32.156" in md
        assert "AbuseIPDB" in md
        assert "85.0%" in md

    def test_report_with_source_log(self):
        report = TriageReport(overall_risk=RiskLevel.NONE, total_iocs=0, unique_iocs=0)
        md = format_markdown(report, source_text="Sample log line here")
        assert "Sample log line here" in md
        assert "## Source Log" in md

    def test_empty_report(self):
        report = TriageReport(overall_risk=RiskLevel.NONE, total_iocs=0, unique_iocs=0)
        md = format_markdown(report)
        assert "NONE" in md
        assert "## Summary" in md


class TestJSONFormatter:
    def test_basic_json(self):
        ioc = IoC(ioc_type=IoCType.IPV4, value="45.33.32.156", risk_level=RiskLevel.CRITICAL)
        report = TriageReport(
            iocs=[ioc],
            results=[
                ThreatIntelResult(
                    ioc=ioc,
                    source="AbuseIPDB",
                    confidence_score=85.0,
                    malicious_count=12,
                )
            ],
            overall_risk=RiskLevel.CRITICAL,
            total_iocs=1,
            unique_iocs=1,
        )
        json_str = format_json(report)
        data = json.loads(json_str)

        assert data["report"]["overall_risk"] == "critical"
        assert len(data["iocs"]) == 1
        assert data["iocs"][0]["value"] == "45.33.32.156"
        assert data["iocs"][0]["type"] == "ipv4"
        assert len(data["threat_intel_results"]) == 1

    def test_compact_json(self):
        report = TriageReport(overall_risk=RiskLevel.NONE, total_iocs=0, unique_iocs=0)
        json_str = format_json(report, pretty=False)
        assert "\n" not in json_str  # compact = single line

    def test_json_roundtrip(self):
        """Generated JSON should be parseable and have all expected keys."""
        report = TriageReport(
            iocs=[
                IoC(ioc_type=IoCType.SHA256, value="a" * 64, risk_level=RiskLevel.HIGH),
                IoC(ioc_type=IoCType.DOMAIN, value="evil.com", risk_level=RiskLevel.MEDIUM),
            ],
            results=[],
            overall_risk=RiskLevel.HIGH,
            total_iocs=2,
            unique_iocs=2,
        )
        json_str = format_json(report)
        data = json.loads(json_str)

        assert "report" in data
        assert "iocs" in data
        assert "threat_intel_results" in data
        assert "generated_at" in data["report"]
