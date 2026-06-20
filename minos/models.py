"""Data models for MINOS — Auto-Triage SOC Bot."""

from dataclasses import dataclass, field
from enum import Enum


class IoCType(Enum):
    """Types of Indicators of Compromise."""

    IPV4 = "ipv4"
    DOMAIN = "domain"
    MD5 = "md5"
    SHA256 = "sha256"


class RiskLevel(Enum):
    """Risk severity levels."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class IoC:
    """A single Indicator of Compromise extracted from a log."""

    ioc_type: IoCType
    value: str
    risk_level: RiskLevel = RiskLevel.NONE
    sources: list[str] = field(default_factory=list)

    def __hash__(self) -> int:
        return hash((self.ioc_type, self.value))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, IoC):
            return NotImplemented
        return self.ioc_type == other.ioc_type and self.value == other.value


@dataclass
class ThreatIntelResult:
    """Result from querying a Threat Intel API for a single IoC."""

    ioc: IoC
    source: str
    malicious_count: int = 0
    total_count: int = 0
    confidence_score: float = 0.0
    raw_response: dict = field(default_factory=dict)
    error: str | None = None


@dataclass
class TriageReport:
    """The final triage report containing all analyzed IoCs."""

    iocs: list[IoC] = field(default_factory=list)
    results: list[ThreatIntelResult] = field(default_factory=list)
    overall_risk: RiskLevel = RiskLevel.NONE
    total_iocs: int = 0
    unique_iocs: int = 0
