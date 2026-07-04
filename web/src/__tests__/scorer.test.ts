import { describe, it, expect } from "vitest";
import { scoreFromResult, scoreIoC, computeOverallRisk } from "../lib/scorer";
import { IoC, IoCType, RiskLevel, ThreatIntelResult } from "../types";

function makeResult(overrides: Partial<ThreatIntelResult>): ThreatIntelResult {
  return {
    ioc: { type: IoCType.IPV4, value: "1.2.3.4" },
    source: "VirusTotal",
    maliciousCount: 0,
    totalCount: 0,
    confidenceScore: 0,
    error: null,
    ...overrides,
  };
}

function makeIoC(overrides: Partial<IoC> = {}): IoC {
  return {
    type: IoCType.IPV4,
    value: "1.2.3.4",
    riskLevel: RiskLevel.NONE,
    sources: [],
    ...overrides,
  };
}

describe("scoreFromResult — VirusTotal", () => {
  it("CRITICAL when > 50%", () =>
    expect(scoreFromResult(makeResult({ confidenceScore: 75 }))).toBe(RiskLevel.CRITICAL));
  it("HIGH when > 25%", () =>
    expect(scoreFromResult(makeResult({ confidenceScore: 30 }))).toBe(RiskLevel.HIGH));
  it("MEDIUM when > 10%", () =>
    expect(scoreFromResult(makeResult({ confidenceScore: 15 }))).toBe(RiskLevel.MEDIUM));
  it("LOW when > 0%", () =>
    expect(scoreFromResult(makeResult({ confidenceScore: 5 }))).toBe(RiskLevel.LOW));
  it("NONE when 0%", () =>
    expect(scoreFromResult(makeResult({ confidenceScore: 0 }))).toBe(RiskLevel.NONE));
});

describe("scoreFromResult — AbuseIPDB", () => {
  it("CRITICAL when > 80", () =>
    expect(scoreFromResult(makeResult({ source: "AbuseIPDB", confidenceScore: 95 }))).toBe(RiskLevel.CRITICAL));
  it("HIGH when > 50", () =>
    expect(scoreFromResult(makeResult({ source: "AbuseIPDB", confidenceScore: 60 }))).toBe(RiskLevel.HIGH));
  it("LOW when > 25", () =>
    expect(scoreFromResult(makeResult({ source: "AbuseIPDB", confidenceScore: 30 }))).toBe(RiskLevel.LOW));
  it("NONE when error", () =>
    expect(scoreFromResult(makeResult({ error: "Rate limited" }))).toBe(RiskLevel.NONE));
});

describe("scoreIoC", () => {
  it("picks max across sources", () => {
    const results = [
      makeResult({ source: "VirusTotal", confidenceScore: 5 }),
      makeResult({ source: "AbuseIPDB", confidenceScore: 95 }),
    ];
    expect(scoreIoC(results)).toBe(RiskLevel.CRITICAL);
  });

  it("returns NONE for empty results", () => {
    expect(scoreIoC([])).toBe(RiskLevel.NONE);
  });
});

describe("computeOverallRisk", () => {
  it("CRITICAL dominates", () => {
    const iocs = [
      makeIoC({ riskLevel: RiskLevel.CRITICAL }),
      makeIoC({ value: "2.2.2.2", riskLevel: RiskLevel.NONE }),
    ];
    expect(computeOverallRisk(iocs)).toBe(RiskLevel.CRITICAL);
  });

  it("2x HIGH → CRITICAL", () => {
    const iocs = [
      makeIoC({ riskLevel: RiskLevel.HIGH }),
      makeIoC({ value: "2.2.2.2", riskLevel: RiskLevel.HIGH }),
    ];
    expect(computeOverallRisk(iocs)).toBe(RiskLevel.CRITICAL);
  });

  it("1x HIGH → HIGH", () => {
    const iocs = [
      makeIoC({ riskLevel: RiskLevel.HIGH }),
      makeIoC({ value: "2.2.2.2", riskLevel: RiskLevel.LOW }),
    ];
    expect(computeOverallRisk(iocs)).toBe(RiskLevel.HIGH);
  });

  it("3x MEDIUM → HIGH", () => {
    const iocs = [
      makeIoC({ riskLevel: RiskLevel.MEDIUM }),
      makeIoC({ value: "2.2.2.2", riskLevel: RiskLevel.MEDIUM }),
      makeIoC({ value: "3.3.3.3", riskLevel: RiskLevel.MEDIUM }),
    ];
    expect(computeOverallRisk(iocs)).toBe(RiskLevel.HIGH);
  });

  it("5x LOW → MEDIUM", () => {
    const iocs = Array.from({ length: 5 }, (_, i) =>
      makeIoC({ value: `1.1.1.${i + 1}`, riskLevel: RiskLevel.LOW }),
    );
    expect(computeOverallRisk(iocs)).toBe(RiskLevel.MEDIUM);
  });

  it("empty → NONE", () => {
    expect(computeOverallRisk([])).toBe(RiskLevel.NONE);
  });
});
