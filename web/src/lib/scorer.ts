/**
 * Risk Scoring Engine — TypeScript port of minos/scorer.py
 */

import { IoC, RiskLevel, ThreatIntelResult } from "../types";

// ---------------------------------------------------------------------------
// Per-source scoring thresholds
// ---------------------------------------------------------------------------

const VT_CRITICAL = 50.0;
const VT_HIGH = 25.0;
const VT_MEDIUM = 10.0;

const ABUSE_CRITICAL = 80;
const ABUSE_HIGH = 50;
const ABUSE_MEDIUM = 25;

// ---------------------------------------------------------------------------
// Per-result scoring
// ---------------------------------------------------------------------------

export function scoreFromResult(result: ThreatIntelResult): RiskLevel {
  if (result.error) return RiskLevel.NONE;

  const score = result.confidenceScore;

  if (result.source === "VirusTotal") {
    if (score > VT_CRITICAL) return RiskLevel.CRITICAL;
    if (score > VT_HIGH) return RiskLevel.HIGH;
    if (score > VT_MEDIUM) return RiskLevel.MEDIUM;
    if (score > 0) return RiskLevel.LOW;
    return RiskLevel.NONE;
  }

  if (result.source === "AbuseIPDB") {
    if (score > ABUSE_CRITICAL) return RiskLevel.CRITICAL;
    if (score > ABUSE_HIGH) return RiskLevel.HIGH;
    if (score > ABUSE_MEDIUM) return RiskLevel.LOW;
    return RiskLevel.NONE;
  }

  return RiskLevel.NONE;
}

// ---------------------------------------------------------------------------
// Aggregate multiple results for a single IoC
// ---------------------------------------------------------------------------

const SEVERITY_ORDER: Record<RiskLevel, number> = {
  [RiskLevel.NONE]: 0,
  [RiskLevel.LOW]: 1,
  [RiskLevel.MEDIUM]: 2,
  [RiskLevel.HIGH]: 3,
  [RiskLevel.CRITICAL]: 4,
};

export function scoreIoC(results: ThreatIntelResult[]): RiskLevel {
  if (results.length === 0) return RiskLevel.NONE;
  const levels = results.map(scoreFromResult);
  return levels.reduce((worst, cur) =>
    SEVERITY_ORDER[cur] > SEVERITY_ORDER[worst] ? cur : worst,
  );
}

// ---------------------------------------------------------------------------
// Overall risk
// ---------------------------------------------------------------------------

export function computeOverallRisk(iocs: IoC[]): RiskLevel {
  if (iocs.length === 0) return RiskLevel.NONE;

  const counts: Record<RiskLevel, number> = {
    [RiskLevel.NONE]: 0,
    [RiskLevel.LOW]: 0,
    [RiskLevel.MEDIUM]: 0,
    [RiskLevel.HIGH]: 0,
    [RiskLevel.CRITICAL]: 0,
  };
  for (const ioc of iocs) counts[ioc.riskLevel]++;

  if (counts[RiskLevel.CRITICAL] > 0) return RiskLevel.CRITICAL;
  if (counts[RiskLevel.HIGH] >= 2) return RiskLevel.CRITICAL;
  if (counts[RiskLevel.HIGH] >= 1) return RiskLevel.HIGH;
  if (counts[RiskLevel.MEDIUM] >= 3) return RiskLevel.HIGH;
  if (counts[RiskLevel.MEDIUM] >= 1) return RiskLevel.MEDIUM;
  if (counts[RiskLevel.LOW] >= 5) return RiskLevel.MEDIUM;
  if (counts[RiskLevel.LOW] >= 1) return RiskLevel.LOW;
  return RiskLevel.NONE;
}

// ---------------------------------------------------------------------------
// Full report scoring
// ---------------------------------------------------------------------------

export function scoreReport(
  iocs: IoC[],
  results: ThreatIntelResult[],
): { iocs: IoC[]; overallRisk: RiskLevel } {
  // Group results by IoC
  const resultsByIoC = new Map<string, ThreatIntelResult[]>();
  for (const r of results) {
    const key = `${r.ioc.type}:${r.ioc.value}`;
    const arr = resultsByIoC.get(key) ?? [];
    arr.push(r);
    resultsByIoC.set(key, arr);
  }

  // Populate IoC.sources from successful results
  const sourceMap = new Map<string, Set<string>>();
  for (const r of results) {
    if (!r.error) {
      const key = `${r.ioc.type}:${r.ioc.value}`;
      const set = sourceMap.get(key) ?? new Set();
      set.add(r.source);
      sourceMap.set(key, set);
    }
  }

  // Score each IoC
  const scored = iocs.map((ioc) => {
    const key = `${ioc.type}:${ioc.value}`;
    const iocResults = resultsByIoC.get(key) ?? [];
    const sources = Array.from(sourceMap.get(key) ?? []).sort();
    return { ...ioc, riskLevel: scoreIoC(iocResults), sources };
  });

  return { iocs: scored, overallRisk: computeOverallRisk(scored) };
}
