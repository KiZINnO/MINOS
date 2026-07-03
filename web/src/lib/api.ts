/**
 * API Client — proxy calls to FastAPI backend for VT & AbuseIPDB.
 * Includes client-side throttling (5s between analyses).
 */

import axios, { AxiosError } from "axios";
import { IoC, IoCType, ThreatIntelResult } from "../types";

// ---------------------------------------------------------------------------
// Throttle
// ---------------------------------------------------------------------------

const THROTTLE_MS = 5000;
let lastAnalysisTime = 0;

function throttle(): Promise<void> {
  const elapsed = Date.now() - lastAnalysisTime;
  if (elapsed >= THROTTLE_MS) return Promise.resolve();
  return new Promise((r) => setTimeout(r, THROTTLE_MS - elapsed));
}

// ---------------------------------------------------------------------------
// VirusTotal
// ---------------------------------------------------------------------------

function vtPathFor(ioc: IoC): string {
  if (ioc.type === IoCType.IPV4) return `ip_addresses/${ioc.value}`;
  if (ioc.type === IoCType.DOMAIN) return `domains/${ioc.value}`;
  return `files/${ioc.value}`;
}

function parseVtStats(data: Record<string, unknown>): {
  malicious: number;
  total: number;
  score: number;
} {
  const attrs = (data["data"] as Record<string, unknown>)?.["attributes"] as Record<string, unknown> | undefined;
  const stats = (attrs?.["last_analysis_stats"] as Record<string, number>) ?? {};
  const malicious = stats["malicious"] ?? 0;
  const total = Object.values(stats).reduce((a, b) => a + b, 0);
  const score = total > 0 ? (malicious / total) * 100 : 0;
  return { malicious, total, score };
}

async function queryVT(
  iocs: IoC[],
  apiKey: string,
): Promise<ThreatIntelResult[]> {
  const vtIocs = iocs.filter((i) =>
    [IoCType.IPV4, IoCType.DOMAIN, IoCType.MD5, IoCType.SHA256].includes(i.type),
  );

  const tasks = vtIocs.map(async (ioc): Promise<ThreatIntelResult> => {
    try {
      const resp = await axios.post(
        "/api/virustotal",
        { path: vtPathFor(ioc) },
        { headers: { "X-VT-API-Key": apiKey } },
      );
      const { malicious, total, score } = parseVtStats(resp.data);
      return {
        ioc: { type: ioc.type, value: ioc.value },
        source: "VirusTotal",
        maliciousCount: malicious,
        totalCount: total,
        confidenceScore: score,
        error: null,
      };
    } catch (err) {
      const axiosErr = err as AxiosError<{ detail?: string }>;
      const msg =
        axiosErr.response?.status === 429
          ? "Rate limited"
          : axiosErr.response?.data?.detail ?? axiosErr.message ?? "Request failed";
      return {
        ioc: { type: ioc.type, value: ioc.value },
        source: "VirusTotal",
        maliciousCount: 0,
        totalCount: 0,
        confidenceScore: 0,
        error: msg,
      };
    }
  });

  return Promise.all(tasks);
}

// ---------------------------------------------------------------------------
// AbuseIPDB
// ---------------------------------------------------------------------------

async function queryAbuse(
  iocs: IoC[],
  apiKey: string,
): Promise<ThreatIntelResult[]> {
  const ipIocs = iocs.filter((i) => i.type === IoCType.IPV4);
  if (ipIocs.length === 0) return [];

  const tasks = ipIocs.map(async (ioc): Promise<ThreatIntelResult> => {
    try {
      const resp = await axios.post(
        "/api/abuseipdb",
        { ip: ioc.value },
        { headers: { "X-AbuseIPDB-Key": apiKey } },
      );
      const abuseData = resp.data?.data ?? {};
      return {
        ioc: { type: ioc.type, value: ioc.value },
        source: "AbuseIPDB",
        maliciousCount: abuseData.totalReports ?? 0,
        totalCount: 1,
        confidenceScore: abuseData.abuseConfidenceScore ?? 0,
        error: null,
      };
    } catch (err) {
      const axiosErr = err as AxiosError<{ detail?: string }>;
      const msg =
        axiosErr.response?.status === 429
          ? "Rate limited"
          : axiosErr.response?.data?.detail ?? axiosErr.message ?? "Request failed";
      return {
        ioc: { type: ioc.type, value: ioc.value },
        source: "AbuseIPDB",
        maliciousCount: 0,
        totalCount: 0,
        confidenceScore: 0,
        error: msg,
      };
    }
  });

  return Promise.all(tasks);
}

// ---------------------------------------------------------------------------
// Unified query
// ---------------------------------------------------------------------------

export async function queryAll(
  iocs: IoC[],
  vtKey: string,
  abuseKey: string,
): Promise<ThreatIntelResult[]> {
  await throttle();
  lastAnalysisTime = Date.now();

  const tasks: Promise<ThreatIntelResult[]>[] = [];
  if (vtKey) tasks.push(queryVT(iocs, vtKey));
  if (abuseKey) tasks.push(queryAbuse(iocs, abuseKey));
  if (tasks.length === 0) return [];

  const results = await Promise.all(tasks);
  return results.flat();
}
