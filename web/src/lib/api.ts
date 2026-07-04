/**
 * API Client — proxy calls to FastAPI backend for VT & AbuseIPDB.
 * Staggers requests with per-service delays to stay within rate limits.
 */

import axios, { AxiosError } from "axios";
import { IoC, IoCType, ThreatIntelResult } from "../types";

// ---------------------------------------------------------------------------
// Throttle — prevent back-to-back analyses
// ---------------------------------------------------------------------------

const THROTTLE_MS = 5000;
let lastAnalysisTime = 0;

function throttle(): Promise<void> {
  const elapsed = Date.now() - lastAnalysisTime;
  if (elapsed >= THROTTLE_MS) return Promise.resolve();
  return new Promise((r) => setTimeout(r, THROTTLE_MS - elapsed));
}

// ---------------------------------------------------------------------------
// Sequential query helper — stagger requests with a delay between each
// ---------------------------------------------------------------------------

async function querySequentially<T>(
  items: T[],
  delayMs: number,
  fn: (item: T) => Promise<ThreatIntelResult>,
  onProgress?: (done: number, total: number) => void,
): Promise<ThreatIntelResult[]> {
  const results: ThreatIntelResult[] = [];
  for (let i = 0; i < items.length; i++) {
    if (i > 0) {
      await new Promise((r) => setTimeout(r, delayMs));
    }
    results.push(await fn(items[i]!));
    onProgress?.(i + 1, items.length);
  }
  return results;
}

// ---------------------------------------------------------------------------
// VirusTotal
// ---------------------------------------------------------------------------

// VT free tier: 4 requests/min → ~16s between requests to be safe
const VT_DELAY_MS = 16_000;

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
  onProgress?: (done: number, total: number) => void,
): Promise<ThreatIntelResult[]> {
  const vtIocs = iocs.filter((i) =>
    [IoCType.IPV4, IoCType.DOMAIN, IoCType.MD5, IoCType.SHA256].includes(i.type),
  );

  return querySequentially(vtIocs, VT_DELAY_MS, async (ioc) => {
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
  }, onProgress);
}

// ---------------------------------------------------------------------------
// AbuseIPDB
// ---------------------------------------------------------------------------

// AbuseIPDB free tier: ~1000/day, ~60/min → 2s between requests is safe
const ABUSE_DELAY_MS = 2_000;

async function queryAbuse(
  iocs: IoC[],
  apiKey: string,
  onProgress?: (done: number, total: number) => void,
): Promise<ThreatIntelResult[]> {
  const ipIocs = iocs.filter((i) => i.type === IoCType.IPV4);
  if (ipIocs.length === 0) return [];

  return querySequentially(ipIocs, ABUSE_DELAY_MS, async (ioc) => {
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
  }, onProgress);
}

// ---------------------------------------------------------------------------
// Unified query — run VT and AbuseIPDB in parallel (they're independent),
// but each service queries its IoCs sequentially with delays.
// ---------------------------------------------------------------------------

export interface QueryProgress {
  vtDone: number;
  vtTotal: number;
  abuseDone: number;
  abuseTotal: number;
}

export async function queryAll(
  iocs: IoC[],
  vtKey: string,
  abuseKey: string,
  onProgress?: (progress: QueryProgress) => void,
): Promise<ThreatIntelResult[]> {
  await throttle();
  lastAnalysisTime = Date.now();

  const vtIocs = vtKey
    ? iocs.filter((i) => [IoCType.IPV4, IoCType.DOMAIN, IoCType.MD5, IoCType.SHA256].includes(i.type))
    : [];
  const abuseIocs = abuseKey
    ? iocs.filter((i) => i.type === IoCType.IPV4)
    : [];

  const progress: QueryProgress = {
    vtDone: 0,
    vtTotal: vtIocs.length,
    abuseDone: 0,
    abuseTotal: abuseIocs.length,
  };

  const update = () => onProgress?.({ ...progress });

  const vtTask = vtKey
    ? queryVT(iocs, vtKey, (done, total) => {
        progress.vtDone = done;
        progress.vtTotal = total;
        update();
      })
    : Promise.resolve([]);

  const abuseTask = abuseKey
    ? queryAbuse(iocs, abuseKey, (done, total) => {
        progress.abuseDone = done;
        progress.abuseTotal = total;
        update();
      })
    : Promise.resolve([]);

  const [vtResults, abuseResults] = await Promise.all([vtTask, abuseTask]);
  return [...vtResults, ...abuseResults];
}
