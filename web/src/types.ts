export enum IoCType {
  IPV4 = "ipv4",
  DOMAIN = "domain",
  MD5 = "md5",
  SHA256 = "sha256",
}

export enum RiskLevel {
  NONE = "none",
  LOW = "low",
  MEDIUM = "medium",
  HIGH = "high",
  CRITICAL = "critical",
}

export interface IoC {
  type: IoCType;
  value: string;
  riskLevel: RiskLevel;
  sources: string[];
}

export interface ThreatIntelResult {
  ioc: { type: IoCType; value: string };
  source: string;
  maliciousCount: number;
  totalCount: number;
  confidenceScore: number;
  error: string | null;
}

export interface ApiKeys {
  vt: string;
  abuseipdb: string;
}

export type AnalysisStatus = "idle" | "extracting" | "querying" | "done";
