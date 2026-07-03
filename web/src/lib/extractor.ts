/**
 * IoC Extraction Engine — TypeScript port of minos/extractor.py
 */

import { IoC, IoCType } from "../types";

// ---------------------------------------------------------------------------
// Regex patterns (compiled once, reused)
// ---------------------------------------------------------------------------

const IPV4_OCTET = "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";
const IPV4_PATTERN = new RegExp(
  `\\b(?:${IPV4_OCTET}\\.){3}${IPV4_OCTET}\\b`,
  "g",
);

const DOMAIN_PATTERN = new RegExp(
  "\\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+" +
    "[a-zA-Z]{2,63}\\b",
  "g",
);

const EXECUTABLE_EXTENSIONS = new Set([
  "exe", "dll", "sys", "ps1", "bat", "cmd", "vbs", "vbe",
  "scr", "msi", "drv", "ocx", "cpl", "pif", "wsf", "wsh",
]);

const MD5_PATTERN = /\b(?<![A-Fa-f0-9])([a-fA-F0-9]{32})(?![A-Fa-f0-9])\b/g;
const SHA256_PATTERN = /\b([a-fA-F0-9]{64})\b/g;

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

function isValidIPv4(value: string): boolean {
  const parts = value.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    const n = Number(p);
    return !isNaN(n) && n >= 0 && n <= 255 && String(n) === p;
  });
}

function isValidDomain(value: string): boolean {
  if (value.length > 253) return false;
  if (isValidIPv4(value)) return false;
  const labels = value.replace(/\.$/, "").split(".");
  const tld = labels[labels.length - 1]?.toLowerCase() ?? "";
  if (EXECUTABLE_EXTENSIONS.has(tld)) return false;
  return labels.every((label) => label.length >= 1 && label.length <= 63);
}

// ---------------------------------------------------------------------------
// Main extraction function
// ---------------------------------------------------------------------------

export function extractIoCs(text: string, deduplicate = true): IoC[] {
  const iocs: IoC[] = [];

  // IPv4
  for (const match of text.matchAll(IPV4_PATTERN)) {
    const value = match[0];
    if (isValidIPv4(value)) {
      iocs.push({ type: IoCType.IPV4, value, riskLevel: "none" as never, sources: [] });
    }
  }

  // Domains
  for (const match of text.matchAll(DOMAIN_PATTERN)) {
    const value = match[0].replace(/\.$/, "").toLowerCase();
    if (isValidDomain(value)) {
      iocs.push({ type: IoCType.DOMAIN, value, riskLevel: "none" as never, sources: [] });
    }
  }

  // SHA256 (extract BEFORE MD5 to avoid substring matches)
  const sha256Values = new Set<string>();
  for (const match of text.matchAll(SHA256_PATTERN)) {
    sha256Values.add(match[1].toLowerCase());
  }
  for (const v of sha256Values) {
    iocs.push({ type: IoCType.SHA256, value: v, riskLevel: "none" as never, sources: [] });
  }

  // MD5 (exclude strings already captured as SHA256)
  const md5Values = new Set<string>();
  for (const match of text.matchAll(MD5_PATTERN)) {
    const v = match[1].toLowerCase();
    if (!sha256Values.has(v)) {
      md5Values.add(v);
    }
  }
  for (const v of md5Values) {
    iocs.push({ type: IoCType.MD5, value: v, riskLevel: "none" as never, sources: [] });
  }

  if (deduplicate) {
    return deduplicateIoCs(iocs);
  }
  return iocs;
}

function deduplicateIoCs(iocs: IoC[]): IoC[] {
  const seen = new Set<string>();
  return iocs.filter((ioc) => {
    const key = `${ioc.type}:${ioc.value}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
