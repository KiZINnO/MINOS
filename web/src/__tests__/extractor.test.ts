import { describe, it, expect } from "vitest";
import { extractIoCs } from "../lib/extractor";
import { IoCType } from "../types";

describe("IPv4 extraction", () => {
  it("extracts a single IPv4", () => {
    const iocs = extractIoCs("Connection from 192.168.1.1 established.");
    expect(iocs).toHaveLength(1);
    expect(iocs[0]?.type).toBe(IoCType.IPV4);
    expect(iocs[0]?.value).toBe("192.168.1.1");
  });

  it("extracts multiple IPv4 addresses", () => {
    const iocs = extractIoCs("Src: 10.0.0.1, Dst: 172.16.5.254");
    const ips = iocs.filter((i) => i.type === IoCType.IPV4);
    expect(ips).toHaveLength(2);
    expect(ips.map((i) => i.value)).toEqual(expect.arrayContaining(["10.0.0.1", "172.16.5.254"]));
  });

  it("rejects invalid octets", () => {
    const iocs = extractIoCs("Bad IP: 999.999.999.999");
    const ips = iocs.filter((i) => i.type === IoCType.IPV4);
    expect(ips).toHaveLength(0);
  });

  it("deduplicates IPv4", () => {
    const iocs = extractIoCs("1.1.1.1 and 1.1.1.1 again");
    const ips = iocs.filter((i) => i.value === "1.1.1.1");
    expect(ips).toHaveLength(1);
  });
});

describe("Domain extraction", () => {
  it("extracts a simple domain", () => {
    const iocs = extractIoCs("Visit example.com for details.");
    const domains = iocs.filter((i) => i.type === IoCType.DOMAIN);
    expect(domains.some((i) => i.value === "example.com")).toBe(true);
  });

  it("extracts subdomains", () => {
    const iocs = extractIoCs("C2 at api.malicious.evil.com detected.");
    const domains = iocs.filter((i) => i.type === IoCType.DOMAIN);
    expect(domains.some((i) => i.value === "api.malicious.evil.com")).toBe(true);
  });

  it("lowercases domains", () => {
    const iocs = extractIoCs("BadServer.Example.COM is suspect.");
    const domains = iocs.filter((i) => i.type === IoCType.DOMAIN);
    expect(domains.every((i) => i.value === i.value.toLowerCase())).toBe(true);
  });

  it("does not extract IPs as domains", () => {
    const iocs = extractIoCs("Addr: 192.168.1.1");
    const domains = iocs.filter((i) => i.type === IoCType.DOMAIN);
    expect(domains).toHaveLength(0);
  });

  it("rejects executable extensions", () => {
    const iocs = extractIoCs("Process: svchost.exe, driver: kernel32.dll");
    const domains = iocs.filter((i) => i.type === IoCType.DOMAIN);
    expect(domains.every((i) => !i.value.includes("svchost.exe"))).toBe(true);
    expect(domains.every((i) => !i.value.includes("kernel32.dll"))).toBe(true);
  });

  it("accepts valid .com/.net domains", () => {
    const iocs = extractIoCs("C2 at evil.com and bad.net");
    const domains = iocs.filter((i) => i.type === IoCType.DOMAIN);
    const values = domains.map((i) => i.value);
    expect(values).toContain("evil.com");
    expect(values).toContain("bad.net");
  });
});

describe("Hash extraction", () => {
  it("extracts MD5", () => {
    const iocs = extractIoCs("File hash: d41d8cd98f00b204e9800998ecf8427e");
    const md5s = iocs.filter((i) => i.type === IoCType.MD5);
    expect(md5s).toHaveLength(1);
    expect(md5s[0]?.value).toBe("d41d8cd98f00b204e9800998ecf8427e");
  });

  it("extracts SHA256", () => {
    const sha = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
    const iocs = extractIoCs(`SHA256=${sha}`);
    const sha256s = iocs.filter((i) => i.type === IoCType.SHA256);
    expect(sha256s).toHaveLength(1);
  });

  it("does not extract SHA256 prefix as MD5", () => {
    const sha = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
    const iocs = extractIoCs(`hash: ${sha}`);
    const md5s = iocs.filter((i) => i.type === IoCType.MD5 && i.value === sha.slice(0, 32));
    expect(md5s).toHaveLength(0);
  });
});

describe("Empty input", () => {
  it("returns empty for empty string", () => {
    expect(extractIoCs("")).toEqual([]);
  });

  it("returns empty for plain text", () => {
    expect(extractIoCs("Plain text with no indicators at all.")).toEqual([]);
  });
});
