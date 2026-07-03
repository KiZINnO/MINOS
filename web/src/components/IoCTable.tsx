import { IoC, IoCType } from "../types";
import RiskBadge from "./RiskBadge";

const TYPE_LABEL: Record<IoCType, string> = {
  [IoCType.IPV4]: "IPv4",
  [IoCType.DOMAIN]: "Domain",
  [IoCType.MD5]: "MD5",
  [IoCType.SHA256]: "SHA256",
};

const SEVERITY: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  none: 0,
};

export default function IoCTable({ iocs }: { iocs: IoC[] }) {
  if (iocs.length === 0) return null;

  const sorted = [...iocs].sort(
    (a, b) => (SEVERITY[b.riskLevel] ?? 0) - (SEVERITY[a.riskLevel] ?? 0),
  );

  return (
    <div style={{ marginBottom: "1.5rem" }}>
      <h2 style={{ fontSize: "1.1rem", marginBottom: "0.5rem" }}>
        Indicators of Compromise ({iocs.length})
      </h2>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.85rem" }}>
        <thead>
          <tr style={{ textAlign: "left", borderBottom: "2px solid #ddd" }}>
            <th style={{ padding: "6px 8px" }}>Type</th>
            <th style={{ padding: "6px 8px" }}>Value</th>
            <th style={{ padding: "6px 8px" }}>Risk</th>
            <th style={{ padding: "6px 8px" }}>Sources</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((ioc, i) => (
            <tr key={`${ioc.type}:${ioc.value}:${i}`} style={{ borderBottom: "1px solid #eee" }}>
              <td style={{ padding: "6px 8px", fontWeight: 600 }}>{TYPE_LABEL[ioc.type]}</td>
              <td style={{ padding: "6px 8px", fontFamily: "monospace", wordBreak: "break-all" }}>
                {ioc.value}
              </td>
              <td style={{ padding: "6px 8px" }}><RiskBadge level={ioc.riskLevel} /></td>
              <td style={{ padding: "6px 8px", color: "#666" }}>
                {ioc.sources.length > 0 ? ioc.sources.join(", ") : "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
