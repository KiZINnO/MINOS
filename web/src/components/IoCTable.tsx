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
    <div className="table-section">
      <h2 className="table-title">
        Indicators of Compromise ({iocs.length})
      </h2>
      <div className="table-responsive">
        <table>
          <thead>
            <tr>
              <th>Type</th>
              <th>Value</th>
              <th>Risk</th>
              <th className="sources-col">Sources</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((ioc, i) => (
              <tr key={`${ioc.type}:${ioc.value}:${i}`}>
                <td className="ioc-type">{TYPE_LABEL[ioc.type]}</td>
                <td className="ioc-value">{ioc.value}</td>
                <td><RiskBadge level={ioc.riskLevel} /></td>
                <td className="sources-col">
                  {ioc.sources.length > 0 ? ioc.sources.join(", ") : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
