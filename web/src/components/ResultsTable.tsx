import { ThreatIntelResult } from "../types";

export default function ResultsTable({ results }: { results: ThreatIntelResult[] }) {
  if (results.length === 0) return null;

  return (
    <div style={{ marginBottom: "1.5rem" }}>
      <h2 style={{ fontSize: "1.1rem", marginBottom: "0.5rem" }}>
        Threat Intelligence Results ({results.length})
      </h2>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.85rem" }}>
        <thead>
          <tr style={{ textAlign: "left", borderBottom: "2px solid #ddd" }}>
            <th style={{ padding: "6px 8px" }}>IoC</th>
            <th style={{ padding: "6px 8px" }}>Source</th>
            <th style={{ padding: "6px 8px" }}>Confidence</th>
            <th style={{ padding: "6px 8px" }}>Verdict</th>
          </tr>
        </thead>
        <tbody>
          {results.map((r, i) => {
            const verdict =
              r.source === "VirusTotal"
                ? r.error
                  ? `⚠ ${r.error}`
                  : `${r.maliciousCount}/${r.totalCount} malicious`
                : r.error
                  ? `⚠ ${r.error}`
                  : `${r.maliciousCount} reports`;

            return (
              <tr key={`${r.ioc.value}:${r.source}:${i}`} style={{ borderBottom: "1px solid #eee" }}>
                <td style={{ padding: "6px 8px", fontFamily: "monospace", wordBreak: "break-all" }}>
                  {r.ioc.value}
                </td>
                <td style={{ padding: "6px 8px" }}>{r.source}</td>
                <td style={{ padding: "6px 8px" }}>
                  {r.error ? "—" : `${r.confidenceScore.toFixed(1)}%`}
                </td>
                <td style={{ padding: "6px 8px", color: r.error ? "#b45309" : undefined }}>
                  {verdict}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
