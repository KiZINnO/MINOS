import { ThreatIntelResult } from "../types";

export default function ResultsTable({ results }: { results: ThreatIntelResult[] }) {
  if (results.length === 0) return null;

  return (
    <div className="table-section">
      <h2 className="table-title">
        Threat Intelligence Results ({results.length})
      </h2>
      <div className="table-responsive">
        <table>
          <thead>
            <tr>
              <th>IoC</th>
              <th>Source</th>
              <th>Confidence</th>
              <th>Verdict</th>
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
                <tr key={`${r.ioc.value}:${r.source}:${i}`}>
                  <td className="ioc-value">
                    {r.ioc.value}
                  </td>
                  <td>{r.source}</td>
                  <td>
                    {r.error ? "—" : `${r.confidenceScore.toFixed(1)}%`}
                  </td>
                  <td style={{ color: r.error ? "#b45309" : undefined }}>
                    {verdict}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
