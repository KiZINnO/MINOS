export default function About() {
  return (
    <div className="about">
      <section className="about-section">
        <h2>About MINOS</h2>
        <p>
          MINOS is an auto-triage SOC bot that automates the first stage of
          incident response: extracting Indicators of Compromise from raw
          security logs, querying them against threat intelligence APIs, and
          producing a scored triage report.
        </p>
        <p>
          Named after the mythological king who judged the dead &mdash; MINOS
          judges your logs.
        </p>
      </section>

      <section className="about-section">
        <h2>Architecture</h2>
        <pre className="code-block"><code>{`Raw Security Logs
       |
  Extract IoCs (IPv4, Domain, MD5, SHA256)
       |
  Query Threat Intel (VirusTotal, AbuseIPDB)
       |
  Score Risks (per-source thresholds + aggregation)
       |
  Triage Report (Markdown / JSON)`}</code></pre>
      </section>

      <section className="about-section">
        <h2>Supported IoC Types</h2>
        <table>
          <thead>
            <tr>
              <th>Type</th>
              <th>Description</th>
              <th>Example</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>IPv4</strong></td>
              <td>IP addresses validated with proper octet ranges</td>
              <td><code>45.33.32.156</code></td>
            </tr>
            <tr>
              <td><strong>Domain</strong></td>
              <td>FQDNs with executable extension filtering</td>
              <td><code>evil.com</code></td>
            </tr>
            <tr>
              <td><strong>MD5</strong></td>
              <td>32-character hex hashes (excluded if part of SHA256)</td>
              <td><code>d41d8cd98f00b204...</code></td>
            </tr>
            <tr>
              <td><strong>SHA256</strong></td>
              <td>64-character hex hashes</td>
              <td><code>a7ffc6f8bf1ed766...</code></td>
            </tr>
          </tbody>
        </table>
      </section>

      <section className="about-section">
        <h2>Scoring Logic</h2>

        <h3>Per-Source Thresholds</h3>
        <table>
          <thead>
            <tr>
              <th>Source</th>
              <th>CRITICAL</th>
              <th>HIGH</th>
              <th>MEDIUM</th>
              <th>LOW</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>VirusTotal</td>
              <td>&gt; 50% malicious</td>
              <td>&gt; 25%</td>
              <td>&gt; 10%</td>
              <td>&gt; 0%</td>
            </tr>
            <tr>
              <td>AbuseIPDB</td>
              <td>&gt; 80 confidence</td>
              <td>&gt; 50</td>
              <td>N/A</td>
              <td>&gt; 25</td>
            </tr>
          </tbody>
        </table>

        <h3>Overall Risk Aggregation</h3>
        <table>
          <thead>
            <tr>
              <th>Condition</th>
              <th>Result</th>
            </tr>
          </thead>
          <tbody>
            <tr><td>Any CRITICAL IoC</td><td><strong>CRITICAL</strong></td></tr>
            <tr><td>&gt;= 2 HIGH IoCs</td><td><strong>CRITICAL</strong></td></tr>
            <tr><td>&gt;= 1 HIGH IoC</td><td><strong>HIGH</strong></td></tr>
            <tr><td>&gt;= 3 MEDIUM IoCs</td><td><strong>HIGH</strong></td></tr>
            <tr><td>&gt;= 1 MEDIUM IoC</td><td><strong>MEDIUM</strong></td></tr>
            <tr><td>&gt;= 5 LOW IoCs</td><td><strong>MEDIUM</strong></td></tr>
            <tr><td>&gt;= 1 LOW IoC</td><td><strong>LOW</strong></td></tr>
            <tr><td>Otherwise</td><td>NONE</td></tr>
          </tbody>
        </table>
      </section>

      <section className="about-section">
        <h2>Getting API Keys</h2>
        <p>
          MINOS needs at least one API key to query threat intelligence.
          You can use just one service, or both for broader coverage.
        </p>

        <h3>VirusTotal (free)</h3>
        <ol>
          <li>Go to <a href="https://www.virustotal.com/gui/join-us" target="_blank" rel="noreferrer">virustotal.com/gui/join-us</a> and create a free account</li>
          <li>After verifying your email, go to <strong>My API Key</strong> in your profile settings</li>
          <li>Copy your API key</li>
          <li>In MINOS, expand <strong>API Key Settings</strong> on the Analyze page and paste it into the VirusTotal field</li>
        </ol>

        <h3>AbuseIPDB (free)</h3>
        <ol>
          <li>Go to <a href="https://www.abuseipdb.com/register" target="_blank" rel="noreferrer">abuseipdb.com/register</a> and create a free account</li>
          <li>After verifying your email, go to <strong>API Key</strong> in your account settings</li>
          <li>Copy your API key</li>
          <li>In MINOS, expand <strong>API Key Settings</strong> on the Analyze page and paste it into the AbuseIPDB field</li>
        </ol>

        <p className="note">
          Your keys are stored in your browser's localStorage and sent directly
          to the MINOS proxy — they are never stored on any external server.
        </p>
      </section>

      <section className="about-section">
        <h2>Rate Limits</h2>
        <p>
          Both VirusTotal and AbuseIPDB enforce rate limits on their free tiers.
          MINOS automatically staggers requests to stay within these limits.
        </p>

        <table>
          <thead>
            <tr>
              <th>Service</th>
              <th>Free Tier Limit</th>
              <th>MINOS Behavior</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>VirusTotal</td>
              <td>4 requests/minute</td>
              <td>Queries one IoC at a time with ~16s delay between requests</td>
            </tr>
            <tr>
              <td>AbuseIPDB</td>
              <td>1,000 requests/day</td>
              <td>Queries one IP at a time with 2s delay between requests</td>
            </tr>
          </tbody>
        </table>

        <p className="note">
          <strong>Tip:</strong> If you have many IoCs, the analysis will take longer
          due to rate limit delays. For example, 5 IPs against VirusTotal will take
          about 80 seconds (5 x 16s). This is normal — it prevents your API key
          from being throttled or banned.
        </p>
      </section>

      <section className="about-section">
        <h2>Project</h2>
        <p>
          Source code:{" "}
          <a href="https://github.com/KiZINnO/MINOS" target="_blank" rel="noreferrer">
            github.com/KiZINnO/MINOS
          </a>
        </p>
      </section>
    </div>
  );
}
