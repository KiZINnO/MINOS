import { Link } from "react-router-dom";

const SAMPLE_LOG = `Sysmon Event ID 1 - Process Creation
UtcTime: 2024-06-15 14:30:22.123
Image: C:\\Windows\\System32\\cmd.exe
CommandLine: cmd.exe /c powershell -enc SQBF...
User: CORP\\jsmith
Hashes: MD5=8a5b4c9d2e1f3a7b6c0d8e4f2a1b3c5d
NetworkConnection:
  SourceIp: 192.168.1.45
  DestinationIp: 203.0.113.42
  DestinationHostname: malicious-c2.evil.com`;

const STEPS = [
  {
    num: "1",
    title: "Paste Your Log",
    desc: "Paste any security log — Sysmon events, CrowdSec alerts, Splunk exports, or raw text containing IPs, domains, and file hashes.",
  },
  {
    num: "2",
    title: "Extract IoCs",
    desc: "MINOS automatically pulls out IPv4 addresses, domains, MD5, and SHA256 hashes using regex-based extraction.",
  },
  {
    num: "3",
    title: "Score & Triage",
    desc: "Indicators are queried against VirusTotal and AbuseIPDB, then scored by confidence level — from NONE to CRITICAL.",
  },
];

const FORMATS = [
  { name: "Sysmon", desc: "Windows event logs (Event IDs 1, 3, 7, 11, 22, etc.)" },
  { name: "CrowdSec", desc: "JSON alert exports from CrowdSec bouncers" },
  { name: "Splunk", desc: "CSV or text exports from Splunk searches" },
  { name: "EVTX", desc: "Binary Windows Event Log files (CLI only)" },
  { name: "Raw Text", desc: "Any text containing IPs, domains, or hashes" },
];

export default function Home() {
  return (
    <div className="home">
      <section className="hero">
        <h1>MINOS</h1>
        <p className="hero-sub">
          Auto-Triage SOC Bot &mdash; Extract, score, and triage indicators of
          compromise from raw security logs.
        </p>
        <div className="hero-actions">
          <Link to="/analyze" className="btn btn-primary">
            Start Analyzing
          </Link>
          <a href="https://github.com/KiZINnO/MINOS" target="_blank" rel="noreferrer" className="btn">
            View on GitHub
          </a>
        </div>
      </section>

      <section className="section">
        <h2>How It Works</h2>
        <div className="steps-grid">
          {STEPS.map((s) => (
            <div key={s.num} className="step-card">
              <span className="step-num">{s.num}</span>
              <h3>{s.title}</h3>
              <p>{s.desc}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="section">
        <h2>Supported Log Formats</h2>
        <div className="formats-grid">
          {FORMATS.map((f) => (
            <div key={f.name} className="format-card">
              <h4>{f.name}</h4>
              <p>{f.desc}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="section">
        <h2>Quick Start (CLI)</h2>
        <pre className="code-block"><code>{`# Extract IoCs from a Sysmon log
minos sample_logs/sysmon_1.txt --no-intel

# Analyze with live threat intel
minos sample_logs/sysmon_1.txt

# Inline text analysis
minos -t "Connection from 45.33.32.156 to evil.com" --no-intel`}</code></pre>
      </section>

      <section className="section">
        <h2>Sample Log</h2>
        <pre className="code-block"><code>{SAMPLE_LOG}</code></pre>
        <Link to="/analyze" className="btn" style={{ marginTop: "1rem" }}>
          Try this sample in the analyzer &rarr;
        </Link>
      </section>
    </div>
  );
}
