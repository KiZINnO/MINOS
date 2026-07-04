import { useRef } from "react";

interface Props {
  value: string;
  onChange: (text: string) => void;
  onAnalyze: () => void;
  loading: boolean;
}

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

export default function LogInput({ value, onChange, onAnalyze, loading }: Props) {
  const fileRef = useRef<HTMLInputElement>(null);

  const handleFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => onChange(reader.result as string);
    reader.readAsText(file);
    e.target.value = "";
  };

  return (
    <div className="log-input-section">
      <p className="log-input-hint">
        Paste any security log below &mdash; Sysmon events, CrowdSec alerts, Splunk exports,
        or raw text containing IPs, domains, or file hashes. MINOS will extract
        Indicators of Compromise and optionally score them against threat intelligence sources.
      </p>
      <textarea
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder="Paste a Sysmon event, CrowdSec alert, Splunk export, or any text with IPs like 192.168.1.1 and domains like evil.com..."
        rows={10}
        className="log-textarea"
      />
      <div className="log-input-actions">
        <button
          onClick={onAnalyze}
          disabled={loading || !value.trim()}
          className="btn btn-primary"
          style={{
            cursor: loading ? "not-allowed" : "pointer",
            opacity: loading || !value.trim() ? 0.5 : 1,
          }}
        >
          {loading ? "Analyzing..." : "Analyze"}
        </button>
        <button onClick={() => fileRef.current?.click()} type="button">
          Upload file
        </button>
        <button
          type="button"
          className="btn-link"
          onClick={() => onChange(SAMPLE_LOG)}
        >
          Try a sample
        </button>
        <input
          ref={fileRef}
          type="file"
          accept=".txt,.log,.json,.csv"
          onChange={handleFile}
          style={{ display: "none" }}
        />
        <span className="char-count">
          {value.length.toLocaleString()} chars
        </span>
      </div>
    </div>
  );
}
