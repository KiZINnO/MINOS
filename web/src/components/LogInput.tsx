import { useRef } from "react";

interface Props {
  value: string;
  onChange: (text: string) => void;
  onAnalyze: () => void;
  loading: boolean;
}

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
    <div style={{ marginBottom: "1rem" }}>
      <textarea
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder="Paste a security log here (Sysmon, CrowdSec, Splunk export, raw text)..."
        rows={10}
        style={{
          width: "100%",
          padding: "8px",
          fontFamily: "monospace",
          fontSize: "0.85rem",
          boxSizing: "border-box",
          resize: "vertical",
        }}
      />
      <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginTop: "0.5rem" }}>
        <button
          onClick={onAnalyze}
          disabled={loading || !value.trim()}
          style={{
            padding: "8px 20px",
            fontWeight: 600,
            cursor: loading ? "not-allowed" : "pointer",
            opacity: loading || !value.trim() ? 0.5 : 1,
          }}
        >
          {loading ? "Analyzing..." : "Analyze"}
        </button>
        <button onClick={() => fileRef.current?.click()} type="button">
          Upload file
        </button>
        <input
          ref={fileRef}
          type="file"
          accept=".txt,.log,.json,.csv"
          onChange={handleFile}
          style={{ display: "none" }}
        />
        <span style={{ fontSize: "0.8rem", color: "#888" }}>
          {value.length.toLocaleString()} chars
        </span>
      </div>
    </div>
  );
}
