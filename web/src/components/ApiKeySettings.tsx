import { useState } from "react";
import { ApiKeys } from "../types";

interface Props {
  keys: ApiKeys;
  onChange: (keys: ApiKeys) => void;
}

export default function ApiKeySettings({ keys, onChange }: Props) {
  const [showKeys, setShowKeys] = useState(false);

  const update = (field: keyof ApiKeys, value: string) => {
    const next = { ...keys, [field]: value };
    onChange(next);
    sessionStorage.setItem("minos_api_keys", JSON.stringify(next));
  };

  return (
    <details style={{ marginBottom: "1rem" }}>
      <summary style={{ cursor: "pointer", fontWeight: 600 }}>
        API Key Settings
      </summary>
      <div style={{ padding: "0.75rem", display: "flex", flexDirection: "column", gap: "0.75rem" }}>
        <div>
          <label style={{ display: "block", fontSize: "0.85rem", marginBottom: 4 }}>
            VirusTotal API Key (
            <a href="https://www.virustotal.com/gui/join-us" target="_blank" rel="noreferrer">
              register
            </a>
            )
          </label>
          <input
            type={showKeys ? "text" : "password"}
            value={keys.vt}
            onChange={(e) => update("vt", e.target.value)}
            placeholder="VT API key"
            style={{ width: "100%", padding: "6px 8px", boxSizing: "border-box" }}
          />
        </div>
        <div>
          <label style={{ display: "block", fontSize: "0.85rem", marginBottom: 4 }}>
            AbuseIPDB API Key (
            <a href="https://www.abuseipdb.com/register" target="_blank" rel="noreferrer">
              register
            </a>
            )
          </label>
          <input
            type={showKeys ? "text" : "password"}
            value={keys.abuseipdb}
            onChange={(e) => update("abuseipdb", e.target.value)}
            placeholder="AbuseIPDB API key"
            style={{ width: "100%", padding: "6px 8px", boxSizing: "border-box" }}
          />
        </div>
        <label style={{ fontSize: "0.85rem" }}>
          <input
            type="checkbox"
            checked={showKeys}
            onChange={(e) => setShowKeys(e.target.checked)}
            style={{ marginRight: 6 }}
          />
          Show keys
        </label>
      </div>
    </details>
  );
}
