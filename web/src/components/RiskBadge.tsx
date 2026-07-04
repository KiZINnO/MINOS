import { RiskLevel } from "../types";

const STYLES: Record<RiskLevel, { bg: string; text: string; label: string }> = {
  [RiskLevel.NONE]:     { bg: "#e5e7eb", text: "#6b7280", label: "NONE" },
  [RiskLevel.LOW]:      { bg: "#dcfce7", text: "#166534", label: "LOW" },
  [RiskLevel.MEDIUM]:   { bg: "#fef9c3", text: "#854d0e", label: "MEDIUM" },
  [RiskLevel.HIGH]:     { bg: "#ffedd5", text: "#9a3412", label: "HIGH" },
  [RiskLevel.CRITICAL]: { bg: "#fee2e2", text: "#991b1b", label: "CRITICAL" },
};

export default function RiskBadge({ level }: { level: RiskLevel }) {
  const s = STYLES[level];
  return (
    <span
      style={{
        display: "inline-block",
        padding: "2px 10px",
        borderRadius: "9999px",
        fontSize: "0.8rem",
        fontWeight: 600,
        background: s.bg,
        color: s.text,
      }}
    >
      {s.label}
    </span>
  );
}
