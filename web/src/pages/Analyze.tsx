import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ApiKeys, IoC, RiskLevel, ThreatIntelResult } from "../types";
import { extractIoCs } from "../lib/extractor";
import { scoreReport } from "../lib/scorer";
import { queryAll, QueryProgress } from "../lib/api";
import ApiKeySettings from "../components/ApiKeySettings";
import LogInput from "../components/LogInput";
import IoCTable from "../components/IoCTable";
import ResultsTable from "../components/ResultsTable";
import ExportButton from "../components/ExportButton";
import RiskBadge from "../components/RiskBadge";

function loadKeys(): ApiKeys {
  try {
    const raw = sessionStorage.getItem("minos_api_keys");
    if (raw) return JSON.parse(raw);
  } catch {}
  return { vt: "", abuseipdb: "" };
}

export default function Analyze() {
  const [keys, setKeys] = useState<ApiKeys>(loadKeys);
  const [logText, setLogText] = useState("");
  const [iocs, setIocs] = useState<IoC[]>([]);
  const [results, setResults] = useState<ThreatIntelResult[]>([]);
  const [overallRisk, setOverallRisk] = useState<RiskLevel>(RiskLevel.NONE);
  const [status, setStatus] = useState<"idle" | "extracting" | "querying" | "done">("idle");
  const [error, setError] = useState<string | null>(null);
  const [queryProgress, setQueryProgress] = useState<QueryProgress | null>(null);

  useEffect(() => { setKeys(loadKeys()); }, []);

  const handleAnalyze = async () => {
    setError(null);
    setResults([]);
    setIocs([]);
    setOverallRisk(RiskLevel.NONE);
    setQueryProgress(null);

    setStatus("extracting");
    const extracted = extractIoCs(logText);
    setIocs(extracted);

    if (extracted.length === 0) {
      setStatus("done");
      setError("No IoCs found in input. Try pasting a Sysmon log, CrowdSec alert, or any text with IPs, domains, or hashes.");
      return;
    }

    if (!keys.vt && !keys.abuseipdb) {
      setStatus("done");
      setError("No API keys configured. Add your VirusTotal and/or AbuseIPDB keys in API Key Settings, or extract IoCs only.");
      return;
    }

    setStatus("querying");
    try {
      const intelResults = await queryAll(extracted, keys.vt, keys.abuseipdb, setQueryProgress);
      const { iocs: scored, overallRisk: risk } = scoreReport(extracted, intelResults);
      setIocs(scored);
      setResults(intelResults);
      setOverallRisk(risk);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Analysis failed");
    }

    setStatus("done");
    setQueryProgress(null);
  };

  const hasKeys = keys.vt || keys.abuseipdb;

  return (
    <div className="analyze-page">
      <h1 className="page-title">Analyze Logs</h1>
      <p className="page-desc">
        Paste a security log below to extract Indicators of Compromise and
        query them against threat intelligence sources.
      </p>

      {!hasKeys && (
        <div className="info-banner">
          <strong>No API keys yet?</strong> You need at least one API key to query threat intelligence.
          Get a free key from{" "}
          <a href="https://www.virustotal.com/gui/join-us" target="_blank" rel="noreferrer">VirusTotal</a>
          {" "}or{" "}
          <a href="https://www.abuseipdb.com/register" target="_blank" rel="noreferrer">AbuseIPDB</a>,
          then add it in the settings below. See the{" "}
          <Link to="/about">About page</Link>{" "}for step-by-step instructions.
        </div>
      )}

      <ApiKeySettings keys={keys} onChange={setKeys} />

      <LogInput
        value={logText}
        onChange={setLogText}
        onAnalyze={handleAnalyze}
        loading={status === "extracting" || status === "querying"}
      />

      {status === "querying" && queryProgress && (
        <div className="status-banner">
          Querying threat intelligence...
          {queryProgress.vtTotal > 0 && (
            <span> VirusTotal: {queryProgress.vtDone}/{queryProgress.vtTotal}</span>
          )}
          {queryProgress.abuseTotal > 0 && (
            <span> | AbuseIPDB: {queryProgress.abuseDone}/{queryProgress.abuseTotal}</span>
          )}
          {queryProgress.vtTotal > 1 && (
            <span className="rate-hint"> (waiting between requests to respect rate limits)</span>
          )}
        </div>
      )}

      {error && (
        <div className="error-banner">{error}</div>
      )}

      {iocs.length > 0 && (
        <>
          <div className="overall-risk">
            <span style={{ marginRight: 8 }}>Overall Risk:</span>
            <RiskBadge level={overallRisk} />
          </div>
          <IoCTable iocs={iocs} />
          <ResultsTable results={results} />
          <ExportButton iocs={iocs} results={results} overallRisk={overallRisk} />
        </>
      )}
    </div>
  );
}
