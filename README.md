# 🛡️ MINOS — Auto-Triage SOC Bot

**MINOS** extracts Indicators of Compromise (IoCs) from raw security logs, queries them against threat intelligence APIs, and produces a clean, scorable triage report — in Markdown or JSON.

> Named after the mythological king who judged the dead. MINOS judges your logs.

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Raw Security   │     │   MINOS Engine   │     │   Triage Report  │
│      Logs        │────▶│                  │────▶│                  │
│  • Sysmon        │     │  1. Extract IoCs │     │  • Markdown      │
│  • CrowdSec      │     │  2. Query Intel  │     │  • JSON (SIEM)   │
│  • Splunk Export │     │  3. Score Risks  │     │                  │
│  • Raw Text      │     │  4. Format       │     │                  │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                │
                        ┌───────┴───────┐
                        │               │
                   ┌─────────┐   ┌──────────┐
                   │VirusTotal│   │AbuseIPDB │
                   └─────────┘   └──────────┘
```

## Features

- **IoC Extraction** — IPv4, domains, MD5, and SHA256 hashes via regex from any text-based log
- **EVTX Support** — Structured parsing of Windows Event Log (.evtx) files with EventID-aware field extraction
- **Async Threat Intel** — Concurrent lookups against VirusTotal and AbuseIPDB
- **Risk Scoring** — Multi-source confidence-based scoring with aggregation
- **Dual Output** — Beautiful Markdown reports or SIEM-ready JSON
- **Zero Boilerplate** — Pipe a log in, get a report out

## Quick Start

### 1. Install

```bash
git clone git@github.com:KiZINnO/MINOS.git
cd MINOS

# Recommended: install inside a virtual environment
python3 -m venv .venv
source .venv/bin/activate

pip install -e .
```

After install, the `minos` command is available on your PATH:

```bash
$ minos --help
Usage: minos [OPTIONS] [INPUT]
...
```

If `minos` isn't found, use the module runner fallback: `python3 -m minos.cli ...`

### 2. Configure API Keys

```bash
cp .env.example .env
```

Edit `.env` and add your keys:

| Service | Register At | Key Variable |
|---------|------------|--------------|
| VirusTotal | https://www.virustotal.com/gui/join-us | `VIRUSTOTAL_API_KEY` |
| AbuseIPDB | https://www.abuseipdb.com/register | `ABUSEIPDB_API_KEY` |

You can skip API keys for extraction-only mode with `--no-intel`.

### 3. Run

```bash
# From a text-based log file
minos sample_logs/sysmon_1.txt --no-intel

# From a Windows EVTX event log (structured EventID parsing)
minos sample_logs/DE_RDP_Tunnel_5156.evtx --no-intel

# Inline text
minos -t "Suspicious connection from 45.33.32.156 to evil.com" --no-intel

# JSON output for SIEM ingestion
minos sample_logs/sysmon_1.txt -f json -o report.json --no-intel

# Extract only (skip threat intel lookups)
minos sample_logs/crowdsec_alert.json --no-intel

# With live threat intel (requires API keys in .env)
minos sample_logs/sysmon_1.txt
```

## Sample Output

### Markdown

```
# 🛡️ MINOS Triage Report

**Generated:** 2024-06-15 14:35:00 UTC

## Overall Risk Assessment

| Risk Level |
| --- |
| 🟩🟨🟧🟥⬜  CRITICAL |

## Indicators of Compromise (IoCs)

| Type | Value | Risk Level | Sources |
| --- | --- | --- | --- |
| IPv4 | `45.33.32.156` | 🔴 CRITICAL | AbuseIPDB |
| Domain | `bad-actor.phish-tracker.xyz` | 🟠 HIGH | VirusTotal |
| SHA256 | `a7ffc6f8...` | 🟡 MEDIUM | VirusTotal |
```

### JSON

```json
{
  "report": {
    "generated_at": "2024-06-15T14:35:00+00:00",
    "overall_risk": "critical",
    "total_iocs": 3,
    "unique_iocs": 3
  },
  "iocs": [
    {
      "type": "ipv4",
      "value": "45.33.32.156",
      "risk_level": "critical",
      "sources": ["AbuseIPDB"]
    }
  ],
  "threat_intel_results": [...]
}
```

## Scoring Logic

### Per-Source Thresholds

| Source | CRITICAL | HIGH | MEDIUM | LOW |
|--------|----------|------|--------|-----|
| VirusTotal | >50% malicious | >25% | >10% | >0% |
| AbuseIPDB | >80 confidence | >50 | >25 | N/A |

### Overall Risk

| Condition | Result |
|-----------|--------|
| Any CRITICAL IoC | **CRITICAL** |
| ≥2 HIGH IoCs | **CRITICAL** |
| ≥1 HIGH IoC | **HIGH** |
| ≥3 MEDIUM IoCs | **HIGH** |
| ≥1 MEDIUM IoC | **MEDIUM** |
| ≥5 LOW IoCs | **MEDIUM** |
| ≥1 LOW IoC | **LOW** |
| Otherwise | **NONE** |

## Project Structure

```
MINOS/
├── minos/                  # Core package
│   ├── cli.py              # CLI entry point (click)
│   ├── extractor.py         # IoC regex extraction
│   ├── evtx_parser.py       # Windows EVTX structured parser
│   ├── threat_intel.py      # Async API clients (VirusTotal, AbuseIPDB)
│   ├── scorer.py            # Risk scoring engine
│   ├── formatter.py         # Markdown & JSON output
│   └── models.py            # Dataclasses & enums
├── tests/                   # pytest test suite (77 tests)
├── sample_logs/             # Example logs for testing
├── pyproject.toml
├── requirements.txt
└── .env.example
```

## License

MIT

---

🤖 Generated with [Claude Code](https://claude.com/claude-code)
