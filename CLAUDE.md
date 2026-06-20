# MINOS — Auto-Triage SOC Bot

## Project Overview

MINOS is a Python CLI tool (with optional lightweight web API) that automates security log triage. It takes raw security logs (Sysmon events, CrowdSec alerts, Splunk exports), extracts Indicators of Compromise (IoCs), queries them against Threat Intel APIs, and produces a formatted Triage Report.

## Tech Stack

- **Language:** Python 3.10+
- **Async:** `asyncio` + `aiohttp` for concurrent API calls
- **CLI Framework:** `click` or `argparse`
- **Output Formats:** Markdown tables, JSON (SIEM-ingestible)
- **API Integrations:** VirusTotal, AbuseIPDB
- **Config:** `.env` file for API keys via `python-dotenv`

## Project Structure (Planned)

```
MINOS/
├── minos/
│   ├── __init__.py
│   ├── cli.py              # CLI entry point
│   ├── extractor.py         # IoC extraction engine (regex-based)
│   ├── threat_intel.py      # Async API clients (VirusTotal, AbuseIPDB)
│   ├── scorer.py            # Risk scoring logic
│   ├── formatter.py         # Output formatters (Markdown, JSON)
│   └── models.py            # Data models / dataclasses
├── tests/
│   ├── test_extractor.py
│   ├── test_threat_intel.py
│   ├── test_scorer.py
│   └── test_formatter.py
├── sample_logs/             # Sample log files for testing
├── .env.example             # Template for API keys
├── requirements.txt
├── README.md
└── proposal.md
```

## 5-Day Sprint Plan

1. **Day 1 — Extraction Engine:** Parse raw logs/text and extract IPv4, domains, MD5/SHA256 hashes via regex. Output a deduplicated list of IoCs.
2. **Day 2 — Threat Intel Integration:** Async API clients for VirusTotal and AbuseIPDB. Concurrent IoC lookups with `asyncio` + `aiohttp`.
3. **Day 3 — Logic & Scoring:** Risk scoring engine. Per-IoC scoring (e.g., AbuseIPDB confidence > 80% → CRITICAL), aggregate report score.
4. **Day 4 — Output Formatter:** Markdown table reports, JSON output for SIEM ingestion, optional Discord webhook.
5. **Day 5 — GitHub Polish:** README with architecture diagram, setup instructions, `.env.example`, sample outputs.

## Conventions

- All Python code uses type hints.
- Use `dataclasses` for structured data (IoCs, API responses, triage reports).
- Regex patterns are compiled once and reused.
- Async HTTP calls use `aiohttp.ClientSession` with proper timeout/error handling.
- API keys are loaded from environment variables via `python-dotenv` — never hardcoded.
- Logging via `logging` module with configurable verbosity levels.
- Use `pytest` for testing, `pytest-asyncio` for async tests.

## Environment Setup

```bash
cp .env.example .env
# Edit .env with your API keys:
#   VIRUSTOTAL_API_KEY=your_key_here
#   ABUSEIPDB_API_KEY=your_key_here
pip install -r requirements.txt
```

## Related Memories

- [[minos-project-setup]]
