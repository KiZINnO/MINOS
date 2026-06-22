---
marp: true
theme: default
paginate: true
---

<!-- _class: lead -->

# 🛡️ MINOS
### Auto-Triage SOC Bot

**Automated security log triage — extract, score, report.**

Named after the mythological king who judged the dead.
MINOS judges your logs.

---

# 🔴 The Problem

SOC analysts waste **hours** manually triaging security logs.

- **Volume** — Thousands of alerts per day, most are noise
- **Manual extraction** — Copy-pasting IPs, domains, and hashes from raw logs
- **Slow lookups** — Querying VirusTotal and AbuseIPDB one-by-one
- **Inconsistent scoring** — Each analyst applies different severity judgments
- **Report fatigue** — Writing up findings instead of responding to threats

> A single alert can take 15–30 minutes to triage manually.
> MINOS does it in **seconds**.

---

# 👥 Who Uses MINOS?

### Primary Users

- **SOC Analysts (Tier 1/2)** — First responders triaging incoming alerts
- **Incident Responders** — Rapid IoC extraction during active investigations
- **Threat Hunters** — Batch-processing logs to find hidden indicators

### Supported Log Formats

| Source | Format |
|--------|--------|
| Windows Sysmon | `.txt` / `.evtx` |
| CrowdSec Alerts | `.json` |
| Splunk Exports | `.csv` / `.txt` |
| Raw log text | Piped via CLI |

---

# ⚙️ How MINOS Solves It

**4-stage pipeline** — from raw log to scored report:

```
 Raw Log → Extract IoCs → Query Threat Intel → Score → Report
```

1. **Extract** — Regex engine pulls IPv4, domains, MD5, SHA256 hashes.
   EVTX parser reads Windows Event Logs with EventID-aware field mapping.

2. **Enrich** — Async queries to VirusTotal and AbuseIPDB run concurrently.
   10 IoCs looked up in the time it takes to do 1 manually.

3. **Score** — Per-source thresholds (VT > 50% = CRITICAL, AbuseIPDB > 80 = CRITICAL).
   Aggregate logic escalates: 2× HIGH → CRITICAL, 3× MEDIUM → HIGH.

4. **Report** — Markdown tables for humans, JSON for SIEM ingestion.

---

# 🛠️ Tools & Technology

| Layer | Technology |
|-------|-----------|
| Language | Python 3.10+ |
| CLI Framework | Click |
| Async HTTP | `asyncio` + `aiohttp` |
| Config | `python-dotenv` (`.env` for API keys) |
| Threat Intel | VirusTotal API v3, AbuseIPDB v2 |
| EVTX Parsing | `python-evtx` library |
| Testing | `pytest` + `pytest-asyncio` (78 tests) |
| Packaging | `pyproject.toml` + `setuptools` |
| Output | Markdown tables, JSON (SIEM-ready) |

**Zero external infra required** — no database, no server, no cloud.

---

<!-- _class: lead -->

# 🔮 Future Improvements

- **IPv6 support** — Extend extraction to cover next-gen addresses
- **SIEM webhooks** — Push reports directly to Splunk, Elastic, Discord
- **Local caching** — Cache API results to avoid re-querying known IoCs
- **STIX/TAXII output** — Industry-standard threat intel sharing format
- **Web dashboard** — Lightweight Flask/FastAPI UI for non-CLI users
- **MITRE ATT&CK mapping** — Tag IoCs with technique IDs automatically

---

<!-- _class: lead -->

# Thank You

**MINOS** — Auto-Triage SOC Bot

`git clone git@github.com:KiZINnO/MINOS.git`

```bash
pip install -e .
minos sample_logs/sysmon_1.txt --no-intel
```
