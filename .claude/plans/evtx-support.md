# Plan: EVTX / Sysmon Structured Parsing Support

## What We're Adding

Parse Windows `.evtx` files using `python-evtx`, map known Sysmon/Security
EventIDs to their IoC-bearing fields, and feed the extracted IoCs into the
existing `threat_intel → scorer → formatter` pipeline — without touching the
regex-based extractor at all.

## Architecture Decision

### New module: `minos/evtx_parser.py`

This keeps the EVTX parsing **completely separate** from the text regex
extractor. They share only the output type (`IoC` dataclass). The CLI
decides which path to take based on file extension.

```
.evtx file ──▶ evtx_parser.py ──▶ IoC objects ──▶ threat_intel ──▶ scorer ──▶ formatter
.txt/.log/.json ──▶ extractor.py (regex) ──▶ IoC objects ──▶ threat_intel ...
```

Trade-off: a `.evtx` file with embedded text IoCs would also benefit from
regex extraction, but combining both paths adds complexity for minimal gain
(the structured parser already extracts IPs and domains from the EVTX
fields directly). We'll add a combined mode later if we find gaps.

## EventID → IoC Field Mapping

From inspecting `DE_RDP_Tunnel_5156.evtx` (101 records, 5 EventIDs):

| EventID | Event Name | IoC Fields | IoC Type |
|---------|-----------|------------|----------|
| 5156 | WFP Connection Event | `SourceAddress`, `DestAddress` | IPv4 |
| 5156 | WFP Connection Event | `Application` | Process path (domain/IoC via regex) |
| 4688 | Process Creation | `NewProcessName`, `CommandLine` | Text → re-extract via regex |
| 4624 | Successful Logon | `IpAddress` | IPv4 |
| 4624 | Successful Logon | `WorkstationName` | Hostname/domain |
| 4648 | Explicit Credential Logon | `IpAddress` | IPv4 |
| 4648 | Explicit Credential Logon | `TargetServerName`, `ProcessName` | Domain/hostname |
| 1102 | Log Cleared | — (no IoCs) | — |

### Extraction strategy per field type

1. **IP fields** (`SourceAddress`, `DestAddress`, `IpAddress`) → create
   `IoC(ioc_type=IoCType.IPV4, value=...)` directly
2. **Process name fields** (`Application`, `NewProcessName`, `ProcessName`)
   → run the *existing regex extractor* on these values to pull out IPs,
   domains, and hashes embedded in paths and command lines
3. **Hostname fields** (`WorkstationName`, `TargetServerName`) → normalize
   to domain-type IoC if they contain dots (FQDN); otherwise skip
   (bare hostnames like `DESKTOP-ABC123` aren't IoCs)

### Deduplication

The evtx parser will call `extract_iocs(text, deduplicate=True)` for
text-heavy fields, and directly construct `IoC` objects for IP fields.
All IoCs are pooled and deduplicated before return.

## CLI Changes

In `cli.py:main()`, after `Step 1: Load input`, add a branch:

```python
if input.endswith(".evtx"):
    iocs = parse_evtx_file(input)        # structured parser
else:
    raw_text = Path(input).read_text(...)
    iocs = extract_iocs(raw_text, ...)   # regex parser (existing)
```

The `--text` path stays unchanged (evtx is binary, can't come from stdin
or --text).

## Dependencies

- Add `python-evtx>=0.8.0` to `requirements.txt` and `pyproject.toml`
  `dependencies` list.

## Files Changed

| File | Change |
|------|--------|
| `minos/evtx_parser.py` | **NEW** — EVTX reader, EventID mapper, field extractor |
| `minos/cli.py` | Add `.evtx` branch before calling `Path.read_text()` |
| `tests/test_evtx_parser.py` | **NEW** — parse sample evtx, verify IoC counts and types |
| `requirements.txt` | Add `python-evtx>=0.8.0` |
| `pyproject.toml` | Add `python-evtx>=0.8.0` to `dependencies` |

## Test Plan

1. Parse `sample_logs/DE_RDP_Tunnel_5156.evtx` → assert correct IoC count
2. Verify EventID 5156 extracts `SourceAddress` and `DestAddress` as IPv4
3. Verify EventID 4688 extracts IPs/domains from `CommandLine` field
4. Verify EventID 1102 produces zero IoCs (correct skip)
5. Verify deduplication across records (same IP appearing in multiple 5156 events)
6. Verify `query_all()` integration works with evtx-extracted IoCs

## Steps (in order)

1. Create `minos/evtx_parser.py` with EventID mapping and extraction logic
2. Update `cli.py` to route `.evtx` to the new parser
3. Update `requirements.txt` and `pyproject.toml`
4. Create `tests/test_evtx_parser.py`
5. Run full test suite
6. End-to-end test: `minos sample_logs/DE_RDP_Tunnel_5156.evtx --no-intel`
