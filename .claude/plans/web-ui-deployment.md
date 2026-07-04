# MINOS Web UI — Implementation Plan

## 1. Architecture Overview

| Layer | Tech | Host | Purpose |
|-------|------|------|---------|
| **Frontend** | React + Vite + TypeScript | Vercel | UI, client-side extraction & scoring |
| **Backend** | FastAPI (Python) | Vercel Serverless | CORS proxy for VT/AbuseIPDB |
| **Storage** | Browser `localStorage` | — | User API keys (never leave device) |

**No EVTX support** in web UI — EVTX contains private/corporate IPs that are useless for public threat intel APIs. Keep CLI for EVTX processing.

**Supported web log formats:** plain text, JSON (CrowdSec-style), CSV/Splunk exports — anything the regex extractor can parse.

**Keep CLI** alongside web UI for local/EVTX use.

---

## 2. API Rate Limits — Reference

### VirusTotal Public API

| Limit | Value |
|-------|-------|
| Requests per minute | **4** |
| Requests per day | **500** |
| Premium API | No limits (licensed) |

Rate limit response: HTTP 429. No `Retry-After` header documented.

### AbuseIPDB API

| Endpoint | Standard (free) | Basic | Premium |
|----------|-----------------|-------|---------|
| `check` (GET) | 1,000/day | 10,000/day | 50,000/day |
| `report` (POST) | 1,000/day | 10,000/day | 50,000/day |

Rate limit response: HTTP 429 with headers:
- `X-RateLimit-Limit` — daily limit
- `X-RateLimit-Remaining` — remaining requests
- `X-RateLimit-Reset` — epoch timestamp for daily reset
- `Retry-After` — seconds to wait before retry

---

## 3. Rate Limiting Strategy

### 3.1 Problem

Since users bring their own API keys, we must protect against:
1. **Proxy abuse** — bots hitting our proxy endpoint to use it as a free VT/AbuseIPDB proxy
2. **User accidentally burning quota** — a bug or UX issue causing rapid-fire requests
3. **Upstream rate limits** — hitting VT (4/min) or AbuseIPDB (1000/day) limits

### 3.2 Three-Layer Rate Limiting

```
┌─────────────────────────────────────────────────────┐
│ LAYER 1: CLIENT-SIDE (JavaScript)                   │
│                                                     │
│  • Throttle: max 1 analysis request per 5 seconds   │
│  • Progress indicator during batch lookups           │
│  • Show remaining VT quota estimate to user          │
│  • Disable "Analyze" button while loading            │
└───────────────────────┬─────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────┐
│ LAYER 2: PROXY (FastAPI on Vercel)                  │
│                                                     │
│  • Per-IP sliding window: 10 requests/minute        │
│  • Per-IP daily cap: 200 requests/day               │
│  • Return 429 + Retry-After when exceeded           │
│  • Simple in-memory dict (no Redis needed for v1)   │
│  • Forward upstream X-RateLimit-* headers to client  │
└───────────────────────┬─────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────┐
│ LAYER 3: UPSTREAM API LIMITS                        │
│                                                     │
│  VT: 4 req/min, 500/day per key                     │
│  AbuseIPDB: 1000/day per key (standard)             │
│  → These are the user's own limits, not ours to      │
│    enforce, but we surface remaining quota info      │
└─────────────────────────────────────────────────────┘
```

### 3.3 Proxy Rate Limit Details

**Sliding window implementation (in-memory):**

```python
from collections import defaultdict
from time import time

# Per-IP tracking
_rate_limits: dict[str, list[float]] = defaultdict(list)

WINDOW_SECONDS = 60       # 1-minute sliding window
MAX_REQUESTS_PER_MINUTE = 10
MAX_REQUESTS_PER_DAY = 200

def check_rate_limit(ip: str) -> tuple[bool, int]:
    """Returns (allowed, retry_after_seconds)."""
    now = time()
    window_start = now - WINDOW_SECONDS

    # Clean old entries
    _rate_limits[ip] = [t for t in _rate_limits[ip] if t > window_start]

    if len(_rate_limits[ip]) >= MAX_REQUESTS_PER_MINUTE:
        retry_after = int(_rate_limits[ip][0] - window_start) + 1
        return False, retry_after

    # Check daily limit
    day_start = now - 86400
    daily_count = sum(1 for t in _rate_limits[ip] if t > day_start)
    if daily_count >= MAX_REQUESTS_PER_DAY:
        return False, 3600  # suggest waiting 1 hour

    _rate_limits[ip].append(now)
    return True, 0
```

**Response format when rate limited:**

```json
{
  "error": "Rate limit exceeded",
  "detail": "Maximum 10 requests per minute per IP",
  "retry_after": 23,
  "daily_remaining": 0
}
```

### 3.4 Client-Side Rate Limiting

```typescript
// lib/api.ts — request throttling
const THROTTLE_MS = 5000; // 5 seconds between analyses
let lastAnalysisTime = 0;

async function throttledQueryAll(iocs: IoC[], vtKey: string, abuseKey: string) {
  const now = Date.now();
  const elapsed = now - lastAnalysisTime;
  if (elapsed < THROTTLE_MS) {
    await new Promise(r => setTimeout(r, THROTTLE_MS - elapsed));
  }
  lastAnalysisTime = Date.now();
  return queryAll(iocs, vtKey, abuseKey);
}
```

### 3.5 User-Facing Quota Display

The frontend should display:
- **VT estimate**: "You have approximately N/500 requests remaining today"
- **AbuseIPDB estimate**: "You have approximately N/1000 requests remaining today"
- **Warning** when approaching limits: "VT daily quota low — consider reducing IoC count"
- Show the `X-RateLimit-Remaining` headers from AbuseIPDB responses

---

## 4. Monorepo Structure

```
MINOS/
├── minos/                    # Existing CLI (unchanged)
├── api/                      # NEW — Vercel Python serverless
│   ├── index.py              # FastAPI app (CORS proxy + rate limiting)
│   └── requirements.txt      # API-specific deps (fastapi, httpx)
├── web/                      # NEW — React frontend
│   ├── public/
│   ├── src/
│   │   ├── components/
│   │   │   ├── LogInput.tsx
│   │   │   ├── ApiKeySettings.tsx
│   │   │   ├── IoCTable.tsx
│   │   │   ├── ResultsTable.tsx
│   │   │   ├── RiskBadge.tsx
│   │   │   ├── ErrorBoundary.tsx
│   │   │   └── ExportButton.tsx
│   │   ├── lib/
│   │   │   ├── extractor.ts
│   │   │   ├── scorer.ts
│   │   │   └── api.ts
│   │   ├── __tests__/
│   │   │   ├── extractor.test.ts
│   │   │   └── scorer.test.ts
│   │   ├── types.ts
│   │   ├── App.tsx
│   │   ├── App.css
│   │   └── main.tsx
│   ├── index.html
│   ├── package.json
│   ├── vite.config.ts
│   └── tsconfig.json
├── tests/                    # Existing Python tests (unchanged)
├── sample_logs/              # Existing sample files (unchanged)
├── vercel.json               # Vercel deployment config
├── requirements.txt          # CLI deps only
├── pyproject.toml            # CLI packaging
├── .env.example              # CLI API keys template
├── .gitignore
└── README.md
```

---

## 5. Implementation Steps

### Step 1 — Backend: CORS Proxy + Rate Limiting (`api/index.py`)

FastAPI app with:

```
GET  /api/health               → { "status": "ok" }

POST /api/virustotal
  Headers: X-VT-API-Key
  Body: { "path": "ip_addresses/1.2.3.4" }
  Response: VT API v3 JSON + X-RateLimit-Remaining header

POST /api/abuseipdb
  Headers: X-AbuseIPDB-Key
  Body: { "ip": "1.2.3.4" }
  Response: AbuseIPDB API v2 JSON + X-RateLimit-* headers
```

- CORS middleware (allow all origins — proxy is public, keys stay client-side)
- Per-IP sliding window: 10 req/min, 200/day
- Forward upstream rate limit headers to client
- **Never log or store API keys**
- Return structured error responses for 429, 500, network errors

**`api/requirements.txt`:**
```
fastapi>=0.104.0
httpx>=0.25.0
```

### Step 2 — Frontend: Project Setup

```bash
npm create vite@latest web -- --template react-ts
cd web && npm install
npm install -D vitest @testing-library/react @testing-library/jest-dom
npm install axios
```

Configure `vite.config.ts` proxy for dev:
```typescript
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': 'http://localhost:8000'
    }
  }
})
```

**`web/package.json` scripts:**
```json
{
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview",
    "test": "vitest",
    "test:run": "vitest run"
  }
}
```

### Step 3 — Frontend: Port Extractor to TypeScript (`lib/extractor.ts`)

Port from `minos/extractor.py`:
- All 4 regex patterns (IPv4, Domain, SHA256, MD5)
- Validation functions (`isValidIPv4`, `isValidDomain`)
- Extraction order: IPv4 → Domain → SHA256 → MD5
- Deduplication logic
- Executable extension denylist

**Supported input formats for web:**
- Plain text logs (Sysmon text, Splunk exports)
- JSON (CrowdSec-style) — parse and extract from string values
- CSV — extract from all fields

### Step 4 — Frontend: Port Scorer to TypeScript (`lib/scorer.ts`)

Port from `minos/scorer.py`:
- Per-source thresholds (VT: >50/>25/>10/>0, AbuseIPDB: >80/>50/>25)
- Multi-source max aggregation
- Overall risk escalation rules
- `scoreReport()` function

### Step 5 — Frontend: API Client with Throttling (`lib/api.ts`)

```typescript
async function queryVirusTotal(iocs: IoC[], apiKey: string): Promise<ThreatIntelResult[]>
async function queryAbuseIPDB(iocs: IoC[], apiKey: string): Promise<ThreatIntelResult[]>
async function queryAll(iocs: IoC[], vtKey: string, abuseKey: string): Promise<ThreatIntelResult[]>
```

- Client-side throttle (5s between analyses)
- Sends IoCs to proxy with user's API keys in headers
- Both providers fire concurrently (`Promise.all`)
- Gracefully skips providers without keys
- Surfaces upstream rate limit info to UI
- **Handles proxy 429 responses** with countdown timer

### Step 6 — Frontend: React Components

**`ApiKeySettings.tsx`** — Two inputs (VT key, AbuseIPDB key)
- Saves to `localStorage` on change
- Registration links for each service
- Show/hide toggle for sensitive input

**`LogInput.tsx`** — Text area + file upload
- Paste log text or upload `.txt/.log/.json`
- "Analyze" button (disabled while loading)
- Character count / file size display

**`IoCTable.tsx`** — Extracted IoCs display
- Columns: Type, Value, Risk Level (badge)
- Sort by risk level (highest first)

**`ResultsTable.tsx`** — Threat intel results
- Columns: IoC, Source, Malicious, Confidence, Verdict
- Expandable rows for raw API response

**`RiskBadge.tsx`** — Color-coded risk indicator
- NONE=gray, LOW=green, MEDIUM=yellow, HIGH=orange, CRITICAL=red

**`ErrorBoundary.tsx`** — React error boundary
- Catches component rendering errors
- Shows friendly error message + "Try Again" button
- Prevents full UI crash on API failures

**`ExportButton.tsx`** — Export report
- Copy JSON to clipboard
- Download as `.json` file
- Download as Markdown `.md` file

### Step 7 — Main App Flow (`App.tsx`)

```
1. Load API keys from localStorage
2. User pastes log / uploads file
3. Click "Analyze" →
   a. extractIocs(text) → iocs (client-side)
   b. Show extraction results immediately
   c. queryAll(iocs, keys) → results (via proxy)
   d. scoreReport(iocs, results) → scored results
   e. Render IoC table + Results table
4. User can export report at any time
```

**Loading states:**
- Spinner during extraction (instant but shows progress)
- Spinner + "Querying threat intel..." during API calls
- Partial failure: "VT ✓ AbuseIPDB ✗ Rate limited" banner

**Empty states:**
- "No IoCs found in input" with suggestion to check format
- "No threat intel results — add API keys in Settings"

### Step 8 — Frontend Tests (`web/src/__tests__/`)

**`extractor.test.ts`** — Port critical Python tests:
- IPv4 extraction + validation
- Domain extraction + executable extension denylist
- MD5/SHA256 extraction + no SHA256→MD5 false positive
- Deduplication
- Empty input

**`scorer.test.ts`** — Port scoring logic tests:
- VT thresholds (CRITICAL/HIGH/MEDIUM/LOW/NONE)
- AbuseIPDB thresholds
- Multi-source max aggregation
- Overall risk escalation rules

### Step 9 — Vercel Configuration (`vercel.json`)

```json
{
  "builds": [
    { "src": "api/index.py", "use": "@vercel/python" }
  ],
  "routes": [
    { "src": "/api/(.*)", "dest": "/api/index.py" },
    { "src": "/(.*)", "dest": "/web/$1" }
  ]
}
```

> Note: Vercel auto-detects and builds the Vite project in `web/` — no need to
> specify it in builds. The static files are served automatically.

### Step 10 — Testing & Verification

- Existing Python tests: `pytest tests/` (ensure nothing breaks)
- Frontend tests: `cd web && npm test`
- Manual proxy test with real keys
- Extraction accuracy test with `sample_logs/sysmon_1.txt` and `sample_logs/crowdsec_alert.json`
- End-to-end browser test
- Rate limiting test: fire 11 requests in 1 minute → verify 429

### Step 11 — Deploy

```bash
npm i -g vercel
vercel login
vercel --prod
```

Verify:
- `GET /api/health` returns 200
- Frontend loads at Vercel URL
- Paste sample log → IoCs extracted
- Enter API keys → threat intel queries work
- Export button downloads report

---

## 6. Security Model

| Concern | Mitigation |
|---------|-----------|
| API keys in browser | localStorage, same-origin only. Keys only forwarded via proxy to upstream APIs. |
| Proxy abuse | Per-IP rate limiting (10/min, 200/day) |
| Keys logged by proxy | Proxy never logs or stores keys — only passes them upstream |
| localStorage cleared | UX: warn when keys missing, prompt re-entry |
| CORS | Proxy allows all origins (it's public). User keys never stored server-side. |
| XSS | React escapes by default. User input only rendered in tables, not HTML. |
| EVTX data leakage | Not supported in web — private/corporate data stays in CLI |

---

## 7. Dependencies to Add

**CLI (`requirements.txt` at root):**
```
aiohttp>=3.9.0
click>=8.1.0
python-dotenv>=1.0.0
python-evtx>=0.8.0
```

**API (`api/requirements.txt`):**
```
fastapi>=0.104.0
httpx>=0.25.0
```

**Frontend (`web/package.json`):**
```json
{
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "axios": "^1.6.0"
  },
  "devDependencies": {
    "typescript": "^5.3.0",
    "vite": "^5.0.0",
    "@vitejs/plugin-react": "^4.2.0",
    "vitest": "^1.0.0",
    "@testing-library/react": "^14.0.0",
    "@testing-library/jest-dom": "^6.0.0"
  }
}
```
