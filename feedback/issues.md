# Open Issues — MINOS

User feedback → GitHub issues. File each real problem as an issue in your repo,
then list them here. (These are what you'll close in Chapter 6.)

| # | Issue title | GitHub link | From (user/feedback) | Priority | Status |
|---|---|---|---|---|---|
| 1 | Add dark mode support to web UI | [#2](https://github.com/KiZINnO/MINOS/issues/2) | Peer feedback — feature request | low | **Fixed** |
| 2 | Create SECURITY.md with vulnerability disclosure policy | [#3](https://github.com/KiZINnO/MINOS/issues/3) | Peer feedback — security audit | low | Won't do |
| 3 | SSRF / path injection risk in API proxy | [#4](https://github.com/KiZINnO/MINOS/issues/4) | Security audit + peer feedback | low | Left open |
| 4 | API keys stored in browser LocalStorage | [#5](https://github.com/KiZINnO/MINOS/issues/5) | Security audit + peer feedback | medium | **Fixed** |
| 5 | Add Content Security Policy headers | [#6](https://github.com/KiZINnO/MINOS/issues/6) | Code review security audit | medium | **Fixed** |
| 6 | Error messages leak internal details | [#7](https://github.com/KiZINnO/MINOS/issues/7) | Code review security audit | low | **Fixed** |
| 7 | Pin Python dependency versions | [#8](https://github.com/KiZINnO/MINOS/issues/8) | Code review security audit | low | **Fixed** |
| 8 | CORS misconfigured — allow_origins=["*"] with credentials | [#9](https://github.com/KiZINnO/MINOS/issues/9) | Peer feedback — security audit | low | Left open |

## Priority Re-Assessments

Two issues were originally marked **high** during first triage, but after reviewing the actual threat model they were downgraded:

### CORS (#9) — high → low
The concern was that permissive CORS allows any website to steal API keys. However:
- API keys are sent **to** the API as request headers (X-VT-API-Key, X-AbuseIPDB-Key) — they are never returned in API responses.
- Keys are stored in localStorage, protected by same-origin policy — other sites cannot read them.
- Users bring their own VT/AbuseIPDB keys — there are no server-side credentials at risk.
- Browsers already reject `allow_credentials=True` with a wildcard origin per the CORS spec, so the config is effectively a no-op.

Verdict: Defence-in-depth hardening, not an exploit path. Low priority.

### SSRF / Path Injection (#4) — high → low
The concern was that an attacker-controlled `path` parameter enables SSRF attacks. However:
- The VT base URL is hardcoded to `https://www.virustotal.com/api/v3` — there is no way to redirect requests to internal services or arbitrary hosts.
- Users bring their own VT API key, so any request they proxy uses their own quota and rate limits.
- At worst, a user could hit other VT v3 endpoints (e.g. file downloads) and waste their own quota — a self-inflicted inconvenience.

Verdict: Defence-in-depth (waste own quota), not a real SSRF. Low priority.

### Rate limiting — not filed (false positive)
Peer concern about no rate limiting. Server-side per-IP sliding window (10 req/min, 200 req/day) already exists in `api/index.py:36-60`, plus client-side throttle in `web/src/lib/api.ts:13-20`. In-memory only on Vercel (resets on cold start) but adequate for a single-user BYO-key tool.

## Resolution Notes

### Fixed
- **#2 Dark mode** — Added `useTheme` hook, toggle button in navbar, CSS variables for both light/dark palettes, respects `prefers-color-scheme`, persists choice in localStorage.
- **#5 LocalStorage keys** — Switched from `localStorage` to `sessionStorage` (keys cleared on tab close). Same UX during use — page refreshes still work.
- **#6 CSP headers** — Added `<meta http-equiv="Content-Security-Policy">` in `index.html` and `SecurityHeadersMiddleware` in the FastAPI API that sets CSP + `X-Content-Type-Options` + `X-Frame-Options` + `X-XSS-Protection`.
- **#7 Error leakage** — Replaced broad `except Exception as e` with specific `aiohttp.ClientError` and `httpx.RequestError` catches. Full error details logged server-side; generic messages returned to the client.
- **#8 Pin deps** — Pinned all dependencies to exact versions in `requirements.txt` for reproducible Vercel deploys.

### Won't do / Left open
- **#3 SECURITY.md** — Not created. This is a student project with no external users. No vulnerability disclosure channel needed.
- **#4 SSRF** — Left open. VT base URL is hardcoded; users own their API keys. No real attack surface.
- **#9 CORS** — Left open. BYO-key tool, no credentials at risk, browsers already reject the config as-is.

## Notes

Issues were triaged from two sources:
- **Peer feedback** in `feedback.md` — dark mode feature request + 5 security concerns (CORS, SSRF, LocalStorage, rate limiting, missing SECURITY.md).
- **Code review security audit** — 3 additional findings (missing CSP, error leakage, unpinned deps) discovered during a full source audit.
