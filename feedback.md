# User Feedback — MINOS

- **How collected:** Peer review — two reviewers provided written feedback
- **When:** 2026-07-24

## Raw feedback

### Feedback 1 — Feature Request

> Add dark mode for the web.

### Feedback 2 — Security Audit

> 1. **CORS misconfiguration** — Are CORS settings configured to allow all web origins and pass credentials, effectively enabling any website to retrieve API keys?
>
> 2. **SSRF risk in API proxy** — If the API proxy fails to validate incoming request paths or IPs, it could be exploited to attack backend servers.
>
> 3. **API keys in LocalStorage** — Storing API keys in browser LocalStorage poses a risk where keys could be compromised via an XSS vulnerability.
>
> 4. **No rate limiting** — With a serverless architecture, a lack of rate limiting could lead to memory exhaustion.
>
> 5. **Missing SECURITY.md** — There is no `SECURITY.md` file to outline the procedure for reporting discovered vulnerabilities.
>
> 6. **Review methodology** — Results would be more precise if the repository were cloned and audited via terminal with a prompt like "Audit this repo for security vulnerabilities, logic inconsistencies, and code quality issues."

## Themes (what keeps coming up)

- **UI/UX** — Dark mode is a common feature request for improving user experience
- **Security hardening** — Multiple concerns about CORS, SSRF, key storage, rate limiting, and missing security documentation

## Top 3 things to fix

- [ ] Tighten CORS configuration (restrict origins, do not pass credentials with wildcard origins)
- [ ] Add input validation to the API proxy to prevent SSRF attacks
- [ ] Create a SECURITY.md file with vulnerability disclosure procedures
