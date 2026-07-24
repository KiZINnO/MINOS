"""MINOS API — FastAPI CORS proxy for VirusTotal & AbuseIPDB.

Provides rate-limited proxying so the browser frontend can query
threat intel APIs without exposing keys server-side.

Deployment: Vercel Serverless (Python)
"""

import logging
from collections import defaultdict
from time import time

import httpx

logger = logging.getLogger(__name__)
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware

app = FastAPI(title="MINOS API", version="0.1.0")

# ---------------------------------------------------------------------------
# CORS — allow all origins (proxy is public, keys stay client-side)
# ---------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Security headers — CSP, XSS protection, MIME sniffing
# ---------------------------------------------------------------------------


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "connect-src 'self' https://www.virustotal.com https://api.abuseipdb.com; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "base-uri 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response


app.add_middleware(SecurityHeadersMiddleware)

# ---------------------------------------------------------------------------
# Rate limiting — per-IP sliding window
# ---------------------------------------------------------------------------

_rate_limits: dict[str, list[float]] = defaultdict(list)

WINDOW_SECONDS = 60
MAX_REQUESTS_PER_MINUTE = 10
MAX_REQUESTS_PER_DAY = 200


def _check_rate_limit(ip: str) -> tuple[bool, int]:
    """Returns (allowed, retry_after_seconds)."""
    now = time()
    window_start = now - WINDOW_SECONDS

    _rate_limits[ip] = [t for t in _rate_limits[ip] if t > window_start]

    if len(_rate_limits[ip]) >= MAX_REQUESTS_PER_MINUTE:
        retry_after = int(_rate_limits[ip][0] - window_start) + 1
        return False, retry_after

    day_start = now - 86400
    daily_count = sum(1 for t in _rate_limits[ip] if t > day_start)
    if daily_count >= MAX_REQUESTS_PER_DAY:
        return False, 3600

    _rate_limits[ip].append(now)
    return True, 0


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class VTRequest(BaseModel):
    path: str  # e.g. "ip_addresses/1.2.3.4"


class AbuseRequest(BaseModel):
    ip: str


# ---------------------------------------------------------------------------
# Upstream base URLs
# ---------------------------------------------------------------------------

VT_BASE = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.post("/api/virustotal")
async def proxy_virustotal(
    body: VTRequest,
    request: Request,
    x_vt_api_key: str = Header(..., alias="X-VT-API-Key"),
):
    ip = _get_client_ip(request)
    allowed, retry_after = _check_rate_limit(ip)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "Rate limit exceeded",
                "detail": f"Maximum {MAX_REQUESTS_PER_MINUTE} requests per minute per IP",
                "retry_after": retry_after,
            },
        )

    url = f"{VT_BASE}/{body.path}"
    headers = {"x-apikey": x_vt_api_key, "Accept": "application/json"}

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            resp = await client.get(url, headers=headers)
        except httpx.TimeoutException:
            logger.warning("VT upstream timeout for path=%s", body.path)
            raise HTTPException(status_code=504, detail="Upstream request timed out")
        except httpx.RequestError as e:
            logger.warning("VT upstream error: %s", e)
            raise HTTPException(status_code=502, detail="Upstream request failed")

    data = resp.json()
    response = JSONResponse(content=data, status_code=resp.status_code)

    remaining = resp.headers.get("x-ratelimit-remaining")
    if remaining is not None:
        response.headers["X-RateLimit-Remaining"] = remaining

    return response


@app.post("/api/abuseipdb")
async def proxy_abuseipdb(
    body: AbuseRequest,
    request: Request,
    x_abuseipdb_key: str = Header(..., alias="X-AbuseIPDB-Key"),
):
    ip = _get_client_ip(request)
    allowed, retry_after = _check_rate_limit(ip)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "Rate limit exceeded",
                "detail": f"Maximum {MAX_REQUESTS_PER_MINUTE} requests per minute per IP",
                "retry_after": retry_after,
            },
        )

    url = f"{ABUSEIPDB_BASE}/check"
    headers = {"Key": x_abuseipdb_key, "Accept": "application/json"}
    params = {"ipAddress": body.ip, "maxAgeInDays": 90}

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            resp = await client.get(url, headers=headers, params=params)
        except httpx.TimeoutException:
            logger.warning("AbuseIPDB upstream timeout for ip=%s", body.ip)
            raise HTTPException(status_code=504, detail="Upstream request timed out")
        except httpx.RequestError as e:
            logger.warning("AbuseIPDB upstream error: %s", e)
            raise HTTPException(status_code=502, detail="Upstream request failed")

    data = resp.json()
    response = JSONResponse(content=data, status_code=resp.status_code)

    for header_name in ("x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset", "retry-after"):
        value = resp.headers.get(header_name)
        if value is not None:
            response.headers[header_name] = value

    return response
