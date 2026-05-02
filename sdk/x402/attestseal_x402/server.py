"""Server-side helpers: stamp X-AttestSeal-* headers on outgoing 402 responses.

The AttestSeal service hosts the per-domain attestation; the server middleware
in this module fetches it (with a sane TTL cache), parses the JSON into an
Attestation, and stamps the response. Servers MAY also prebuild an attestation
at build time and pass it in directly, skipping the runtime fetch entirely.

Three flavors:
- :class:`AttestationStamper` -- the stateless core: turn an attestation into headers
- :class:`AttestationFetcher` -- TTL-cached fetch from /v1/check/<domain>
- :func:`asgi_middleware` -- ASGI middleware factory (FastAPI, Starlette, etc.)

Flask and aiohttp adapters live in adjacent modules so importing
``attestseal_x402.server`` does not pull in framework dependencies.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Mapping, Optional, TYPE_CHECKING

import httpx

from .attestation import Attestation
from .headers import build_headers


_DEFAULT_API_BASE = "https://api.attestseal.com"
_DEFAULT_FETCH_TIMEOUT = 5.0
_DEFAULT_CACHE_TTL = 86400.0  # 24h


@dataclass(frozen=True)
class _CacheEntry:
    attestation: Attestation
    cached_at: float


class AttestationFetcher:
    """Fetches and caches AttestSeal attestations for a set of merchant domains.

    Caching policy: per-domain, TTL-bounded by the smaller of (configured TTL)
    and (attestation.expires_at - now). After a hard error from the AttestSeal
    API, the fetcher returns the last successful cached attestation for up to
    ``stale_grace_seconds`` past its TTL, so a brief upstream outage does not
    take a merchant offline.
    """

    def __init__(
        self,
        *,
        api_base: str = _DEFAULT_API_BASE,
        timeout: float = _DEFAULT_FETCH_TIMEOUT,
        cache_ttl: float = _DEFAULT_CACHE_TTL,
        stale_grace_seconds: float = 600.0,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self._api_base = api_base.rstrip("/")
        self._timeout = timeout
        self._cache_ttl = cache_ttl
        self._stale_grace = stale_grace_seconds
        self._client = client
        self._cache: dict[str, _CacheEntry] = {}
        self._lock = threading.Lock()

    def get(self, domain: str) -> Optional[Attestation]:
        """Return a cached or freshly-fetched attestation, or None if the
        upstream API is unreachable AND no usable cached entry exists."""
        now = time.time()
        with self._lock:
            entry = self._cache.get(domain)
        if entry is not None and (now - entry.cached_at) < self._cache_ttl:
            return entry.attestation

        try:
            attestation = self._fetch(domain)
        except httpx.HTTPError:
            # Upstream failed; serve stale within grace if we have one.
            if entry is not None and (now - entry.cached_at) < (self._cache_ttl + self._stale_grace):
                return entry.attestation
            return None

        with self._lock:
            self._cache[domain] = _CacheEntry(attestation=attestation, cached_at=now)
        return attestation

    def _fetch(self, domain: str) -> Attestation:
        url = f"{self._api_base}/v1/check/{domain}"
        if self._client is not None:
            resp = self._client.get(url, timeout=self._timeout)
        else:
            with httpx.Client(timeout=self._timeout) as client:
                resp = client.get(url)
        resp.raise_for_status()
        body = resp.json()

        return Attestation(
            domain=body["domain"],
            issuer=body["issuer"],
            issued_at=body["checkedAt"],
            expires_at=body["expiresAt"],
            trust_score=int(body["trustScore"]),
            recommendation=body["recommendation"],
            confidence=body.get("confidence", "high"),
            assurance_basis=body.get("assuranceBasis", "earned_proceed"),
            scoring_model=body["scoringModel"],
            signature=body["signature"],
            signature_key_id=body.get("signatureKeyId", ""),
            site_category=body.get("siteCategory"),
            caution_reason=body.get("cautionReason"),
            parent_company=body.get("parentCompany"),
            parent_floor_inherited=bool(body.get("parentFloorInherited", False)),
            agent_policy_hint=body.get("agentPolicyHint"),
            signals=body.get("signals"),
            flags=body.get("flags"),
            reputation_sources=body.get("reputationSources"),
        )


class AttestationStamper:
    """Turn an Attestation into a header dict suitable for stamping on a
    response. Stateless; safe to share across threads and requests.

    Most users should prefer :func:`asgi_middleware`, which combines this
    with :class:`AttestationFetcher` and integrates with ASGI.
    """

    def __init__(self, *, spec_version: str = "0.1.0") -> None:
        self._spec_version = spec_version

    def headers_for(self, attestation: Attestation) -> dict[str, str]:
        return build_headers(attestation, spec_version=self._spec_version)


# ----------------------------------------------------------------------
# ASGI middleware (FastAPI, Starlette, etc.)
# ----------------------------------------------------------------------

if TYPE_CHECKING:
    Scope = dict
    Receive = Callable[[], Awaitable[Mapping]]
    Send = Callable[[Mapping], Awaitable[None]]


def asgi_middleware(
    *,
    domain: str,
    fetcher: Optional[AttestationFetcher] = None,
    stamper: Optional[AttestationStamper] = None,
    only_on_status: tuple[int, ...] = (402,),
):
    """Return an ASGI middleware callable that stamps X-AttestSeal-* headers
    on responses with status codes in ``only_on_status`` (default: 402 only).

    Usage with FastAPI/Starlette::

        from fastapi import FastAPI
        from attestseal_x402.server import asgi_middleware, AttestationFetcher

        app = FastAPI()
        fetcher = AttestationFetcher()
        app.add_middleware(asgi_middleware, domain="merchant.example", fetcher=fetcher)

    The middleware fetches the attestation lazily on the first 402 response
    and reuses the cached value for subsequent requests; it does NOT block
    request handling on attestation availability.
    """
    fetcher = fetcher or AttestationFetcher()
    stamper = stamper or AttestationStamper()

    def factory(app):
        async def middleware(scope, receive, send):
            if scope.get("type") != "http":
                return await app(scope, receive, send)

            async def send_with_stamp(message):
                if message.get("type") == "http.response.start":
                    status = int(message.get("status", 200))
                    if status in only_on_status:
                        attestation = fetcher.get(domain)
                        if attestation is not None:
                            extra = stamper.headers_for(attestation)
                            existing = list(message.get("headers", []))
                            for name, value in extra.items():
                                existing.append((name.encode("latin-1"), value.encode("latin-1")))
                            message = {**message, "headers": existing}
                await send(message)

            await app(scope, receive, send_with_stamp)

        return middleware

    return factory


# ----------------------------------------------------------------------
# Flask hook
# ----------------------------------------------------------------------

def flask_after_request(domain: str, *,
                        fetcher: Optional[AttestationFetcher] = None,
                        stamper: Optional[AttestationStamper] = None,
                        only_on_status: tuple[int, ...] = (402,)) -> Callable:
    """Return a Flask `after_request` hook that stamps the headers.

    Usage::

        from flask import Flask
        from attestseal_x402.server import flask_after_request

        app = Flask(__name__)
        app.after_request(flask_after_request("merchant.example"))
    """
    fetcher = fetcher or AttestationFetcher()
    stamper = stamper or AttestationStamper()

    def hook(response):
        if response.status_code not in only_on_status:
            return response
        attestation = fetcher.get(domain)
        if attestation is None:
            return response
        for name, value in stamper.headers_for(attestation).items():
            response.headers[name] = value
        return response

    return hook
