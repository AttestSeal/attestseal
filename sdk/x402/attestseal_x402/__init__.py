"""attestseal-x402 -- AttestSeal trust attestation headers for x402-style
payment protocols.

The package is the reference implementation of the X-AttestSeal-* HTTP
header specification (see spec/X-ATTESTSEAL-HEADERS.md). It contains:

- :mod:`attestseal_x402.headers` -- canonical header names + (de)serialization
- :mod:`attestseal_x402.attestation` -- the Attestation dataclass + signing-form
- :mod:`attestseal_x402.did_resolver` -- did:web fetch + cache + key lookup
- :mod:`attestseal_x402.client` -- the verifier (one entrypoint: ``verify``)
- :mod:`attestseal_x402.server` -- the issuer (FastAPI/Flask/aiohttp middleware)

Public API:

>>> from attestseal_x402 import verify, AttestationVerifier
>>> verifier = AttestationVerifier()
>>> result = verifier.verify_response_headers(headers, request_url="https://merchant.example/page")
>>> if result.ok:
...     apply_policy(result.attestation)
"""
__version__ = "0.1.0"

from .attestation import Attestation, VerificationResult
from .client import AttestationVerifier, verify
from .headers import HEADER_NAMES, build_headers, parse_headers
from .did_resolver import DIDResolver, default_resolver
from .server import (
    AttestationFetcher,
    AttestationStamper,
    StampingMiddleware,
    asgi_middleware,
    flask_after_request,
)

__all__ = [
    "Attestation",
    "VerificationResult",
    "AttestationVerifier",
    "verify",
    "HEADER_NAMES",
    "build_headers",
    "parse_headers",
    "DIDResolver",
    "default_resolver",
    "AttestationFetcher",
    "AttestationStamper",
    "StampingMiddleware",
    "asgi_middleware",
    "flask_after_request",
    "__version__",
]
