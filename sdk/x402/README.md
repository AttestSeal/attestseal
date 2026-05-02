# attestseal-x402

AttestSeal trust attestation headers for x402, AP2, and MPP payment protocols.
Drop-in middleware for FastAPI, Flask, and aiohttp servers, plus a verifier
for httpx and aiohttp clients.

This is the reference implementation of the
[X-AttestSeal-* HTTP Header Specification](https://github.com/AttestSeal/attestseal/blob/main/spec/X-ATTESTSEAL-HEADERS.md).

## Install

```
pip install attestseal-x402
```

Optional extras for framework-specific helpers:

```
pip install 'attestseal-x402[fastapi]'
pip install 'attestseal-x402[flask]'
pip install 'attestseal-x402[aiohttp]'
```

## Server: stamp X-AttestSeal-* on your 402 responses

FastAPI / Starlette:

```python
from fastapi import FastAPI, Response
from attestseal_x402.server import asgi_middleware, AttestationFetcher

app = FastAPI()
fetcher = AttestationFetcher()                                 # 24h cache by default
app.add_middleware(asgi_middleware, domain="merchant.example", fetcher=fetcher)

@app.get("/paid-resource")
def paid_resource():
    return Response(
        status_code=402,
        content='{"scheme":"x402","amount":"0.10","currency":"USD"}',
        media_type="application/json",
        headers={"Accept-Payment": "x402; scheme=base-usdc; amount=0.10"},
    )
```

Flask:

```python
from flask import Flask, jsonify
from attestseal_x402.server import flask_after_request

app = Flask(__name__)
app.after_request(flask_after_request("merchant.example"))

@app.get("/paid-resource")
def paid_resource():
    body = jsonify(scheme="x402", amount="0.10", currency="USD")
    body.status_code = 402
    body.headers["Accept-Payment"] = "x402; scheme=base-usdc; amount=0.10"
    return body
```

The middleware fetches your domain's attestation from
`https://api.attestseal.com/v1/check/<domain>` once per cache TTL (default
24 hours) and stamps the headers on every 402 response.

## Client: verify before paying

```python
import httpx
from attestseal_x402 import AttestationVerifier

verifier = AttestationVerifier(allowed_issuers={"did:web:attestseal.com"})

resp = httpx.get("https://merchant.example/paid-resource")
if resp.status_code == 402:
    result = verifier.verify_response_headers(
        resp.headers, request_url=str(resp.url),
    )
    if result.ok:
        # Apply policy keyed on assuranceBasis
        if result.attestation.assurance_basis == "well_known_tranco_anchor":
            pay(result.attestation, limit=5.00)
        elif result.attestation.assurance_basis == "kyc_verified":
            pay(result.attestation, limit=None)
        elif result.attestation.assurance_basis in {"tracking", "not_recommended"}:
            refuse()
        else:
            ask_user(result.attestation)
    else:
        # Verification failed; fall back to the AttestSeal API for a fresh check
        fallback_check(resp.url)
```

Reasons that come back as `result.reason` when verification fails:
`missing_required_header`, `domain_mismatch`, `expired`, `issuer_not_allowed`,
`did_resolution_failed`, `key_not_found`, `bad_signature`. Fall-back-to-API is
the recommended response for everything except `domain_mismatch` and
`bad_signature`, which suggest active tampering.

## Architecture

```
attestseal_x402/
  attestation.py     -- Attestation dataclass + canonical signing form (SHA-256 over sorted-keys JSON)
  headers.py         -- X-AttestSeal-* names + (de)serialization
  did_resolver.py    -- did:web fetch + 24h TTL cache + Ed25519 key extraction
  client.py          -- AttestationVerifier (one entrypoint: verify_response_headers)
  server.py          -- AttestationFetcher + ASGI middleware + Flask hook
```

The same canonical signing form is used by the production AttestSeal API,
so attestations issued by `did:web:attestseal.com` verify with this client.

## Testing

```
pip install 'attestseal-x402[test]'
pytest tests/
```

The test suite covers signing-form stability across header round-trips,
signature tampering detection, expiry, issuer allow-listing, and
domain-mismatch rejection.

## Spec compatibility

This package implements `X-AttestSeal-*` spec version `0.1.0`. See
`spec/X-ATTESTSEAL-HEADERS.md` in the main repo for the full protocol
document. Compatibility is maintained across patch and minor versions of
the spec; major version changes (signing form, required headers) will be
published as `attestseal-x402` major version bumps.

## License

MIT. See `LICENSE` in the package root.
