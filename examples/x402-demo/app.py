"""Reference x402 + AttestSeal demo service.

Run locally:

    pip install fastapi uvicorn 'attestseal-x402[fastapi]'
    DEMO_DOMAIN=demo.attestseal.com uvicorn app:app --reload

Or in production behind nginx at demo.attestseal.com.

Endpoints:
- GET /            -> 200 HTML, explains the demo
- GET /generate    -> 402 with x402 challenge + X-AttestSeal-* headers
- GET /generate?paid=true -> 200 with the actual generated content
"""
from __future__ import annotations

import os
import secrets

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

from attestseal_x402.server import StampingMiddleware, AttestationFetcher

DOMAIN = os.environ.get("DEMO_DOMAIN", "demo.attestseal.com")
PRICE_USD = "0.10"
DEMO_SCHEME = "x402"
DEMO_DESTINATION = "0x0000000000000000000000000000000000000000"  # demo only

app = FastAPI(title="AttestSeal x402 demo", version="0.1.0")

# Stamp X-AttestSeal-* on every 402 response. The fetcher caches the
# attestation for DOMAIN for up to 24 hours.
fetcher = AttestationFetcher()
app.add_middleware(StampingMiddleware, domain=DOMAIN, fetcher=fetcher, only_on_status=(402,))


@app.on_event("startup")
def _warm_attestation_cache() -> None:
    # The synchronous fetcher inside the async middleware can lose the race
    # against the response on a cold first request: the response goes out
    # before the upstream API call completes, leaving the very first 402
    # without X-AttestSeal-* headers. Pre-warming on startup makes every
    # request from request 1 onwards a guaranteed cache hit.
    try:
        fetcher.get(DOMAIN)
    except Exception:
        pass


HOME_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>AttestSeal x402 Demo</title>
  <style>
    body { font: 16px/1.55 -apple-system, BlinkMacSystemFont, sans-serif;
           max-width: 720px; margin: 60px auto; padding: 0 20px; color: #1a1a2e; }
    h1 { font-weight: 600; }
    code { background: #f4f4f7; padding: 2px 6px; border-radius: 4px; }
    pre { background: #f4f4f7; padding: 16px; border-radius: 8px; overflow-x: auto; }
    .hint { color: #555; font-size: 14px; }
  </style>
</head>
<body>
  <h1>AttestSeal x402 Demo</h1>
  <p>This service charges $0.10 per call to <code>/generate</code>. Hit it
     with an x402-aware client and you will receive a 402 response that
     carries an AttestSeal trust attestation in HTTP headers.</p>

  <h2>Try it</h2>
  <pre>$ http GET https://demo.attestseal.com/generate</pre>

  <p class="hint">In the response, look for <code>X-AttestSeal-Issuer</code>,
     <code>X-AttestSeal-Recommendation</code>,
     <code>X-AttestSeal-Assurance-Basis</code>, and
     <code>X-AttestSeal-Signature</code>. An x402-aware client verifies the
     signature against <code>https://attestseal.com/.well-known/did.json</code>
     and decides whether to send payment.</p>

  <h2>Spec</h2>
  <p><a href="https://github.com/AttestSeal/attestseal/blob/main/spec/X-ATTESTSEAL-HEADERS.md">X-AttestSeal-* HTTP Header Specification</a></p>

  <h2>Reference client</h2>
  <pre>pip install attestseal-x402

from attestseal_x402 import AttestationVerifier
import httpx

resp = httpx.get("https://demo.attestseal.com/generate")
verifier = AttestationVerifier()
result = verifier.verify_response_headers(resp.headers, request_url=str(resp.url))
print(result.ok, result.attestation.recommendation, result.attestation.assurance_basis)</pre>

  <p class="hint">Source for this demo:
     <a href="https://github.com/AttestSeal/attestseal/tree/main/examples/x402-demo">github.com/AttestSeal/attestseal/examples/x402-demo</a></p>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def home():
    return HOME_HTML


@app.get("/generate")
def generate(request: Request):
    paid = request.query_params.get("paid", "").lower() == "true"
    if not paid:
        # Issue 402 with x402 challenge. The middleware stamps X-AttestSeal-*
        # headers automatically.
        challenge = {
            "scheme": DEMO_SCHEME,
            "amount": PRICE_USD,
            "currency": "USD",
            "destination": DEMO_DESTINATION,
            "resource": f"https://{DOMAIN}/generate?paid=true",
            "note": "Demo only. The destination wallet is the zero address; "
                    "do NOT actually send funds. Replay /generate?paid=true to "
                    "see the simulated payment-completed flow.",
        }
        return JSONResponse(
            content=challenge,
            status_code=402,
            headers={"Accept-Payment": f"x402; scheme={DEMO_SCHEME}; amount={PRICE_USD}"},
        )

    # Simulated payment success path. In a real implementation this is where
    # the server would verify the agent's payment proof against the rail.
    return JSONResponse(
        content={
            "ok": True,
            "generated": secrets.token_hex(16),
            "note": "This is a simulated paid response; the demo does not "
                    "actually verify any payment.",
        },
        status_code=200,
    )


@app.get("/health")
def health():
    return {"status": "ok"}
