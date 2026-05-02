# AttestSeal x402 Demo

A reference implementation of an x402-aware paid endpoint that stamps
X-AttestSeal-* trust attestation headers on every 402 response.

Live deployment: [demo.attestseal.com](https://demo.attestseal.com)

## What it does

`GET /generate` returns a 402 with an x402 payment challenge body and
the full `X-AttestSeal-*` header set. An x402-aware agent reads the 402,
verifies the AttestSeal signature locally against
`attestseal.com/.well-known/did.json`, decides whether to pay, and (in
this demo) replays `GET /generate?paid=true` to receive a simulated
generated content payload.

The demo is deliberately simple. The destination wallet is `0x0000...`,
so attempting to actually send funds would be a no-op. The point is the
header surface, not the payment.

## Run locally

```bash
cd examples/x402-demo
pip install -r requirements.txt
DEMO_DOMAIN=demo.attestseal.com uvicorn app:app --reload --port 8000
```

Then in another terminal hit the endpoint:

```
$ http GET http://localhost:8000/generate
```

You will see all 14 `X-AttestSeal-*` headers in the 402 response.

## Deploy to demo.attestseal.com

Behind nginx (mirror of `api.attestseal.com`):

```nginx
server {
    listen 443 ssl http2;
    server_name demo.attestseal.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_read_timeout 30s;
    }
}
```

Plus a systemd unit that runs `uvicorn app:app --host 127.0.0.1 --port 8000`.

## Source

`app.py` is 80 lines. It uses `attestseal-x402` (this repo's
`sdk/x402/`) for the middleware. The middleware does the work; the demo
just wires up routes.
