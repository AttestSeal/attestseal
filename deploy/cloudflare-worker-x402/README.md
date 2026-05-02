# attestseal-x402-stamper (Cloudflare Worker)

A Cloudflare Worker template that sits in front of your origin and stamps
`X-AttestSeal-*` trust attestation headers on every 402 response.

## What it does

When an agent hits your `merchant.example/paid-resource` endpoint, the
Worker forwards the request to your origin. If the origin returns a 402,
the Worker:

1. Fetches the AttestSeal attestation for `merchant.example` (cached at
   the Cloudflare edge for up to 24 hours, honoring the attestation's own
   `expiresAt`).
2. Stamps all 14 `X-AttestSeal-*` headers on the response.
3. Forwards the now-stamped response to the agent.

The agent verifies the headers locally (one Ed25519 signature check
against the cached `did:web:attestseal.com` document) and decides whether
to pay.

## Deploy

Prereqs: a Cloudflare account, [`wrangler`](https://developers.cloudflare.com/workers/wrangler/install-and-update/) installed, and the merchant domain on Cloudflare.

```bash
cd deploy/cloudflare-worker-x402
npm install
# Edit wrangler.toml: set ATTESTSEAL_DOMAIN to your merchant domain.
wrangler deploy
```

Then add a route in the Cloudflare dashboard (or in `wrangler.toml`) so
the Worker fronts the URLs that issue 402s. A common pattern:

```toml
routes = [
  { pattern = "merchant.example/paid/*", zone_name = "merchant.example" }
]
```

## Verify it's working

After deployment, hit a paid endpoint with `curl`:

```bash
curl -i https://merchant.example/paid/sample
```

You should see all the `X-AttestSeal-*` headers in the 402 response.

## Cache invariants

The Worker cache is keyed by `attestseal-cache.invalid/v1/check/<domain>`
(a synthetic URL that never resolves; it just gives Cloudflare's edge
cache a stable key). Cache TTL is the minimum of:

- `ATTESTSEAL_CACHE_TTL_SECONDS` (default 86400)
- `attestation.expiresAt - now`

So a fresh attestation with 7 days of validity caches for 24 hours, then
refetches on the next request after expiry. A near-expiry attestation
(e.g., 5 minutes left) caches for 5 minutes.

## Security considerations

- The Worker stamps headers received over `fetch()` from
  `api.attestseal.com`. If your origin or the Worker code is compromised,
  the stamp itself cannot be forged (the attestation is signed by
  AttestSeal, not by your origin), so an attacker can at worst fail to
  stamp or stamp with a stale-but-valid attestation.
- The attestation includes the merchant domain in its signed body. An
  attempt to copy a valid attestation from one merchant to another will
  fail the verifier's domain-match check.
- The Worker does not need any secrets (no API keys to AttestSeal). The
  trust attestation API is unauthenticated and public.

## License

MIT.
