# Changelog

## 0.1.0 (2026-05-02)

Initial release. Reference implementation of `X-AttestSeal-*` HTTP header spec
v0.1.0-draft.

### Features
- `attestseal_x402.attestation` -- Attestation dataclass with canonical
  signing form (SHA-256 over sorted-keys JSON of the signed fields).
- `attestseal_x402.headers` -- X-AttestSeal-* serialization. Required +
  optional fields per spec section 4.
- `attestseal_x402.did_resolver` -- did:web fetch with 24-hour TTL cache,
  Ed25519 verification key extraction from `publicKeyMultibase` field.
- `attestseal_x402.client.AttestationVerifier` -- 5-step verification flow
  (issuer allow-list, domain match, expiry, DID resolve, signature) with
  fall-back to forced DID refresh on bad-signature (handles key-rotation race).
- `attestseal_x402.server.AttestationFetcher` -- 24-hour TTL cache for
  /v1/check/<domain> responses, with stale-grace fallback on upstream outage.
- `attestseal_x402.server.asgi_middleware` -- ASGI middleware factory for
  FastAPI/Starlette/aiohttp.
- `attestseal_x402.server.flask_after_request` -- Flask hook for the same.

### Tests
- 14 tests covering signing-form stability, signature tampering detection,
  expiry, issuer allow-listing, domain-mismatch rejection, and round-trip.
