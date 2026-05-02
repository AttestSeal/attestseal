# X-AttestSeal-* HTTP Header Specification

**Version:** 0.1.0-draft
**Status:** Draft
**Authors:** Allen Lu
**Date:** 2026-05-02
**Audience:** authors of x402 / AP2 / MPP servers and clients, payment-aware HTTP clients in agent runtimes, CDN-edge implementors

---

## 1. Abstract

This document specifies a set of HTTP response headers (`X-AttestSeal-*`) that a payment-issuing server can include alongside an HTTP `402 Payment Required` response to attach a cryptographically signed AttestSeal trust attestation directly to the payment challenge. Agents that process the 402 perform a single Ed25519 verification against the issuer's published DID document to decide whether to pay, with no additional round-trip to a trust-score API in the common case.

The headers are protocol-agnostic. They work with Coinbase x402, Stripe Machine Payments Protocol, Skyfire KYAPay, AP2, MPP, or any future scheme that uses HTTP 402 to gate access to a paid resource.

## 2. Motivation

x402 (and its peers) solve "how does an agent pay?" Trust ("should an agent pay?") was left to a separate API call: `GET https://api.attestseal.com/v1/check/<merchant>` before each payment. Two problems:

1. Every agent transaction adds a second HTTP round-trip that gates payment latency on AttestSeal's availability.
2. Merchants who want their 402 to be honored have no way to *push* trust evidence inline; they're forced to hope the agent does its own check.

Stamping the attestation directly in the 402 response solves both. The agent already has to read the 402 to learn payment requirements. Adding cryptographic proof of trust to the same response is free, and it binds the trust assertion to the payment challenge in a way an attacker cannot strip without breaking the signature.

## 3. Design Principles

1. **No new round-trip in the happy path.** The agent verifies locally using a cached DID document.
2. **Cryptographic, not advisory.** Headers are Ed25519-signed; the score field cannot be tampered with.
3. **Composable with existing 402 schemes.** Headers do not replace any payment field; they sit alongside.
4. **Failure mode = fall back to API.** If headers are absent or signature fails, the agent calls `GET /v1/check/<domain>`. Same outcome, one extra round-trip.
5. **Cache-friendly.** A 24-hour TTL on attestations means a popular merchant stamps once per day; CDN edges can serve the same headers for the cache window.

## 4. Headers

A 402 response that participates in this specification SHOULD include all of the headers in section 4.1. It MAY include the optional headers in section 4.2.

### 4.1 Required headers

| Header | Format | Description |
|---|---|---|
| `X-AttestSeal-Issuer` | `did:web:attestseal.com` | The DID under which the attestation is signed. |
| `X-AttestSeal-Domain` | `<host>` | The merchant domain the attestation refers to. MUST equal the host of the URL that returned the 402. |
| `X-AttestSeal-Score` | integer 0-100 | Trust score. |
| `X-AttestSeal-Recommendation` | `PROCEED` \| `CAUTION` \| `DENY` | Human-actionable verdict. |
| `X-AttestSeal-Confidence` | `high` \| `medium` \| `low` | How complete the underlying evidence is. |
| `X-AttestSeal-Assurance-Basis` | string (see section 6) | Why the recommendation is what it is. |
| `X-AttestSeal-Issued-At` | RFC 3339 | Timestamp the attestation was minted. |
| `X-AttestSeal-Expires-At` | RFC 3339 | Timestamp after which the attestation MUST be re-fetched. |
| `X-AttestSeal-Scoring-Model` | string | Versioned model identifier (e.g., `attestseal-v1.5.1-weights`). |
| `X-AttestSeal-Signature` | multibase string (M-prefix base64pad) | Ed25519 signature over the canonical signing input (section 5). |
| `X-AttestSeal-Key-Id` | DID URL fragment | Verification key reference, e.g., `did:web:attestseal.com#signing-key-1`. |

### 4.2 Optional headers

| Header | Format | Description |
|---|---|---|
| `X-AttestSeal-Caution-Reason` | string | When `Recommendation=CAUTION`. Values: `weak_signals` \| `incomplete_evidence` \| `new_domain` \| `infrastructure` \| `tenant_platform` \| `tracking`. |
| `X-AttestSeal-Site-Category` | string | `consumer` \| `tenant_platform` \| `infrastructure` \| `tracking` \| `api_service`. |
| `X-AttestSeal-Parent-Company` | string | Human-readable parent name when the merchant matches the AttestSeal `parent_companies` registry (e.g., `Vercel`, `Cloudflare`). |
| `X-AttestSeal-Parent-Floor-Inherited` | `true` \| `false` | `false` everywhere today. Reserved for future inheritance scenarios; cryptographic confirmation that the score did NOT come from parent-rank inheritance. |
| `X-AttestSeal-Agent-Policy-Hint` | string | One of: `proceed_normal`, `proceed_earned`, `proceed_with_platform_context`, `proceed_with_infrastructure_context`, `proceed_with_api_context`, `proceed_registered`, `proceed_kyc_verified`, `do_not_pay_tracking`, `do_not_pay`. Convenience field for agents that prefer not to derive policy from the basis. |

## 5. Canonical signing input

The signature in `X-AttestSeal-Signature` is computed over the SHA-256 of the canonical JSON form of an *attestation object*. Implementations MUST construct exactly this object and serialize it with sorted keys and no whitespace before hashing.

```jsonc
{
  "domain": "<X-AttestSeal-Domain>",
  "issuer": "<X-AttestSeal-Issuer>",
  "issuedAt": "<X-AttestSeal-Issued-At>",
  "expiresAt": "<X-AttestSeal-Expires-At>",
  "trustScore": <integer>,
  "recommendation": "<PROCEED|CAUTION|DENY>",
  "confidence": "<high|medium|low>",
  "assuranceBasis": "<string>",
  "scoringModel": "<string>",
  "siteCategory": "<string|null>",
  "cautionReason": "<string|null>",
  "parentCompany": "<string|null>",
  "parentFloorInherited": <bool>,
  "agentPolicyHint": "<string>"
}
```

Optional headers that are absent in the response MUST be present in the signing object as JSON `null` (for strings) or their default value (for booleans). This keeps the signing input stable across servers that omit optional headers.

The signature value is the multibase-encoded form of the raw 64-byte Ed25519 output: `"M" + base64pad(signature_bytes)`. (`"M"` is multibase code for base64pad.)

## 6. Assurance basis values

Identical to the `assuranceBasis` field in the AttestSeal API response. Reproduced here so this spec stands alone.

| Value | Meaning |
|---|---|
| `well_known_tranco_anchor` | Top-50K Tranco rank, aged 5+ years, valid SSL, clean reputation. The brand-anchor floor lifted the score. |
| `earned_proceed` | PROCEED on signal merit alone, no anchor or registration. |
| `registered_proceed` | Operator completed the AttestSeal registration flow with verified business fields. |
| `kyc_verified` | Highest assurance: government-ID, business docs, bank, and video call all verified. |
| `tenant_platform_earned` | Domain is the apex of (or sits under a suffix of) a registered tenant platform AND PROCEED'd via own signals. The `_earned` suffix tells the agent the score did NOT come from parent-rank inheritance. |
| `infrastructure_earned` | Same shape as above, for SaaS / cloud-infrastructure parents (e.g., `cloudflare.com`). |
| `api_service_earned` | Heuristic-detected API endpoint that PROCEED'd via own signals. The agent-commerce primary case. |
| `tracking` | Ad/analytics domain (e.g., `doubleclick.net`). Always blocked from PROCEED regardless of score. |
| `not_recommended` | CAUTION/DENY; score below threshold or safety flag fired. |

## 7. Server flow

When a payment-aware server is about to issue a 402:

1. Look up the merchant's most recent AttestSeal attestation (cached locally for at most the TTL of `expiresAt`).
2. If cache miss or expired, fetch a fresh attestation from `GET https://api.attestseal.com/v1/check/<domain>` (or load from a static token cached at build time).
3. Stamp the response with the `X-AttestSeal-*` headers.
4. Continue with the payment-protocol-specific 402 body (e.g., x402 `Accept-Payment` header, AP2 manifest URL).

The reference implementation (`attestseal-x402` Python package, section 10) provides FastAPI / Flask / aiohttp middleware that does steps 1-3 automatically.

Servers MAY issue the headers on responses other than 402. There is no protocol harm; agents simply have one fewer reason to verify them.

## 8. Client (agent) flow

When a payment-aware HTTP client receives a response containing `X-AttestSeal-*` headers:

1. **Required-header check.** If any of the section 4.1 headers is missing, treat the attestation as absent and fall back to the API.
2. **Issuer authorization.** Confirm `X-AttestSeal-Issuer` is on the agent's allow-list. Reject otherwise.
3. **Domain match.** Confirm `X-AttestSeal-Domain` equals the host of the request URL. Reject otherwise; this prevents header-injection from a third-party 402.
4. **Freshness.** Confirm `X-AttestSeal-Expires-At` is in the future. Treat expired as absent.
5. **DID resolve.** Fetch `https://attestseal.com/.well-known/did.json` (cached locally for 24h, see section 9). Locate the verification method whose `id` matches `X-AttestSeal-Key-Id`.
6. **Reconstruct canonical signing input** per section 5.
7. **Verify** the Ed25519 signature in `X-AttestSeal-Signature` against the SHA-256 of the canonical input using the public key from step 5. Reject on failure.
8. **Apply policy.** Use `X-AttestSeal-Recommendation` (or `X-AttestSeal-Agent-Policy-Hint` for explicit handling) to decide whether to proceed with payment. Apply transaction limits per `X-AttestSeal-Assurance-Basis` if the agent has policy keyed on basis.

If any step fails, the client SHOULD fall back to a direct API call (`GET https://api.attestseal.com/v1/check/<domain>?refresh=true`) and apply the same policy to that response. The fallback adds one round-trip but preserves the trust guarantee.

## 9. Caching

### 9.1 DID document

Clients MUST cache the DID document for at most 24 hours. They MUST validate the cache by re-fetching when:

- The cache age exceeds 24 hours.
- The signature verification step fails for an attestation that the agent reasonably expects to be valid (e.g., score is recent and under TTL). This handles the rare key-rotation case.

The DID document at `https://attestseal.com/.well-known/did.json` is small (about 1 KB) and served behind Cloudflare; the bandwidth cost of cache misses is negligible.

### 9.2 Attestation

Servers SHOULD cache attestations until `expiresAt` and serve the same headers from cache to multiple clients. The default `expiresAt` is 7 days from `issuedAt`; servers MAY shorten this by re-fetching more aggressively but MUST NOT extend it beyond what the AttestSeal API returned.

### 9.3 CDN edge

The `attestseal-x402` Cloudflare Worker template (section 10) caches per-domain attestations at the edge with the `expiresAt` value as the cache TTL. A popular merchant fronted by Cloudflare will cause exactly one origin fetch per (Cloudflare PoP * 7 days * domain).

## 10. Reference implementations

| Implementation | Language / runtime | Path |
|---|---|---|
| Python middleware (FastAPI / Flask / aiohttp) | Python 3.10+ | `sdk/x402/attestseal_x402/server.py` |
| Python client verifier (httpx / aiohttp) | Python 3.10+ | `sdk/x402/attestseal_x402/client.py` |
| Cloudflare Worker template | TypeScript | `deploy/cloudflare-worker-x402/` |
| TypeScript client verifier | TypeScript | (TODO post-launch) |

## 11. Security considerations

### 11.1 Header injection

Step 3 of section 8 (domain match) prevents an attacker from copying a legitimate AttestSeal attestation for `goodmerchant.com` into a 402 response from `evilsite.com`. The signature covers the domain field; the client checks it against the URL host.

### 11.2 Replay across endpoints on the same domain

The signature does not bind to the URL path. An attestation valid for `merchant.com/checkout` is also valid for `merchant.com/another-resource`. This is by design: AttestSeal scores domains, not endpoints, and an agent should treat all of `merchant.com` as the same trust unit.

### 11.3 Replay after revocation

AttestSeal does not currently support attestation revocation prior to `expiresAt`. The 7-day default expiry bounds the worst case: an attestation issued before a domain was compromised continues to verify until it expires. Mitigations:

- Servers SHOULD re-fetch attestations more often than the 7-day default for high-risk merchants. The `attestseal-x402` middleware exposes a `cache_ttl` parameter for this.
- AttestSeal MAY introduce short-lived attestations (e.g., 1h `expiresAt`) for merchants in a "watching" state; this is a server-side decision invisible to the protocol.
- Future versions of this spec may add revocation via the DID document's `assertionMethod` constraints. Out of scope for v0.1.

### 11.4 Key rotation

When the `did:web:attestseal.com` DID document rotates the signing key, old attestations signed by the prior key continue to verify until their `expiresAt` because the prior verification method remains in the DID's `assertionMethod` set with a `revoked` timestamp. New attestations are signed under the new key. Clients with a 24h DID cache may briefly fail verification during rotation; the section 8 fallback rule handles this.

### 11.5 Trust-on-first-use of the issuer DID

The first time an agent fetches `https://attestseal.com/.well-known/did.json`, it relies on TLS to authenticate the response. AttestSeal serves this URL behind Cloudflare with a publicly-CT-logged certificate. A future version of this spec may add DID-document pinning or out-of-band publication (e.g., via blockchain anchoring) for clients that need stronger assurance.

### 11.6 Information leakage

The `X-AttestSeal-*` headers do not leak any sensitive information about the agent: they are server-issued static headers attached to a 402 response. The agent's IP, User-Agent, and other request metadata are not communicated to AttestSeal during the verification flow (step 5 is a public DID document fetch over Cloudflare; AttestSeal does not see the agent's request).

## 12. Example response

A complete 402 response from an x402-aware merchant `widgets.example` charging $0.10:

```http
HTTP/1.1 402 Payment Required
Content-Type: application/json
Accept-Payment: x402; scheme=base-usdc; amount=0.10
X-AttestSeal-Issuer: did:web:attestseal.com
X-AttestSeal-Domain: widgets.example
X-AttestSeal-Score: 78
X-AttestSeal-Recommendation: PROCEED
X-AttestSeal-Confidence: high
X-AttestSeal-Assurance-Basis: earned_proceed
X-AttestSeal-Issued-At: 2026-05-02T14:00:00Z
X-AttestSeal-Expires-At: 2026-05-09T14:00:00Z
X-AttestSeal-Scoring-Model: attestseal-v1.5.1-weights
X-AttestSeal-Signature: MAbCdEf...
X-AttestSeal-Key-Id: did:web:attestseal.com#signing-key-1
X-AttestSeal-Site-Category: consumer
X-AttestSeal-Parent-Floor-Inherited: false
X-AttestSeal-Agent-Policy-Hint: proceed_earned

{
  "scheme": "x402",
  "amount": "0.10",
  "currency": "USD",
  "destination": "0xabc..."
}
```

## 13. Versioning

This document uses semantic versioning (`MAJOR.MINOR.PATCH`). Major-version bumps are reserved for breaking changes to the canonical signing input or required-header set. Minor bumps add optional headers or extend value enums. Patch bumps are editorial.

The current version is reflected in the `X-AttestSeal-Spec-Version` response header (optional). Clients SHOULD ignore this header but MAY record it for telemetry.

## 14. IANA / registry considerations

This spec defines headers under the deprecated `X-` prefix. For wider interoperability the production names may move to `Attestseal-*` (no `X-` per RFC 6648) once the spec stabilizes. Until then, the `X-AttestSeal-*` set is canonical.

## 15. Open questions

- Should `X-AttestSeal-Domain` allow wildcards (e.g., `*.example.com`) to support multi-domain merchants signing once?
- Should `X-AttestSeal-Signature` migrate to JWS detached form for easier interop with existing JOSE tooling?
- Is a 7-day default `expiresAt` correct for all merchant categories, or should `tenant_platform_earned` attestations expire faster?

Comments welcome at `https://github.com/AttestSeal/attestseal/issues` or via the Coinbase x402 GitHub Discussion.

---

## Appendix A: Verification pseudocode

```python
def verify(headers, request_url):
    required = ["X-AttestSeal-Issuer", "X-AttestSeal-Domain", "X-AttestSeal-Score",
                "X-AttestSeal-Recommendation", "X-AttestSeal-Confidence",
                "X-AttestSeal-Assurance-Basis", "X-AttestSeal-Issued-At",
                "X-AttestSeal-Expires-At", "X-AttestSeal-Scoring-Model",
                "X-AttestSeal-Signature", "X-AttestSeal-Key-Id"]
    if any(h not in headers for h in required):
        return None  # caller falls back to API

    if headers["X-AttestSeal-Domain"] != urlparse(request_url).hostname:
        return False

    if parse_rfc3339(headers["X-AttestSeal-Expires-At"]) < now():
        return None  # caller falls back to API

    if headers["X-AttestSeal-Issuer"] not in ALLOWED_ISSUERS:
        return False

    did_doc = fetch_did_document(headers["X-AttestSeal-Issuer"])  # 24h cache
    pubkey = did_doc.find_key(headers["X-AttestSeal-Key-Id"])
    if pubkey is None:
        return False

    canonical = json.dumps({
        "domain": headers["X-AttestSeal-Domain"],
        "issuer": headers["X-AttestSeal-Issuer"],
        "issuedAt": headers["X-AttestSeal-Issued-At"],
        "expiresAt": headers["X-AttestSeal-Expires-At"],
        "trustScore": int(headers["X-AttestSeal-Score"]),
        "recommendation": headers["X-AttestSeal-Recommendation"],
        "confidence": headers["X-AttestSeal-Confidence"],
        "assuranceBasis": headers["X-AttestSeal-Assurance-Basis"],
        "scoringModel": headers["X-AttestSeal-Scoring-Model"],
        "siteCategory": headers.get("X-AttestSeal-Site-Category"),
        "cautionReason": headers.get("X-AttestSeal-Caution-Reason"),
        "parentCompany": headers.get("X-AttestSeal-Parent-Company"),
        "parentFloorInherited": headers.get("X-AttestSeal-Parent-Floor-Inherited", "false") == "true",
        "agentPolicyHint": headers.get("X-AttestSeal-Agent-Policy-Hint", "do_not_pay"),
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")

    digest = sha256(canonical).digest()
    sig = multibase_decode(headers["X-AttestSeal-Signature"])
    return ed25519_verify(pubkey, digest, sig)
```

## Appendix B: Changelog

- **0.1.0-draft (2026-05-02)** -- Initial draft, derived from the v1.5.1 AttestSeal scoring model.
