# GitHub Discussion submission: coinbase/x402

This document is the prepared submission for posting at
`https://github.com/coinbase/x402/discussions/new`. Category: "Show and tell"
or "Ideas" depending on what the maintainers prefer at submission time.

---

## Title

**Proposal: pre-payment trust attestation headers for x402 (X-AttestSeal-* spec, reference impl)**

## Body

Hi x402 team and community,

I'm Allen, working on AttestSeal -- an independent trust attestation layer
for AI agent commerce. Over the last year, we've built a million-domain
trust dataset (signed Ed25519 attestations under `did:web:attestseal.com`,
versioned scoring at `attestseal-v1.5.1-weights`, dataset publishing to
HuggingFace under CC-BY-4.0), and as we get ready to publish for general
use, we wanted to put a small protocol proposal in front of this community
before anything else.

### The proposal in one paragraph

x402 solves "how does an agent pay?" Trust ("should an agent pay?") is left
to a separate API call -- typically `GET /v1/check/<merchant>` against
whatever trust service the agent picked. We propose attaching a
cryptographically signed trust attestation directly to the 402 response via
a new set of `X-AttestSeal-*` HTTP response headers, so the agent can
verify trust locally with zero additional round-trips. The headers are
issuer-agnostic (any DID-method-web issuer can be allow-listed); the
signature is bound to the merchant domain so an attestation cannot be
copied between merchants; and the protocol degrades gracefully -- if
headers are absent or signatures fail, the agent falls back to the
direct API call. No change required to the existing x402 payment fields.

### What it looks like

```http
HTTP/1.1 402 Payment Required
Accept-Payment: x402; scheme=base-usdc; amount=0.10
X-AttestSeal-Issuer: did:web:attestseal.com
X-AttestSeal-Domain: merchant.example
X-AttestSeal-Score: 78
X-AttestSeal-Recommendation: PROCEED
X-AttestSeal-Confidence: high
X-AttestSeal-Assurance-Basis: earned_proceed
X-AttestSeal-Issued-At: 2026-05-02T14:00:00Z
X-AttestSeal-Expires-At: 2026-05-09T14:00:00Z
X-AttestSeal-Scoring-Model: attestseal-v1.5.1-weights
X-AttestSeal-Signature: M4OqKvuOiu...
X-AttestSeal-Key-Id: did:web:attestseal.com#signing-key-1
X-AttestSeal-Site-Category: consumer
X-AttestSeal-Parent-Floor-Inherited: false
X-AttestSeal-Agent-Policy-Hint: proceed_earned
```

The agent verifies the signature against the issuer's DID document
(`https://attestseal.com/.well-known/did.json`, cached for 24 hours), checks
domain match and freshness, and applies policy keyed on `assuranceBasis`.
End-to-end verification is one Ed25519 verify (~0.4 ms) and zero network
round-trips when the DID document is cached.

### Resources

- **Spec**: [github.com/AttestSeal/attestseal/blob/main/spec/X-ATTESTSEAL-HEADERS.md](https://github.com/AttestSeal/attestseal/blob/main/spec/X-ATTESTSEAL-HEADERS.md)
- **Reference implementation (Python)**: [`attestseal-x402` on PyPI](https://pypi.org/project/attestseal-x402/) (and [`sdk/x402/`](https://github.com/AttestSeal/attestseal/tree/main/sdk/x402) in repo) -- FastAPI / Flask / aiohttp middleware to stamp; httpx / aiohttp verifier to check
- **Cloudflare Worker template**: [`deploy/cloudflare-worker-x402/`](https://github.com/AttestSeal/attestseal/tree/main/deploy/cloudflare-worker-x402/) -- one-click deploy for any merchant fronted by Cloudflare
- **Live demo**: [demo.attestseal.com/generate](https://demo.attestseal.com/generate) -- a 402-issuing endpoint with the headers attached
- **Background reading**: [The Trust Gap in Agent Commerce](https://attestseal.com/blog/trust-gap-agent-commerce/) explains the strategic case; [x402 and the New Role of Payment Protocols](https://attestseal.com/blog/x402-payment-protocol-trust-layer/) explains the technical case

### Why we're proposing this here

1. The cement is wet. x402 is a young protocol and patterns aren't set yet. We'd much rather argue about header naming and canonical-signing form *now* than after they've been baked into a hundred merchant deployments.
2. We don't think AttestSeal should be the only issuer. The DID-based issuer field means another trust attester can stand up `did:web:competitor.example` and ship `X-Competitor-*` headers using the same mechanism. We'd love to see a multi-issuer ecosystem; we're starting the spec, not claiming the slot.
3. We deliberately do not handle payments. AttestSeal is independent of any payment rail -- the same x402 attestation works for AP2, MPP, Skyfire, or whatever ships next. We see this as complementary to x402, not in tension with it.

### What we'd like feedback on

The full spec has 15 sections; we're particularly interested in feedback on:

- **Header naming**: should we move off the deprecated `X-` prefix to `Attestseal-*` per RFC 6648? We picked `X-AttestSeal-*` for v0.1 because the `X-` prefix is more recognizable for non-IETF audiences, but we're open to switching.
- **Canonical signing form**: we use sorted-keys JSON + SHA-256, then Ed25519 over the digest. Alternative is JWS detached form for easier interop with existing JOSE tooling. Trade-off discussion welcome.
- **Wildcard domains**: should `X-AttestSeal-Domain` allow `*.example.com` for multi-domain merchants? We currently require an exact match. The wildcard case is real (e.g., a Shopify Plus merchant with several country-code TLDs) but the security implications need careful thought.
- **Cache TTL**: 7-day default `expiresAt` for attestations. Is that the right number for x402 use? We could shorten if the community would prefer fresher attestations at the cost of more origin fetches.

### What we're explicitly NOT proposing

- We are not asking for x402 to require these headers. They are optional. An x402 server that doesn't ship them works fine; an agent that doesn't verify them works fine. The spec degrades gracefully on both sides.
- We are not asking for x402 to bless AttestSeal as the canonical issuer. The spec is per-issuer; multiple issuers can co-exist, and agents authenticate per-issuer.
- We are not asking for x402 to add anything to its own canonical message format. Every change is in the response-header layer.

Happy to answer questions, take feedback, or rip this apart. The protocol gets better with adversarial review, and the ecosystem benefits from getting it right early.

Thanks for x402, by the way -- the moment HTTP 402 stopped being a placeholder and started being a real wire protocol, agent commerce became a real thing. We're trying to add the trust primitive that should sit alongside it.

-- Allen Lu
   AttestSeal, Inc.
   alu@attestseal.com
   github.com/AttestSeal/attestseal

---

## Notes for the human submitter (Allen)

- Submit at `https://github.com/coinbase/x402/discussions/new`. Pick category "Ideas" if available; otherwise "Show and tell."
- Tag whoever currently maintains the protocol (`@brendanedoyle`, `@bowlofeggs`, etc., based on recent commit history at submission time).
- Attach the spec PDF if discussions support PDF uploads, or just link to the markdown.
- Subscribe to the thread; respond within a business day on the first wave of feedback. The first 48 hours of community response set the tone.
- If maintainers ask for a PR against `coinbase/x402` itself rather than just a discussion, prepare a small PR adding `docs/extensions/X-AttestSeal-*.md` or similar.
