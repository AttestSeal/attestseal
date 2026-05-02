---
title: How to Read an AttestSeal Attestation
slug: reading-an-attestseal-attestation
date: 2026-05-02
author: Allen Lu
tags: [developer, technical, attestation, signature]
summary: Every AttestSeal response is a signed JSON document. This post walks through every field, what it means, and how to verify the signature in the language of your choice.
---

# How to Read an AttestSeal Attestation

If you are integrating AttestSeal into an agent, an x402-aware server, or any system that needs to make a payment decision based on trust, the unit of trust you are working with is the *attestation*: a signed JSON document with a known schema, a known signer, and a known verification procedure.

This post is a field-by-field walkthrough. We'll take a real response, explain what each field is for, and then show how to verify the signature in Python, TypeScript, and from a shell script.

## A complete attestation

Here is the actual response you would get from `GET https://api.attestseal.com/v1/check/amazon.com` today, abridged for readability:

```json
{
  "domain": "amazon.com",
  "checkedAt": "2026-05-02T14:00:00Z",
  "expiresAt": "2026-05-09T14:00:00Z",
  "trustScore": 90,
  "scoringModel": "attestseal-v1.5.1-weights",
  "recommendation": "PROCEED",
  "confidence": "high",
  "cautionReason": null,
  "assuranceBasis": "well_known_tranco_anchor",
  "agentPolicyHint": "proceed_normal",
  "siteCategory": "consumer",
  "parentCompany": null,
  "parentFloorInherited": false,
  "brandTier": "well_known",
  "crawlability": "ok",
  "flags": ["WELL_KNOWN_BRAND", "CONTENT_UNSCORABLE", "ANCHOR_ONLY"],
  "signals": {
    "domainAge": { "registeredDate": "1994-11-01", "band": "5+ years", "score": 100 },
    "ssl":       { "valid": true, "tlsVersion": "TLSv1.3", "hsts": true, "score": 100 },
    "dns":       { "spf": true, "dmarc": true, "dnssec": false, "caa": false, "score": 60 },
    "content":   { "privacyPolicy": false, "termsOfService": false, "contactInfo": false, "score": 0 },
    "reputation":{ "malware": false, "phishing": false, "spamListed": false, "score": 96 },
    "identity":  { "verified": false, "verificationTier": "automated", "score": 40 }
  },
  "reputationSources": {
    "tranco": { "checked": true, "rank": 24, "matched": false },
    "spamhaus_dbl": { "checked": true, "matched": false },
    "surbl": { "checked": true, "matched": false },
    "urlhaus": { "checked": true, "matched": false },
    "google_safe_browsing": { "checked": true, "matched": false }
  },
  "jurisdiction": {
    "country": "US",
    "legalFramework": "us_consumer_protection",
    "crossBorderRisk": "low",
    "disputeResolution": "available",
    "kycAvailable": true
  },
  "checklist": [
    { "category": "Email Security", "item": "DNSSEC", "status": "fail", "fix": "Enable DNSSEC at your registrar." },
    { "category": "Email Security", "item": "CAA record", "status": "fail", "fix": "Add a CAA record at your DNS provider." }
  ],
  "checklistSummary": { "total": 14, "passing": 12, "failing": 2, "improvable": 0 },
  "signature": "M4OqKvuOiuv8...EfAg==",
  "signatureKeyId": "did:web:attestseal.com#signing-key-1",
  "issuer": "did:web:attestseal.com"
}
```

That's a lot of fields. They fall into five families. Let's go through them.

## Family 1: identity

| Field | Purpose |
|---|---|
| `domain` | The host this attestation is about. The signature covers this; an attacker cannot move an attestation between domains. |
| `issuer` | The DID that signed this attestation. Today there's exactly one: `did:web:attestseal.com`. |
| `signatureKeyId` | The DID URL of the specific verification key used. The DID document at `attestseal.com/.well-known/did.json` lists every valid key. |
| `signature` | Multibase-encoded Ed25519 signature over the canonical signable form (more on this in §"How to verify"). |
| `checkedAt` / `expiresAt` | When the attestation was minted and when it goes stale. Default validity is 7 days. |

Two things to know about this family. First, the signature covers exactly the fields you need to make a decision (`domain`, `recommendation`, `trustScore`, `assuranceBasis`, etc.) — *not* the entire response. Decorative fields like `checklist` are not signed and may differ between cached and fresh responses. The fields that are signed are listed below in "Canonical signable form."

Second, the verification key is referenced by ID, not embedded. This is how key rotation works: when AttestSeal rotates the signing key, the old key remains in the DID document with a `revoked` timestamp, so attestations issued before the rotation continue to verify until they expire. Clients with a cached DID document might briefly fail verification during a rotation; the protocol's fallback rule is "fall back to a fresh API call" in that case.

## Family 2: the recommendation surface

| Field | Purpose |
|---|---|
| `trustScore` | An integer 0-100 summarizing the weighted signal evidence. Useful for histograms and dashboards; agents should not threshold on the raw number. |
| `recommendation` | `PROCEED`, `CAUTION`, or `DENY`. The agent-actionable verdict. |
| `confidence` | `high`, `medium`, or `low`. How complete the evidence is. A high-confidence CAUTION means the signals are weak; a low-confidence CAUTION means we couldn't gather enough signals. |
| `cautionReason` | Only set when `recommendation == "CAUTION"`. Values: `weak_signals`, `incomplete_evidence`, `new_domain`, `infrastructure`, `tenant_platform`, `tracking`. Tells the agent *why*. |
| `assuranceBasis` | The basis on which the recommendation rests. Critical for transaction-limit policy. See [Public Legitimacy Is Not Merchant Trust](public-legitimacy-vs-merchant-trust.md). |
| `agentPolicyHint` | An explicit "what to do" string for agents that don't want to derive policy from the basis. E.g., `proceed_normal`, `proceed_with_platform_context`, `do_not_pay_tracking`. |

The right way to use these together is: **recommendation gates the action; assuranceBasis sets the limit; cautionReason explains the friction.** A high-confidence PROCEED with `well_known_tranco_anchor` lets the agent send up to a few dollars without prompting the user. A medium-confidence CAUTION with `cautionReason=incomplete_evidence` is the agent saying "I tried to verify this but the merchant blocked my crawler; ask the user whether to proceed anyway." A DENY with `MALWARE_DETECTED` in flags should never reach the user as a question.

## Family 3: the registry layer

| Field | Purpose |
|---|---|
| `siteCategory` | `consumer`, `tenant_platform`, `infrastructure`, `tracking`, or `api_service`. The shape of the domain. |
| `parentCompany` | Human-readable parent name when the domain matches our `parent_companies` registry. `null` for ordinary consumer domains. |
| `parentFloorInherited` | `false` everywhere today. Cryptographic confirmation that no parent-rank inheritance applied to this score; the domain earned its trust on own signals. |
| `brandTier` | `"well_known"` or `"scored"`. Set to `well_known` when the brand-anchor floor lifted the score. |
| `crawlability` | `"ok"` or `"blocked"`. `blocked` means our crawler couldn't fetch the homepage; the score was computed on the remaining five signals and the `CONTENT_UNSCORABLE` flag was raised. |

The registry layer matters because it tells the agent the *shape* of the domain. A PROCEED for `vercel.app` and a PROCEED for `amazon.com` are both PROCEEDs, but the `siteCategory` field tells the agent that one of them is a tenant platform (where the actual merchant might be a tenant `alice-store.vercel.app`) and the other is a consumer brand. That's policy-relevant context the agent should not have to re-derive.

`parentFloorInherited=false` is a deliberately boring field. Today it is always `false`. We expose it so that if a future version of the spec ever introduces parent-rank inheritance for first-party subdomains, agents can rely on the *absence* of `false` to mean "this score got a lift from somewhere I should look at." Until then, the field is a guarantee.

## Family 4: the signal evidence

The `signals` object contains the raw evidence, broken down by collector:

```json
"signals": {
  "domainAge":  { "registeredDate": "1994-11-01", "band": "5+ years", "score": 100 },
  "ssl":        { "valid": true, "tlsVersion": "TLSv1.3", "hsts": true, "score": 100 },
  "dns":        { "spf": true, "dmarc": true, "dnssec": false, "caa": false, "score": 60 },
  "content":    { "privacyPolicy": false, "termsOfService": false, "contactInfo": false, "score": 0 },
  "reputation": { "malware": false, "phishing": false, "spamListed": false, "score": 96 },
  "identity":   { "verified": false, "verificationTier": "automated", "score": 40 }
}
```

Each signal has a `score` (0-100) and one or more evidence fields specific to the collector. The composite trust score is a weighted sum:

```
trustScore = 0.30 * reputation.score
           + 0.25 * identity.score
           + 0.17 * content.score
           + 0.10 * domainAge.score
           + 0.10 * ssl.score
           + 0.08 * dns.score
```

Plus the brand-anchor floor and PROCEED-threshold-with-safety-gate logic on top. (Full details in the [scoring spec](../../spec/SCORING-V1.4.md), to be updated for v1.5.1.)

The point of exposing the signals is auditability. An agent that disagrees with our score can look at the signals and see *which* one we disagreed about. A merchant who wants to improve their score can look at the signals and see *exactly* what to fix. We don't ship "the score is what it is, trust us" responses; we ship the receipts.

## Family 5: meta and operations

The remaining fields:

| Field | Purpose |
|---|---|
| `scoringModel` | The versioned model identifier (`attestseal-v1.5.1-weights`). When we change the model, this string changes too, and old attestations remain valid under their original model. |
| `flags` | Boolean signals that aren't worth their own field: `WELL_KNOWN_BRAND`, `CONTENT_UNSCORABLE`, `NO_SSL`, `NEW_DOMAIN`, `MALWARE_DETECTED`, etc. |
| `reputationSources` | Per-source check state: which blocklists were queried, what they returned. Distinguishes "checked clean" from "didn't check." |
| `jurisdiction` | Country / legal framework / cross-border risk / dispute-resolution availability for the domain. Useful for agents that have policies tied to merchant jurisdiction. |
| `checklist` | Actionable fix items for the merchant. Mostly relevant to the merchant dashboard; agents can ignore it. |

## How to verify

The signature covers a canonical signable form derived from the response. Here's the procedure in Python:

```python
import json, hashlib, base64
import nacl.signing, nacl.encoding, httpx

def fetch_did_doc(issuer_did="did:web:attestseal.com"):
    # did:web:attestseal.com -> https://attestseal.com/.well-known/did.json
    host = issuer_did.removeprefix("did:web:")
    return httpx.get(f"https://{host}/.well-known/did.json").json()

def public_key_from_did(did_doc, key_id):
    for vm in did_doc.get("verificationMethod", []):
        if vm["id"] == key_id:
            mb = vm["publicKeyMultibase"]   # 'M' + base64pad
            assert mb[0] == "M"
            return nacl.signing.VerifyKey(base64.b64decode(mb[1:]))
    raise ValueError(f"key {key_id} not found in DID document")

def verify(response):
    signable = {
        "domain":         response["domain"],
        "signals":        response["signals"],
        "flags":          response["flags"],
        "trustScore":     response["trustScore"],
        "scoringModel":   response["scoringModel"],
        "recommendation": response["recommendation"],
        "confidence":     response.get("confidence"),
        "cautionReason":  response.get("cautionReason"),
        "assuranceBasis": response.get("assuranceBasis"),
        "agentPolicyHint":response.get("agentPolicyHint"),
        "siteCategory":   response.get("siteCategory"),
        "parentCompany":  response.get("parentCompany"),
        "parentFloorInherited": response.get("parentFloorInherited", False),
        "reputationSources":    response.get("reputationSources"),
    }
    canonical = json.dumps(signable, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(canonical).digest()

    sig_mb = response["signature"]
    assert sig_mb[0] in ("M", "z")  # 'z' is legacy
    sig_bytes = base64.b64decode(sig_mb[1:])

    did_doc = fetch_did_doc(response["issuer"])  # cache this for 24h in production
    pubkey = public_key_from_did(did_doc, response["signatureKeyId"])

    try:
        pubkey.verify(digest, sig_bytes)
        return True
    except nacl.exceptions.BadSignatureError:
        return False
```

In TypeScript:

```typescript
import { webcrypto } from 'crypto';
import nacl from 'tweetnacl';

async function fetchDidDoc(issuerDid: string) {
  const host = issuerDid.replace(/^did:web:/, '');
  return (await fetch(`https://${host}/.well-known/did.json`)).json();
}

function publicKeyFromDid(didDoc: any, keyId: string): Uint8Array {
  const vm = didDoc.verificationMethod.find((v: any) => v.id === keyId);
  if (!vm) throw new Error(`key ${keyId} not found`);
  const mb = vm.publicKeyMultibase;
  if (mb[0] !== 'M') throw new Error('expected M-prefix multibase');
  return Uint8Array.from(Buffer.from(mb.slice(1), 'base64'));
}

async function verify(response: any): Promise<boolean> {
  const signable = {
    domain: response.domain,
    signals: response.signals,
    flags: response.flags,
    trustScore: response.trustScore,
    scoringModel: response.scoringModel,
    recommendation: response.recommendation,
    confidence: response.confidence ?? null,
    cautionReason: response.cautionReason ?? null,
    assuranceBasis: response.assuranceBasis ?? null,
    agentPolicyHint: response.agentPolicyHint ?? null,
    siteCategory: response.siteCategory ?? null,
    parentCompany: response.parentCompany ?? null,
    parentFloorInherited: response.parentFloorInherited ?? false,
    reputationSources: response.reputationSources ?? null,
  };
  const canonical = JSON.stringify(signable, Object.keys(signable).sort());
  const digest = new Uint8Array(
    await webcrypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical))
  );

  const sigMb = response.signature;
  if (sigMb[0] !== 'M' && sigMb[0] !== 'z') return false;
  const sig = Uint8Array.from(Buffer.from(sigMb.slice(1), 'base64'));

  const didDoc = await fetchDidDoc(response.issuer);
  const pubkey = publicKeyFromDid(didDoc, response.signatureKeyId);

  return nacl.sign.detached.verify(digest, sig, pubkey);
}
```

From the shell, using `jq` and `openssl`:

```bash
RESP=$(curl -s https://api.attestseal.com/v1/check/amazon.com)
DID=$(curl -s https://attestseal.com/.well-known/did.json)
KEY_ID=$(echo "$RESP" | jq -r .signatureKeyId)
PUBKEY_MB=$(echo "$DID" | jq -r --arg id "$KEY_ID" '.verificationMethod[] | select(.id==$id) | .publicKeyMultibase')
echo "key reference: $KEY_ID"
echo "key (multibase): $PUBKEY_MB"
# Reconstruct the canonical signable, hash, decode signature, verify -- left as
# an exercise for the reader, or just use the Python or TypeScript SDK.
```

The shell version is illustrative; in real deployments use the SDK. The Python `attestseal-x402` package (`pip install attestseal-x402`) wraps all of this in `attestseal_x402.client.verify(response)` and handles DID-document caching automatically.

## Common verification failures

| Symptom | Likely cause |
|---|---|
| Signature verifies but `parentFloorInherited` is `true` | Future-proofing field; today this should never happen, and an agent seeing it should treat the attestation as suspicious. |
| Signature fails on what looks like a valid response | Canonical signable form mismatch. Most often the caller is including a field that isn't signed (like `checklist`) or excluding a field that is (like `reputationSources`). The signed list is the one in the Python example above. |
| DID document fetch returns 404 | Ensure you are fetching `https://attestseal.com/.well-known/did.json` (not `attestseal.com/.well-known/did:web:attestseal.com.json`). The `did:web:` scheme always maps to the `.well-known/did.json` path. |
| `signatureKeyId` not found in DID document | Either you have a stale DID document (re-fetch) or the attestation is signed by a key the issuer no longer publishes (very rare; usually means a long-cached attestation that survived a key rotation). |

## Summary

An AttestSeal attestation is a signed JSON document with five field families: identity (who signed it and for what), recommendation (PROCEED/CAUTION/DENY plus basis), registry layer (shape of the domain), signal evidence (raw inputs), and meta. The signature covers exactly the fields the agent needs to make a payment decision; verification is local once the DID document is cached. The SDKs handle this for you, but the protocol is simple enough that you can implement it from scratch in a couple hundred lines if you want to.

Read the response. Verify the signature. Apply policy keyed on `assuranceBasis`. That's the whole job.

---

*Reference: [`X-AttestSeal-*` Header Specification](../../spec/X-ATTESTSEAL-HEADERS.md) for the same schema delivered alongside an x402 402 response. SDK: [`attestseal-x402`](https://github.com/AttestSeal/attestseal/tree/main/sdk/x402) on PyPI (post-launch).*
