---
title: Public Legitimacy Is Not Merchant Trust
slug: public-legitimacy-vs-merchant-trust
date: 2026-05-02
author: Allen Lu
tags: [scoring, taxonomy, agent-policy, kyc]
summary: An AttestSeal recommendation of PROCEED tells you a domain is the real entity it appears to be. It does not tell you the operator has been bank-verified. The distinction matters more than it sounds, and we built the API to expose it explicitly.
---

# Public Legitimacy Is Not Merchant Trust

When an agent asks AttestSeal whether to trust `acme-widgets.com` and we return `PROCEED`, we are answering a specific question: is this domain almost certainly the real, established public entity it appears to be?

We are not answering: has the operator behind this domain been business-verified, identity-verified, bank-verified, or insured against chargebacks?

These two questions sound related. They feel like they should be the same question. They are not, and conflating them causes real failures in agent commerce. This post is about the distinction, why it matters, and how AttestSeal's response surface separates the two so an agent can apply the right policy to each.

## The two questions, separated

**Public legitimacy** asks: is this domain who it appears to be? Is `amazon.com` actually Amazon and not a typosquatted clone? Is `kohls.com` the real Kohl's department store and not a phishing kit run from a basement? Has this domain existed long enough, with a clean enough reputation, with valid enough infrastructure, that we can be confident it is what it presents itself as?

This is a question about identity in the public record. It is answerable from observable signals: WHOIS history, SSL chain, Tranco rank over time, reputation file across blocklists, content presence (does the homepage have a privacy policy and contact information?), DNS hygiene. Anyone with a crawler and a year of patience can answer it. AttestSeal's job is to do this at scale, sign the answer, and serve it in two milliseconds.

**Merchant trust** asks something stronger: is this operator someone you should send money to in exchange for goods or services? Have they been onboarded by a payment processor that verified their bank account? Are they covered by chargeback protection? Is there a real human you can sue if the goods don't arrive? Have they been insured? Are they incorporated in a jurisdiction with consumer-protection law you can invoke?

This is a question about commercial accountability. It is not answerable from observable signals. It requires the merchant to actively verify themselves to a trusted intermediary, hand over identity documents, link a bank account, and accept legal terms. Stripe's onboarding flow answers this question. Skyfire's KYAPay answers this question. AttestSeal's KYC tier answers this question, but only because we built a separate verification flow for it.

These two questions live on different sides of a fundamental architectural line: **public legitimacy can be observed from the outside; merchant trust requires the operator to opt in.**

## Why it matters in practice

An agent buying a $0.10 research credit from a top-Tranco news site is operating in the public-legitimacy regime. The agent does not need to know that the news site has been bank-verified. It needs to know that `nytimes.com` is actually The New York Times and not `n-y-times.com` set up yesterday. The cost of the error is small (you lose a dime) and the verification is structurally available from public signals.

An agent buying a $500 product from a Shopify merchant the agent has never heard of is operating in the merchant-trust regime. Public legitimacy is not enough. The merchant might be a real domain with valid SSL and a clean reputation file, but the agent is wiring real money to a real bank account, and the cost of the error is real money lost. The agent needs the merchant to have actively done verification work — submitted business docs, linked a bank, completed KYC — before the agent treats `PROCEED` as authorization to commit.

The same domain can have *the same observable signals* and produce *the same trust score* for both transactions. It is the *policy applied on top of the score* that should differ. And the agent can only apply the right policy if the response tells it what kind of trust it has.

## The taxonomy AttestSeal exposes

Every AttestSeal response carries an `assuranceBasis` field that names *why* the recommendation is what it is. The values are deliberately ladder-shaped:

| Basis | What it means | What it doesn't mean |
|---|---|---|
| `well_known_tranco_anchor` | This is the real public entity. Top-50K Tranco rank, valid SSL, clean reputation, 5+ years of domain age. The brand-anchor floor lifted the score. | The operator is bank-verified, KYC'd, or commercially accountable. |
| `earned_proceed` | The score crossed 70 on signal merit alone. SSL is valid, reputation is clean, content is present, no anchor was needed. | Anything more than the signals say. |
| `tenant_platform_earned` / `infrastructure_earned` / `api_service_earned` | Same as `earned_proceed`, but the domain is shaped like a tenant platform (vercel.app), infrastructure (cloudflare.com), or an API endpoint (api.openai.com). The `_earned` suffix tells the agent the score was earned, not inherited from the parent's reputation. | The agent should treat this as automatically equivalent to a known consumer brand. |
| `registered_proceed` | The operator completed AttestSeal registration, proved domain control, and submitted business fields (legal name, address, EIN/VAT, contact info) which we cross-referenced. | KYC has been performed. |
| `kyc_verified` | Government ID, business documents, bank link, and video call have all been completed. | (Nothing more; this is the highest tier.) |
| `tracking` | Domain is in our registry as ad/analytics infrastructure (e.g., `doubleclick.net`). Always blocked from PROCEED regardless of score. | (n/a, this is a refusal.) |
| `not_recommended` | Score below threshold or a safety flag fired. | (n/a, this is a refusal.) |

An agent that treats all PROCEED values as equivalent is making a category error. An agent that uses the basis to apply per-tier transaction limits is doing the right thing.

A reasonable default policy looks like:

```python
LIMITS_BY_BASIS = {
    "kyc_verified":             None,    # no per-transaction cap
    "registered_proceed":       50.00,
    "well_known_tranco_anchor": 5.00,    # top brands; small per-txn limit, no KYC
    "earned_proceed":           1.00,
    "tenant_platform_earned":   1.00,
    "infrastructure_earned":    1.00,
    "api_service_earned":       2.00,    # API endpoints common in agent commerce
    # tracking and not_recommended → don't pay
}
```

The exact numbers will be specific to the agent operator, the user's risk tolerance, and the kind of work the agent is doing. The point is that they should be specific to the basis, not collapsed into a single value for "PROCEED."

## Why we don't quietly upgrade the basis

We could, in principle, treat `well_known_tranco_anchor` as more or less equivalent to `kyc_verified` for top-Tranco brands and let agents stop worrying about the distinction. We deliberately do not.

The reason is that `well_known_tranco_anchor` answers a categorically different question than `kyc_verified`. It answers "who is this?" with high confidence. It does not answer "what happens when I send them $500 and the goods don't arrive?" An attacker who compromises a top-Tranco brand's TLS endpoint inherits the brand-anchor floor for the duration of the compromise. (We have safeguards: revocation flags downgrade the score immediately, and our short attestation TTL bounds the worst case to days, not months.) But the failure mode of compromise looks different from the failure mode of a registered, KYC'd merchant going bad — the legal recourse, insurance posture, and recovery path are not the same. Agents should be able to apply different policies to those two cases, which means the response has to expose the distinction explicitly.

Conflating them upgrades the cosmetic experience for top brands at the cost of erasing the policy surface for everyone else. We picked the policy surface.

## What this means for merchants

A consumer brand that wants `PROCEED` from AttestSeal usually doesn't have to do anything. If you are top-50K Tranco, valid SSL, five-plus years of domain age, no malware/phishing/spam in your reputation file, you already qualify and you already get `well_known_tranco_anchor`. We are not in the business of charging you to attest to facts that are publicly verifiable. This tier is permanently free.

A merchant that wants the higher-trust tiers — and the higher transaction limits agents will associate with them — registers with us. Registration is structured: legal business name, address, EIN/VAT, phone, email, social profiles. We cross-reference the fields against WHOIS, SSL certificate organization, public business registries, and your DMARC posture. Verified fields earn points; unverified fields do not. Once you've collected enough points, your basis upgrades to `registered_proceed`, and agents that apply higher limits to that tier start trusting you for more.

KYC is the next step beyond registration. We partner with identity-verification providers (Stripe Identity, Onfido, Jumio, depending on jurisdiction) to verify a real human, real business documents, a linked bank account, and a video confirmation. Merchants who complete this earn `kyc_verified`, which is the only tier that should be treated as merchant-grade trust by an agent.

The ladder gives every operator a path to higher trust. It also keeps the lower tiers honest about what they are and aren't. That is the design.

## What this means for agent developers

When you read an AttestSeal response, look at three fields together: `recommendation`, `assuranceBasis`, and `agentPolicyHint`. The recommendation tells you the answer to "should I proceed at all?" The basis tells you the *kind* of trust the recommendation rests on. The policy hint translates the basis into an explicit suggestion if you would rather not derive policy yourself.

If you are writing an agent that handles real money, the assuranceBasis is where your transaction-limit policy should hook. If you are writing a LangChain tool that just looks up trust scores, the recommendation alone is fine. If you are writing the next x402 reference client, you should probably surface the basis to your users so they can write their own policies.

The taxonomy is not arbitrary. Every line in the ladder corresponds to a real difference in the underlying evidence. Treating them as a single bit erases information that was carefully gathered and signed. Don't do that.

---

*See also: [Reading an AttestSeal Attestation](reading-an-attestseal-attestation.md) for a developer walkthrough of the signed response format, and the [`X-AttestSeal-*` Header Specification](../../spec/X-ATTESTSEAL-HEADERS.md) for how the basis is delivered alongside x402 payment challenges.*
