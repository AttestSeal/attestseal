---
title: Why AttestSeal Doesn't Handle Payments
slug: why-attestseal-doesnt-handle-payments
date: 2026-05-02
author: Allen Lu
tags: [strategy, neutrality, business-model, conflicts-of-interest]
summary: We could have built a payment processor with a built-in trust score. We deliberately didn't. Neutrality is not a compromise; it is the product.
---

# Why AttestSeal Doesn't Handle Payments

The most common pitch correction we hear from investors and partners goes something like: "Why don't you also process the payment? You'd capture so much more value per transaction."

It is a reasonable question. The economic argument is real: a trust attestation per transaction is worth fractions of a cent; a payment processed per transaction is worth basis points of the transaction value. The same agent infrastructure that needs trust attestations also needs to send money. Owning both surfaces sounds, on paper, like a better business.

We have considered this carefully. We are not going to do it. This post is about why.

## The structural conflict

Every payment-rail company that scores its own merchants has, on every score, a small but unavoidable conflict.

Their revenue grows when payments happen. Their reputation grows when fraud doesn't. Both are real pressures. The score that maximizes revenue is the score that lets the most merchants through. The score that maximizes safety is the score that turns the most merchants away. There is no value of the dial that resolves both pressures simultaneously, and over the long run, the dial bends toward whichever pressure is felt more acutely in any given quarter.

This is not a moral failing of the people involved. It is geometry. A company that processes payments has shareholders who measure quarterly revenue. The shareholders care about transaction volume. Transaction volume goes up when more transactions clear. The trust score is the system that controls how many transactions clear. Over time, the trust score becomes a controllable revenue lever. The people running it might be saints, but the institution itself has a thumb on the scale.

Stripe Trust Score, Coinbase Verified, PayPal Risk — none of these are bad systems. They are *good systems with structural conflicts*. They are very useful internally to the rail that owns them. They are not the right primitive for an *open ecosystem* of agent commerce, where every agent on every platform needs to apply the same trust assessment to every merchant on every rail.

The right primitive in an open ecosystem is independence.

## How we know this is the right shape

Look at how this played out before, in adjacent industries.

In credit cards, the rails (Visa, Mastercard, Amex) emerged in the 1950s and 60s. By the 1990s, electronic commerce demanded fraud scoring at scale, and the rails *could not credibly own it*. So a parallel ecosystem of independent fraud-scoring vendors emerged: FICO, LexisNexis Risk Solutions, Sift, Forter, Riskified. Their product is precisely "we tell you who not to trust, and our customer is not the merchant." Today they are a multi-billion-dollar industry. The credit-card rails are happy this industry exists; it lets them stay focused on processing rails without getting caught between merchant lobby pressure and fraud-victim lawsuits.

In domain registration, the registrars (GoDaddy, Namecheap, etc.) emerged as commercial businesses. By the 2000s, the security ecosystem demanded trust signals about which domains were malicious, and the registrars *could not credibly own it*. So a parallel ecosystem emerged: Spamhaus, SURBL, URLhaus, the various reputation feeds. Their product is "we tell you who is bad," and their customer is not the registrar. The registrars are again happy with this. They could not have built it themselves credibly.

In code distribution, the package managers (npm, PyPI) emerged. By the late 2010s, the security ecosystem demanded supply-chain trust, and the package managers *could not credibly own it*. So a parallel ecosystem emerged: Snyk, Socket.dev, Phylum, Sigstore. Their product is "we tell you which packages are compromised," and their customer is not the package manager. Same pattern.

The pattern, three times in three industries: rails come first, ecosystem demands trust, rails are structurally unable to credibly own trust, an independent layer emerges and becomes large.

Agent commerce is going to follow this pattern. The only question is whether the independent layer that emerges is well-engineered, open-protocol, and built with the failure modes of the previous three industries in mind, or whether it is whatever the first VC-funded "merchant verification API" decides to become.

We are trying to be the well-engineered version. To do that we have to actually be neutral, not just claim neutrality on a slide deck. Neutrality means not handling the payment, not taking a cut of the transaction, not having merchant relationships that could bias the score, not having investor pressure to inflate any particular merchant's tier. Every one of those constraints is a constraint we accept on purpose.

## The architecture that follows from neutrality

Neutrality is not a slogan; it implies a specific architecture.

**We never see the payment.** The agent verifies our attestation locally and decides whether to pay. The actual payment goes from the agent's wallet to the merchant's wallet via x402, AP2, MPP, or whichever rail. AttestSeal is not on the path. We don't see who paid whom how much. We can't, because we are not in the network.

**We don't have payment-rail integrations.** We don't have a "preferred partner" tier with Coinbase or Stripe. We don't have revenue-share with any payment processor. Our SDK works with x402 today, AP2 tomorrow, and whatever ships in 2027 the day after. The protocol surface is rail-agnostic, which is only credible if the company itself doesn't have rail-specific deals.

**Our customer is the agent, not the merchant.** Merchants can register with us to upgrade their assurance basis (free for the basic tier; paid for KYC). But the *primary* customer is the developer of the agent that needs trust answers. The agent pays — directly via API access, indirectly via the SDK — for verification. Merchants pay only for the optional verified tiers, and even then the score is ours, not theirs. A merchant who pays for KYC and then turns out to be a bad actor gets their KYC tier revoked the moment we have evidence; the payment doesn't buy a tier they don't meet.

**We publish the dataset.** Every domain we score, the score, the basis, the signals. CC-BY-4.0. The same data we use internally is the same data anyone can audit, replicate, or build on. The trust attestation can be verified offline against the published dataset by anyone who wants to. This is the strongest possible commitment to neutrality: we are saying "if you don't trust our API, here is the raw evidence; check the math yourself."

**We sign every attestation.** Ed25519 over a canonical signable form. An attacker who wants to show an agent a forged "AttestSeal verified" badge has to forge an Ed25519 signature, which they cannot. An attestation issued by AttestSeal cannot be tampered with after issuance, even by AttestSeal. This is what cryptographic neutrality looks like: the issuer is constrained by mathematics, not by good intentions.

**The protocol is open.** The header spec, the canonical signing form, the DID resolution flow — all published, all open. Another trust attester can stand up `did:web:competitor.example` tomorrow and ship `X-Competitor-*` headers using exactly the same mechanism. Agents authenticate per-issuer; multiple issuers can co-exist. We expect (and welcome) this. A market with one trust attester is fragile in exactly the way a market with one fraud-scoring vendor would be fragile. We want competition.

## The business model that supports this

So if we don't handle payments and we publish the dataset and the protocol is open, what is the business?

Three layers.

**Layer 1: API consumption.** Agent runtimes that want sub-200ms verification at scale call our API. The API is rate-limited at 60 requests per minute on the free tier; high-volume agents pay for higher rate limits. This is a developer-tools business with the unit economics of any API: low per-call cost, high gross margin at scale, growth tied to the growth of the agent ecosystem itself.

**Layer 2: Merchant verification.** Merchants who want to upgrade their tier pay for KYC. This is a self-service flow with a real cost (we partner with Stripe Identity / Onfido / Jumio for the actual ID verification, which is the largest variable cost). Merchants pay because being `kyc_verified` unlocks higher transaction limits in agents that key policy on basis. The price reflects the cost of the underlying KYC, plus a margin for our continuous-monitoring overhead.

**Layer 3: Premium signed evidence bundles.** For high-value transactions or compliance use cases, we offer signed, time-stamped, court-admissible attestations that include richer evidence than the public dataset. This is enterprise-grade: priced per attestation, sold to fraud-investigation, AML, and KYC teams that need provable due-diligence trails.

None of these layers requires us to handle the payment. None creates the merchant-revenue conflict that breaks rail-owned trust scoring. The dataset stays free, the public scoring stays free, the protocol stays open. We make money on the work that is genuinely ours: running the crawl, maintaining the model, doing the KYC verification for the merchants who want it, providing the API uptime and the SDK ergonomics.

## The cost of neutrality

We have given up real things to be neutral.

We will never capture transaction-percentage revenue. The largest line item in agent commerce — the actual payment volume — is structurally not ours. A rail that processes $1B in agent payments at 30 basis points captures $3M in transaction fees. We cannot do that. Our entire revenue model is the much smaller "trust check" surface plus the optional KYC business.

We accept slower growth in exchange for credibility that compounds. A trust company that handles payments has higher peak revenue and lower long-term defensibility (because the conflict is always there, waiting to be discovered). A trust company that doesn't handle payments has lower peak revenue and higher long-term defensibility, because the absence of the conflict is observable on every transaction. We picked the second curve.

We will never partner with any payment rail in a way that creates conflict-of-interest pressure. This rules out a category of "preferred partner" deals that would generate near-term revenue and long-term reputation damage. We say no to those deals on purpose, even when the short-term math looks good.

These are real costs. They are the cost of being the neutral attestation layer rather than another payment company with a trust feature. We think the trade is worth it. The next decade of agent commerce will determine whether we were right.

---

*If you are an investor, partner, or merchant who wants to dig into the implications of this for your own business, [alu@attestseal.com](mailto:alu@attestseal.com). We answer.*

*Read also: [The Trust Gap in Agent Commerce](trust-gap-agent-commerce.md) for the broader market argument, and [Public Legitimacy Is Not Merchant Trust](public-legitimacy-vs-merchant-trust.md) for the policy distinction agents need to apply.*
