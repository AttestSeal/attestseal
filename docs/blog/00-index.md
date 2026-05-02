---
title: AttestSeal Launch Series
slug: launch-index
date: 2026-05-02
author: Allen Lu
tags: [launch, hub]
summary: A six-part series introducing AttestSeal, the trust gap in agent commerce, the x402 integration, and the policy taxonomy agents need to apply.
---

# AttestSeal Launch Series

We have spent a year building an independent trust attestation layer for AI agent commerce. As we open the public surface (dataset, spec, SDKs), we are publishing a series of articles that explain *why* the design is what it is, in case you are evaluating whether to build on top of it.

The series is six articles, each readable on its own, totaling roughly 90 minutes of reading. Read them in order if you want the full argument, or jump to whichever piece answers the question you're holding.

## The series

**1. [The Trust Gap in Agent Commerce](trust-gap-agent-commerce.md)**
The strategic case. Why agent commerce has a structural gap that no payment company or platform can credibly fill, and why an independent attestation layer is the right primitive. Audience: investors, partners, generalist tech.

**2. [x402 and the New Role of Payment Protocols](x402-payment-protocol-trust-layer.md)**
The technical case. How the `X-AttestSeal-*` HTTP headers attach a cryptographically signed trust attestation directly to a 402 payment challenge, with no extra round-trip. Audience: developers building on x402 / AP2 / MPP.

**3. [Public Legitimacy Is Not Merchant Trust](public-legitimacy-vs-merchant-trust.md)**
The policy case. Why a `PROCEED` recommendation tells you a domain is the real entity it appears to be, but does *not* tell you the operator has been bank-verified, and how the `assuranceBasis` field exposes the distinction so agents can apply per-tier transaction limits correctly. Audience: agent implementers, payment-policy designers.

**4. [How to Read an AttestSeal Attestation](reading-an-attestseal-attestation.md)**
The developer walkthrough. Field-by-field guide to the signed attestation format, with verification code in Python and TypeScript. Audience: developers integrating AttestSeal into agent runtimes or trust-aware servers.

**5. [The Compositional Brand Anchor](compositional-brand-anchor.md)**
The methodology case. Why Tranco rank alone is not a security primitive, but Tranco rank combined with domain age, valid SSL, and clean reputation IS. The conjunction is what an attacker cannot fabricate. Audience: skeptics, scoring researchers, threat modelers.

**6. [Why AttestSeal Doesn't Handle Payments](why-attestseal-doesnt-handle-payments.md)**
The neutrality case. Why we deliberately did not build a payment processor with a trust feature, what the structural conflict looks like, and how the credit-card / DNS / package-manager industries each settled into a similar shape. Audience: anyone questioning the business model.

## Reference material

- **[X-AttestSeal-* Header Specification](../../spec/X-ATTESTSEAL-HEADERS.md)** -- the protocol document the technical articles refer to.
- **[Scoring Specification](../../spec/SCORING-V1.4.md)** -- the formal weights and thresholds (v1.5.1 update pending).
- **[GitHub repo](https://github.com/AttestSeal/attestseal)** -- spec, SDK, and dataset publication code.
- **[Public dataset](https://huggingface.co/datasets/AttestSeal/trust-dataset)** -- 1M+ scored domains, CC-BY-4.0 (post-launch).

## What's next

In the weeks following launch we plan to publish:

- **A field guide for agent implementers**: how to wire AttestSeal verification into LangChain, CrewAI, AutoGPT, OpenAI Agents, and Anthropic tool-use, with example agent policies for each.
- **A merchant onboarding guide**: how to register with AttestSeal, what fields earn what verification points, and how to upgrade to the KYC tier.
- **A monthly scoring transparency report**: what changed in the dataset, what new patterns emerged in the long tail, what we got wrong and corrected.

Subscribe via RSS or email at [attestseal.com/subscribe](https://attestseal.com/subscribe).

## Get involved

Reading is good; arguing is better. The protocol is young and the patterns are not set. If you have feedback on the spec, the scoring model, the assurance taxonomy, or the API surface, the most useful place to put it is a GitHub issue at [github.com/AttestSeal/attestseal/issues](https://github.com/AttestSeal/attestseal/issues).

For partnership inquiries: [alu@attestseal.com](mailto:alu@attestseal.com). We answer.

---

*AttestSeal, Inc. -- California C-Corp. Independent trust attestation layer for AI agent commerce. The dataset, spec, and SDKs are open. The score is signed. The basis is named. The protocol is yours to use.*
