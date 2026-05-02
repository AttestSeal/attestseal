"""Attestation dataclass + canonical signing form.

The canonical signing form is what the issuer's Ed25519 signature commits to.
Both server (when stamping headers) and client (when verifying) MUST construct
the same bytes for the signature to validate. This module is the single source
of truth for that construction.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(frozen=True)
class Attestation:
    """An AttestSeal trust attestation.

    Maps 1:1 to the X-AttestSeal-* HTTP headers and to the JSON body returned
    by ``GET /v1/check/<domain>``. The ``signature`` field covers the
    canonical signing form built by :meth:`signable_bytes`.
    """

    # Required
    domain: str
    issuer: str
    issued_at: str           # RFC 3339
    expires_at: str          # RFC 3339
    trust_score: int
    recommendation: str      # PROCEED | CAUTION | DENY
    confidence: str          # high | medium | low
    assurance_basis: str
    scoring_model: str
    signature: str           # 'M' + base64pad(ed25519 sig)
    signature_key_id: str    # e.g. did:web:attestseal.com#signing-key-1

    # Optional
    site_category: Optional[str] = None
    caution_reason: Optional[str] = None
    parent_company: Optional[str] = None
    parent_floor_inherited: bool = False
    agent_policy_hint: Optional[str] = None

    # Optional rich payload (signed when present, ignored when absent).
    # When a server stamps headers, signals/flags/reputation_sources are
    # NOT carried in headers, so the canonical form built from headers
    # alone omits them. When a client verifies the JSON body of a /v1/check
    # response, all three are present and must be included in the signing
    # form.
    signals: Optional[dict] = None
    flags: Optional[list] = None
    reputation_sources: Optional[dict] = None

    def signable_bytes(self) -> bytes:
        """Return the canonical bytes that the signature commits to.

        The shape mirrors what server.app.signing.sign_payload() builds for
        full /v1/check responses; for header-only attestations (where signals,
        flags, and reputation_sources are absent) we still include them as
        explicit nulls so the signing form is stable across both transports.
        """
        payload: dict[str, Any] = {
            "domain": self.domain,
            "issuer": self.issuer,
            "issuedAt": self.issued_at,
            "expiresAt": self.expires_at,
            "trustScore": int(self.trust_score),
            "recommendation": self.recommendation,
            "confidence": self.confidence,
            "assuranceBasis": self.assurance_basis,
            "scoringModel": self.scoring_model,
            "siteCategory": self.site_category,
            "cautionReason": self.caution_reason,
            "parentCompany": self.parent_company,
            "parentFloorInherited": bool(self.parent_floor_inherited),
            "agentPolicyHint": self.agent_policy_hint,
            "signals": self.signals,
            "flags": self.flags,
            "reputationSources": self.reputation_sources,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def signable_digest(self) -> bytes:
        """SHA-256 of :meth:`signable_bytes`. The Ed25519 signature commits
        to this digest, not to the raw bytes."""
        return hashlib.sha256(self.signable_bytes()).digest()


@dataclass(frozen=True)
class VerificationResult:
    """Result of verifying an attestation against the issuer's DID.

    ``ok=True`` iff every check (signature, freshness, domain match, issuer
    allowlist) passed. ``reason`` is set on every non-ok result so the caller
    can log or branch on the failure category.

    Reason codes:
      - "missing_required_header" -- one of the X-AttestSeal-* required headers absent
      - "domain_mismatch"         -- attestation.domain != request URL host
      - "expired"                 -- expires_at < now
      - "issuer_not_allowed"      -- issuer DID not in caller's allow-list
      - "did_resolution_failed"   -- could not fetch/parse the DID document
      - "key_not_found"           -- signature_key_id absent from DID document
      - "bad_signature"           -- Ed25519 verification failed
      - "ok"                      -- (for completeness; ok=True implies this)
    """
    ok: bool
    attestation: Optional[Attestation] = None
    reason: str = "ok"
    detail: str = ""
