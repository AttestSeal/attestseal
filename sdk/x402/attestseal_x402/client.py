"""Verifier for X-AttestSeal-* headers and /v1/check JSON responses.

Standard usage from an agent that has just received an HTTP response:

    from attestseal_x402 import AttestationVerifier

    verifier = AttestationVerifier(
        allowed_issuers={"did:web:attestseal.com"},
    )
    result = verifier.verify_response_headers(
        response.headers,
        request_url="https://merchant.example/checkout",
    )
    if result.ok:
        apply_policy(result.attestation)
    else:
        # Optionally fall back to the AttestSeal HTTP API
        ...
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Mapping, Optional
from urllib.parse import urlparse

import httpx
import nacl.exceptions
import nacl.signing

from .attestation import Attestation, VerificationResult
from .did_resolver import DIDResolver, _multibase_decode, default_resolver
from .headers import parse_headers


_DEFAULT_ISSUERS = frozenset({"did:web:attestseal.com"})


class AttestationVerifier:
    """Verifies X-AttestSeal-* attestations against an issuer's DID document.

    The verifier is stateless beyond the DID-document cache it shares with
    the resolver. Construct one per process and reuse it.
    """

    def __init__(
        self,
        *,
        allowed_issuers: Optional[Iterable[str]] = None,
        resolver: Optional[DIDResolver] = None,
    ) -> None:
        self._allowed_issuers = frozenset(allowed_issuers) if allowed_issuers else _DEFAULT_ISSUERS
        self._resolver = resolver or default_resolver

    # ------------------------------------------------------------------
    # Header path
    # ------------------------------------------------------------------

    def verify_response_headers(
        self, headers: Mapping[str, str], *, request_url: str,
    ) -> VerificationResult:
        """Verify the X-AttestSeal-* headers from an HTTP response.

        ``request_url`` is the URL whose response we're verifying; the
        attestation's ``domain`` field MUST equal that URL's hostname or the
        attestation is rejected as a header-injection attempt.
        """
        attestation = parse_headers(headers)
        if attestation is None:
            return VerificationResult(ok=False, reason="missing_required_header",
                                      detail="one or more X-AttestSeal-* required headers absent")

        return self._verify_attestation(attestation, request_url=request_url)

    # ------------------------------------------------------------------
    # JSON-body path (used when calling /v1/check directly)
    # ------------------------------------------------------------------

    def verify_check_response(self, response_json: dict, *, request_url: Optional[str] = None) -> VerificationResult:
        """Verify the JSON body returned by GET /v1/check/<domain>.

        Unlike header verification, the JSON path includes signals, flags,
        and reputationSources in the signing form because they're present
        in the body. Pass ``request_url`` to enforce the domain match;
        omit it if you trust the API endpoint URL alone (in which case
        the domain in the response is taken at face value).
        """
        try:
            attestation = Attestation(
                domain=response_json["domain"],
                issuer=response_json["issuer"],
                issued_at=response_json["checkedAt"],
                expires_at=response_json["expiresAt"],
                trust_score=int(response_json["trustScore"]),
                recommendation=response_json["recommendation"],
                confidence=response_json.get("confidence", "high"),
                assurance_basis=response_json.get("assuranceBasis", "earned_proceed"),
                scoring_model=response_json["scoringModel"],
                signature=response_json["signature"],
                signature_key_id=response_json.get("signatureKeyId", ""),
                site_category=response_json.get("siteCategory"),
                caution_reason=response_json.get("cautionReason"),
                parent_company=response_json.get("parentCompany"),
                parent_floor_inherited=bool(response_json.get("parentFloorInherited", False)),
                agent_policy_hint=response_json.get("agentPolicyHint"),
                signals=response_json.get("signals"),
                flags=response_json.get("flags"),
                reputation_sources=response_json.get("reputationSources"),
            )
        except KeyError as e:
            return VerificationResult(ok=False, reason="missing_required_header",
                                      detail=f"required JSON field absent: {e}")
        return self._verify_attestation(attestation, request_url=request_url)

    # ------------------------------------------------------------------
    # Common verification core
    # ------------------------------------------------------------------

    def _verify_attestation(
        self, attestation: Attestation, *, request_url: Optional[str],
    ) -> VerificationResult:
        # 1. Issuer allow-list
        if attestation.issuer not in self._allowed_issuers:
            return VerificationResult(ok=False, attestation=attestation,
                                      reason="issuer_not_allowed",
                                      detail=f"issuer {attestation.issuer!r} not in allow-list")

        # 2. Domain match (only when request_url provided)
        if request_url is not None:
            host = urlparse(request_url).hostname or ""
            if host.lower() != attestation.domain.lower():
                return VerificationResult(ok=False, attestation=attestation,
                                          reason="domain_mismatch",
                                          detail=f"attestation.domain={attestation.domain!r}, request host={host!r}")

        # 3. Freshness
        try:
            expires = _parse_rfc3339(attestation.expires_at)
        except ValueError:
            return VerificationResult(ok=False, attestation=attestation,
                                      reason="expired", detail="cannot parse expires_at")
        if expires < datetime.now(timezone.utc):
            return VerificationResult(ok=False, attestation=attestation,
                                      reason="expired",
                                      detail=f"expires_at={attestation.expires_at} is in the past")

        # 4. Signature: try cached DID document first, then a forced refresh
        # if the signature fails (handles key-rotation race).
        digest = attestation.signable_digest()
        try:
            sig_bytes = _multibase_decode(attestation.signature)
        except ValueError as e:
            return VerificationResult(ok=False, attestation=attestation,
                                      reason="bad_signature", detail=str(e))

        for force in (False, True):
            try:
                verify_key = self._resolver.verify_key_for(
                    attestation.issuer, attestation.signature_key_id,
                    force_refresh=force,
                )
            except (httpx.HTTPError, ValueError) as e:
                if force:
                    return VerificationResult(ok=False, attestation=attestation,
                                              reason="did_resolution_failed", detail=str(e))
                continue

            try:
                verify_key.verify(digest, sig_bytes)
                return VerificationResult(ok=True, attestation=attestation, reason="ok")
            except nacl.exceptions.BadSignatureError:
                if force:
                    return VerificationResult(ok=False, attestation=attestation,
                                              reason="bad_signature",
                                              detail="Ed25519 verification failed (after DID refresh)")
                # else: try once more with force_refresh=True
                continue

        # Should be unreachable
        return VerificationResult(ok=False, attestation=attestation,
                                  reason="bad_signature", detail="exhausted refresh attempts")


def _parse_rfc3339(value: str) -> datetime:
    """Parse the subset of RFC 3339 used by AttestSeal timestamps.

    Accepts both ``2026-05-09T14:00:00Z`` and ``2026-05-09T14:00:00+00:00``
    forms; the production API emits the Z form.
    """
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


# Convenience module-level entrypoint for the simple case.
def verify(
    headers: Mapping[str, str], *, request_url: str,
    allowed_issuers: Optional[Iterable[str]] = None,
) -> VerificationResult:
    """One-call header verifier. Constructs a transient verifier with the
    process-wide default DID resolver. Equivalent to::

        AttestationVerifier(allowed_issuers=allowed_issuers).verify_response_headers(
            headers, request_url=request_url,
        )
    """
    return AttestationVerifier(allowed_issuers=allowed_issuers).verify_response_headers(
        headers, request_url=request_url,
    )
