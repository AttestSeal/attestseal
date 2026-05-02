"""X-AttestSeal-* HTTP header (de)serialization.

The canonical header set is defined in spec/X-ATTESTSEAL-HEADERS.md. This
module is the single source of truth for the names, the parse-from-headers
flow, and the build-headers-from-attestation flow.
"""
from __future__ import annotations

from typing import Mapping, Optional

from .attestation import Attestation

# Required headers (section 4.1 of the spec).
HEADER_ISSUER             = "X-AttestSeal-Issuer"
HEADER_DOMAIN             = "X-AttestSeal-Domain"
HEADER_SCORE              = "X-AttestSeal-Score"
HEADER_RECOMMENDATION     = "X-AttestSeal-Recommendation"
HEADER_CONFIDENCE         = "X-AttestSeal-Confidence"
HEADER_ASSURANCE_BASIS    = "X-AttestSeal-Assurance-Basis"
HEADER_ISSUED_AT          = "X-AttestSeal-Issued-At"
HEADER_EXPIRES_AT         = "X-AttestSeal-Expires-At"
HEADER_SCORING_MODEL      = "X-AttestSeal-Scoring-Model"
HEADER_SIGNATURE          = "X-AttestSeal-Signature"
HEADER_KEY_ID             = "X-AttestSeal-Key-Id"

# Optional headers (section 4.2 of the spec).
HEADER_CAUTION_REASON     = "X-AttestSeal-Caution-Reason"
HEADER_SITE_CATEGORY      = "X-AttestSeal-Site-Category"
HEADER_PARENT_COMPANY     = "X-AttestSeal-Parent-Company"
HEADER_PARENT_FLOOR_INHERITED = "X-AttestSeal-Parent-Floor-Inherited"
HEADER_AGENT_POLICY_HINT  = "X-AttestSeal-Agent-Policy-Hint"
HEADER_SPEC_VERSION       = "X-AttestSeal-Spec-Version"

REQUIRED_HEADERS = (
    HEADER_ISSUER, HEADER_DOMAIN, HEADER_SCORE, HEADER_RECOMMENDATION,
    HEADER_CONFIDENCE, HEADER_ASSURANCE_BASIS, HEADER_ISSUED_AT,
    HEADER_EXPIRES_AT, HEADER_SCORING_MODEL, HEADER_SIGNATURE, HEADER_KEY_ID,
)
HEADER_NAMES = REQUIRED_HEADERS + (
    HEADER_CAUTION_REASON, HEADER_SITE_CATEGORY, HEADER_PARENT_COMPANY,
    HEADER_PARENT_FLOOR_INHERITED, HEADER_AGENT_POLICY_HINT, HEADER_SPEC_VERSION,
)


def _ci_get(headers: Mapping[str, str], name: str) -> Optional[str]:
    """HTTP headers are case-insensitive; this helper returns the first
    matching value regardless of casing in the source mapping."""
    direct = headers.get(name)
    if direct is not None:
        return direct
    name_lower = name.lower()
    for k, v in headers.items():
        if k.lower() == name_lower:
            return v
    return None


def parse_headers(headers: Mapping[str, str]) -> Optional[Attestation]:
    """Parse a complete attestation from an HTTP response's headers, or
    return None if any required header is missing.

    The returned Attestation has signals=None / flags=None /
    reputation_sources=None because those fields are not carried in headers.
    The signing form built from this Attestation will include them as JSON
    null, matching what the server stamped.
    """
    for required in REQUIRED_HEADERS:
        if _ci_get(headers, required) is None:
            return None

    try:
        score = int(_ci_get(headers, HEADER_SCORE) or "0")
    except ValueError:
        return None

    inherited_raw = (_ci_get(headers, HEADER_PARENT_FLOOR_INHERITED) or "false").lower()
    inherited = inherited_raw == "true"

    return Attestation(
        domain=_ci_get(headers, HEADER_DOMAIN) or "",
        issuer=_ci_get(headers, HEADER_ISSUER) or "",
        issued_at=_ci_get(headers, HEADER_ISSUED_AT) or "",
        expires_at=_ci_get(headers, HEADER_EXPIRES_AT) or "",
        trust_score=score,
        recommendation=_ci_get(headers, HEADER_RECOMMENDATION) or "",
        confidence=_ci_get(headers, HEADER_CONFIDENCE) or "",
        assurance_basis=_ci_get(headers, HEADER_ASSURANCE_BASIS) or "",
        scoring_model=_ci_get(headers, HEADER_SCORING_MODEL) or "",
        signature=_ci_get(headers, HEADER_SIGNATURE) or "",
        signature_key_id=_ci_get(headers, HEADER_KEY_ID) or "",
        caution_reason=_ci_get(headers, HEADER_CAUTION_REASON),
        site_category=_ci_get(headers, HEADER_SITE_CATEGORY),
        parent_company=_ci_get(headers, HEADER_PARENT_COMPANY),
        parent_floor_inherited=inherited,
        agent_policy_hint=_ci_get(headers, HEADER_AGENT_POLICY_HINT),
    )


def build_headers(attestation: Attestation, *, spec_version: str = "0.1.0") -> dict[str, str]:
    """Build the X-AttestSeal-* response header dict for an attestation.

    Always emits the required headers. Optional headers are emitted only if
    the corresponding attestation field is non-None / non-default.
    """
    headers: dict[str, str] = {
        HEADER_ISSUER:          attestation.issuer,
        HEADER_DOMAIN:          attestation.domain,
        HEADER_SCORE:           str(attestation.trust_score),
        HEADER_RECOMMENDATION:  attestation.recommendation,
        HEADER_CONFIDENCE:      attestation.confidence,
        HEADER_ASSURANCE_BASIS: attestation.assurance_basis,
        HEADER_ISSUED_AT:       attestation.issued_at,
        HEADER_EXPIRES_AT:      attestation.expires_at,
        HEADER_SCORING_MODEL:   attestation.scoring_model,
        HEADER_SIGNATURE:       attestation.signature,
        HEADER_KEY_ID:          attestation.signature_key_id,
        HEADER_PARENT_FLOOR_INHERITED: "true" if attestation.parent_floor_inherited else "false",
        HEADER_SPEC_VERSION:    spec_version,
    }
    if attestation.caution_reason is not None:
        headers[HEADER_CAUTION_REASON] = attestation.caution_reason
    if attestation.site_category is not None:
        headers[HEADER_SITE_CATEGORY] = attestation.site_category
    if attestation.parent_company is not None:
        headers[HEADER_PARENT_COMPANY] = attestation.parent_company
    if attestation.agent_policy_hint is not None:
        headers[HEADER_AGENT_POLICY_HINT] = attestation.agent_policy_hint
    return headers
