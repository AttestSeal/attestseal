"""Trust token response model matching the ATS protocol spec v0.2."""

import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field
from .signals import SignalBundle


class ChecklistItem(BaseModel):
    category: str
    item: str
    status: str  # pass, fail, improve, available
    impact: str  # high, medium, low
    fix: str

    model_config = {"populate_by_name": True}


class ChecklistSummary(BaseModel):
    total: int
    passing: int
    failing: int
    improvable: int

    model_config = {"populate_by_name": True}


class CheckResponse(BaseModel):
    """Lightweight API response format (spec Section 10.1)."""
    check_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        alias="checkId",
    )
    domain: str
    checked_at: str = Field(alias="checkedAt")
    expires_at: str = Field(alias="expiresAt")
    signals: SignalBundle
    flags: list[str] = Field(default_factory=list)
    trust_score: int = Field(alias="trustScore")
    scoring_model: str = Field(default="attestseal-v1.2-weights", alias="scoringModel")
    site_category: str = Field(default="consumer", alias="siteCategory")
    jurisdiction: dict = Field(default_factory=dict)
    recommendation: str  # PROCEED, CAUTION, DENY
    # "high" = all signals collected, "medium" = 1-2 gaps,
    # "low" = 3+ signals missing. Tells agents how much to trust
    # the score: a low-confidence CAUTION means "we need more data"
    # not "this site is suspicious."
    confidence: str = Field(default="high")
    # Only set when recommendation is CAUTION. Explains WHY:
    # "incomplete_evidence", "weak_signals", "new_domain", "infrastructure"
    caution_reason: Optional[str] = Field(default=None, alias="cautionReason")
    reasoning: str
    # "ok" when the homepage fetched cleanly, "blocked" when the site
    # blocked our crawler (Cloudflare bot wall, residential IP filter,
    # etc). On "blocked", the content signal is excluded from the weighted
    # score and the remaining five signals are re-normalized to sum to 100%.
    crawlability: str = "ok"
    # "well_known" when the compositional brand anchor applied (top-10K
    # Tranco + aged + clean reputation + valid SSL), "scored" otherwise.
    # Consumers who want to filter anchored vs heuristic-only scores can
    # read this field directly rather than re-deriving from flags.
    brand_tier: str = Field(default="scored", alias="brandTier")
    # v1.5.1: assuranceBasis names what kind of trust the recommendation is
    # built on. Values: well_known_tranco_anchor / earned_proceed /
    # registered_proceed / kyc_verified / tenant_platform_earned /
    # infrastructure_earned / api_service_earned / tracking /
    # not_recommended. Cryptographically signed.
    assurance_basis: Optional[str] = Field(default=None, alias="assuranceBasis")
    # v1.5.1: parent_companies registry parent name (Vercel, Cloudflare,
    # Amazon, ...) when the domain matches a registry suffix; null otherwise.
    # Helps agents reason about platform context without cross-referencing.
    parent_company: Optional[str] = Field(default=None, alias="parentCompany")
    # v1.5.1: cryptographic confirmation that no parent-rank inheritance
    # applied. Always False today (subdomain_inherits=False everywhere in
    # the registry); the field exists so agents can rely on its absence
    # to mean "this domain earned its score independently."
    parent_floor_inherited: bool = Field(default=False, alias="parentFloorInherited")
    # v1.5.1: explicit policy hint for agents that prefer not to derive
    # policy from the basis. Values: proceed_normal / proceed_earned /
    # proceed_registered / proceed_kyc_verified /
    # proceed_with_platform_context / proceed_with_infrastructure_context /
    # proceed_with_api_context / do_not_pay_tracking / do_not_pay.
    agent_policy_hint: Optional[str] = Field(default=None, alias="agentPolicyHint")
    # v1.5.1: per-source reputation coverage so agents can distinguish
    # "checked clean" from "not checked." Each entry is
    # {"checked": bool, "matched": bool [, "rank": int]}.
    # Cryptographically signed.
    reputation_sources: Optional[dict] = Field(default=None, alias="reputationSources")
    checklist: list[ChecklistItem] = Field(default_factory=list)
    checklist_summary: ChecklistSummary = Field(alias="checklistSummary")
    signature: str
    signature_key_id: str = Field(
        default="did:web:attestseal.com#signing-key-1",
        alias="signatureKeyId",
    )
    issuer: str = "did:web:attestseal.com"

    model_config = {"populate_by_name": True}


class CheckRequestBody(BaseModel):
    domain: str


class QueuedResponse(BaseModel):
    domain: str
    status: str = "queued"
    estimated_completion_seconds: int = Field(120, alias="estimatedCompletionSeconds")
    poll_url: str = Field(alias="pollUrl")

    model_config = {"populate_by_name": True}


class ErrorResponse(BaseModel):
    error: str
    message: str
    suggestion: Optional[str] = None
    last_known_score: Optional[int] = Field(None, alias="lastKnownScore")
    expired_at: Optional[str] = Field(None, alias="expiredAt")

    model_config = {"populate_by_name": True}
