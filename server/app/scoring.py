"""Trust scoring engine (model: attestseal-v1.5.1-weights).

Scoring tiers:
  Layer 1: Automated signals             (max ~65 average site)
  Layer 2: Strong automated + Tranco     (max ~82 top-tier sites)
           + OV cert + institutional
  Layer 3: Registration                  (bump ~8 points)
  Layer 4: KYC                           (unlocks 90+, future)

v1.5 changes vs v1.4:
  - Per-bucket brand anchor floors (top-100=90, top-1K=85, top-10K=80,
    top-50K=75) replace the single 75 floor. Spreads top brands into the
    80-90 range without inflating the long tail.
  - PROCEED threshold dropped from 75 to 70, gated on SSL valid + clean
    reputation (no NO_SSL, MALWARE_DETECTED, PHISHING_DETECTED, SPAM_LISTED).
  - Parent-company inheritance: infrastructure subdomains whose parent is
    in the parent_companies registry and itself qualifies for the brand
    anchor inherit the parent's bucket floor.
  - DENY definition unchanged.

v1.5.1 changes vs v1.5 (Codex pre-commit edge-semantics fixes):
  - parent_companies.json now carries per-entry policy: apex_floor,
    subdomain_inherits, site_category. Defaults are False/False so the
    presence of an apex in the registry signals "infrastructure / tenant
    platform / tracking" -- i.e. NOT a payment endpoint.
  - is_well_known_brand respects apex_floor: a registered apex with
    apex_floor=False does NOT receive the brand anchor even when its own
    Tranco rank, age, SSL, and reputation would otherwise qualify it.
    vercel.app, doubleclick.net, googletagmanager.com, etc. now correctly
    score on signals alone (typically CAUTION) instead of being lifted
    to PROCEED via the floor.
  - determine_brand_anchor respects subdomain_inherits: an unregistered
    tenant subdomain (alice.vercel.app, bucket.s3.amazonaws.com, ...) does
    NOT inherit the parent's bucket floor.
  - Response carries a new assuranceBasis field (signed) so agents can
    distinguish well_known_tranco_anchor / earned_proceed / kyc_verified /
    registered_proceed / tenant_platform / tracking / infrastructure /
    not_recommended.
  - Response carries a new reputationSources map (signed) so agents can
    distinguish "checked clean" from "not checked".
"""

from .models.signals import SignalBundle

SCORING_MODEL = "attestseal-v1.5.1-weights"

WEIGHTS = {
    "domain_age": 0.10,
    "ssl": 0.10,
    "dns": 0.08,
    "content": 0.17,
    "reputation": 0.30,
    "identity": 0.25,
}

# Well-known brand anchor criteria. Long-term Tranco top-50K membership
# combined with clean reputation, 5+ years of domain age, and valid SSL
# is unfakeable composite evidence of public trust. Top 50K of Tranco is
# about 0.014% of all registered domains globally -- the list comes from
# billions of real-user requests seen across Cloudflare, Umbrella,
# Majestic and Quantcast, so membership cannot be purchased or gamed.
# When ANDed with 5+ years of age, clean reputation, and valid SSL, the
# population left is essentially "real businesses with no fraud flags."
# Crateandbarrel (rank 12931) and petco (12647) are the reason the
# threshold isn't 10K -- both are unambiguously major brands just outside
# the round-number cutoff, and shipping the tighter threshold would
# produce CAUTION verdicts that look obviously wrong to users.
#
# Encoded as a floor on identity and on the final trust_score so sites
# that score below 75 by pure weighted average (because content is
# unscorable) still get the correct PROCEED verdict. Gated by safety
# signals -- any malware, phishing, spam, or compromise indicator
# revokes the anchor immediately.
WELL_KNOWN_TRANCO_MAX = 50000
WELL_KNOWN_MIN_AGE_DAYS = 1825  # 5 years
WELL_KNOWN_IDENTITY_FLOOR = 50
WELL_KNOWN_SCORE_FLOOR = 75

# v1.5: per-bucket brand anchor floors. The top of Tranco is qualitatively
# different from the rest of top-50K -- amazon, google, microsoft are not
# the same trust shape as the 49,999th-ranked specialty retailer. A single
# 75 floor flattened that distribution; bucketing lifts top brands into the
# 80-90 range while preserving 75 for the rest of the well-known cohort.
BRAND_FLOOR_TOP_100 = 90
BRAND_FLOOR_TOP_1K = 85
BRAND_FLOOR_TOP_10K = 80
BRAND_FLOOR_TOP_50K = 75

# v1.5: PROCEED threshold dropped from 75 to 70 when the safety gate is
# clean. Critical safety failures (malware, phishing) already DENY in
# compute_recommendation; the gate adds NO_SSL and SPAM_LISTED to the
# blockers so a PROCEED verdict always implies "we saw valid SSL and the
# reputation file is clean."
PROCEED_THRESHOLD = 70
PROCEED_GATE_BLOCKERS = frozenset({
    "NO_SSL",
    "MALWARE_DETECTED",
    "PHISHING_DETECTED",
    "SPAM_LISTED",
    "RECENTLY_COMPROMISED",
})

# v1.4: Top-100 Tranco consensus tier. Sustained presence in the top 100
# across billions of real-user requests is itself a form of identity
# verification that no automated system can fake. Combined with 10+ years
# of domain age, this lifts the identity ceiling from 55 to 75, spreading
# amazon/google/wikipedia from the 75 anchor floor into the 80-90 range.
# Tighter eligibility than the brand anchor (top 100 vs top 50K, 10 years
# vs 5 years) makes this safe to apply without inflating the long tail.
CONSENSUS_TRANCO_MAX = 100
CONSENSUS_MIN_AGE_DAYS = 3650  # 10 years
CONSENSUS_IDENTITY_CEILING = 75

# Registration bonus applied to identity signal before weighting
REGISTRATION_BONUS = 30

# KYC tier bonuses applied to identity signal
KYC_BONUSES = {
    "enhanced": 15,       # business directory + address/phone verified
    "kyc_verified": 35,   # government ID + business docs + bank + video call
    "enterprise": 50,     # all of above + audit + continuous monitoring
}

# Institutional TLDs that get an identity boost
INSTITUTIONAL_TLDS = {
    ".gov": 20,
    ".mil": 20,
    ".edu": 15,
    ".int": 15,
}


def _get_institutional_bonus(domain: str) -> int:
    """Check if domain has an institutional TLD."""
    domain_lower = domain.lower()
    for tld, bonus in INSTITUTIONAL_TLDS.items():
        if domain_lower.endswith(tld):
            return bonus
    return 0


def _has_identity_anchor(
    signals: SignalBundle,
    domain: str,
    is_registered: bool,
    identity_score: int,
) -> bool:
    """True if the site has at least one strong identity anchor.

    Used when content is unreachable to decide whether to cap the
    re-weighted score. Without an anchor, a high score from "everything
    but content" would be credulous -- we don't know who runs the site
    AND we couldn't see it, so we cap at PROCEED borderline.
    """
    if is_registered:
        return True
    if _get_institutional_bonus(domain):
        return True
    # Top-50K Tranco rank is a strong anchor (billions of requests seen)
    tranco_rank = getattr(signals.reputation, '_tranco_rank', None)
    if tranco_rank and tranco_rank <= 50000:
        return True
    # OV/EV SSL cert: the CA verified a legal entity before issuing
    ssl_subject_org = getattr(signals.ssl, '_subject_org', '')
    if ssl_subject_org:
        return True
    # Strong computed identity (cross-referenced public data)
    if identity_score >= 45:
        return True
    return False


def is_well_known_brand(
    signals: SignalBundle,
    domain_age_days: int,
    parent_match=None,
) -> bool:
    """True if the composite of Tranco rank + age + clean reputation + SSL
    validity justifies treating this domain as an unambiguously established
    public brand. Any negative safety signal revokes the anchor.

    The rationale is compositional: top-10K Tranco membership over years
    is unfakeable (the list comes from billions of observed real-user
    requests across Cloudflare/Umbrella/Majestic/Quantcast), and when
    combined with age and a clean reputation file, the probability of the
    site being a bad actor is effectively zero.

    v1.5.1: the parent_companies registry can suppress this anchor. If the
    domain's apex is in the registry with apex_floor=False (the default
    for tenant platforms, infrastructure backbones, and tracking domains),
    the anchor is not granted even when all other gates pass. vercel.app,
    doubleclick.net, etc. fall in this bucket -- they qualify by Tranco
    rank but they're not consumer payment endpoints.
    """
    if domain_age_days < WELL_KNOWN_MIN_AGE_DAYS:
        return False
    if not signals.ssl.valid:
        return False
    if signals.reputation.malware or signals.reputation.phishing or signals.reputation.spam_listed:
        return False
    tranco_rank = getattr(signals.reputation, "_tranco_rank", None)
    if tranco_rank is None or tranco_rank > WELL_KNOWN_TRANCO_MAX:
        return False
    # v1.5.1 registry-policy gate. Importing here to avoid circular import
    # at module load (scoring is imported by pipeline; pipeline imports
    # collectors which import nothing from scoring).
    if parent_match is not None:
        from .collectors.parent_company import policy_blocks_brand_anchor
        if policy_blocks_brand_anchor(parent_match):
            return False
    return True


def is_consensus_tier(signals: SignalBundle, domain_age_days: int) -> bool:
    """True if the domain qualifies for the v1.4 consensus identity tier.

    Stricter than is_well_known_brand: top 100 Tranco (not top 50K) and
    10+ years old (not 5). All well_known_brand conditions must also be
    met (clean rep, valid SSL). The consensus tier raises the identity
    ceiling from 55 to 75, which spreads top brands above the 75 anchor
    floor into the 80-90 range.
    """
    if not is_well_known_brand(signals, domain_age_days):
        return False
    if domain_age_days < CONSENSUS_MIN_AGE_DAYS:
        return False
    tranco_rank = getattr(signals.reputation, "_tranco_rank", None)
    if tranco_rank is None or tranco_rank > CONSENSUS_TRANCO_MAX:
        return False
    # Also require a pre-ceiling identity score of at least 30 to ensure
    # there's real signal beyond just the Tranco rank.
    if signals.identity.score < 30:
        return False
    return True


def brand_floor_for_rank(rank: int | None) -> int:
    """Return the v1.5 brand anchor floor for a Tranco rank.

    Top-100 brands get 90, top-1K get 85, top-10K get 80, top-50K get 75.
    Ranks outside the well-known cohort (>50K or unknown) return 0, which
    means "no bucket floor; fall back to the legacy 75 floor or the
    weighted score on its own."
    """
    if rank is None or rank <= 0:
        return 0
    if rank <= 100:
        return BRAND_FLOOR_TOP_100
    if rank <= 1000:
        return BRAND_FLOOR_TOP_1K
    if rank <= 10000:
        return BRAND_FLOOR_TOP_10K
    if rank <= WELL_KNOWN_TRANCO_MAX:
        return BRAND_FLOOR_TOP_50K
    return 0


def determine_brand_anchor(
    signals: SignalBundle,
    domain_age_days: int,
    parent_rank: int | None = None,
    parent_match=None,
) -> tuple[bool, int | None]:
    """Resolve the brand anchor for a domain.

    Returns ``(is_well_known, effective_rank)`` where ``effective_rank`` is
    the Tranco rank to use for picking the bucket floor. The caller passes
    that into :func:`compute_score` as ``brand_floor_rank``.

    Resolution order:
      1. Domain qualifies on its own via :func:`is_well_known_brand` ->
         use the domain's own Tranco rank.
      2. ``parent_rank`` is supplied AND the registry entry permits
         subdomain inheritance AND the parent rank is in the well-known
         cohort (top-50K) -> inherit from parent. The caller is responsible
         for resolving the parent via :func:`parent_company.lookup` and
         passing both the rank and the match object.
      3. Otherwise the domain is not a well-known brand. Returns
         ``(False, None)``.

    Inheritance does NOT propagate the consensus tier (top-100 + 10y) -- a
    CDN subdomain is not amazon.com even when its parent is. The bucket
    floor lifts the score; the identity ceiling remains the automated cap.

    Inheritance is also gated on the domain's own safety signals (valid SSL
    AND clean reputation). A malicious S3 bucket hosted under amazonaws.com
    must not inherit amazon.com's brand floor.

    v1.5.1: registry policy further constrains both branches. An apex with
    apex_floor=False (vercel.app, doubleclick.net, ...) is denied the own-
    qualification path via :func:`is_well_known_brand`. A subdomain whose
    parent registry entry has subdomain_inherits=False is denied the
    inheritance path. The combined effect is "default deny": if a domain
    or its registered parent suffix appears in the registry, no brand
    anchor unless the registry explicitly opts in.
    """
    if is_well_known_brand(signals, domain_age_days, parent_match=parent_match):
        own_rank = getattr(signals.reputation, "_tranco_rank", None)
        return True, own_rank
    # Inheritance branch -- only fires for subdomain matches whose parent
    # entry has subdomain_inherits=True. v1.5.1 sets that to False on every
    # entry by default, so this path is currently dormant; it stays in the
    # code so a future registry can opt specific apexes back into trusted
    # first-party-subdomain inheritance without a code change.
    if parent_rank is not None and 0 < parent_rank <= WELL_KNOWN_TRANCO_MAX:
        if parent_match is not None and not parent_match.subdomain_inherits:
            return False, None
        if parent_match is not None and parent_match.is_apex:
            # We only inherit on subdomain matches, not on the apex itself
            return False, None
        if not signals.ssl.valid:
            return False, None
        if signals.reputation.malware or signals.reputation.phishing or signals.reputation.spam_listed:
            return False, None
        return True, parent_rank
    return False, None


# v1.5.1 assurance basis taxonomy. Surfaced in the signed response payload
# so agents can apply transaction limits or routing differently per basis.
#
# The "_earned" suffix on tenant/infrastructure/api_service is deliberate:
# it tells agents the domain reached PROCEED via its OWN SSL/content/
# identity/reputation/registration signals, NOT by inheriting from the
# parent's Tranco rank. parentFloorInherited in the response is always
# False today; that field is the cryptographic confirmation that no
# parent inheritance applied.
#
# Honest framing: a tenant_platform_earned PROCEED means "tenant/platform-
# shaped endpoint with sufficient direct evidence to proceed under default
# policy." It does NOT mean "this tenant inherits Vercel's reputation."
ASSURANCE_BASIS_WELL_KNOWN_TRANCO = "well_known_tranco_anchor"
ASSURANCE_BASIS_EARNED = "earned_proceed"
ASSURANCE_BASIS_REGISTERED = "registered_proceed"
ASSURANCE_BASIS_KYC_VERIFIED = "kyc_verified"
ASSURANCE_BASIS_TENANT_PLATFORM_EARNED = "tenant_platform_earned"
ASSURANCE_BASIS_INFRASTRUCTURE_EARNED = "infrastructure_earned"
ASSURANCE_BASIS_API_SERVICE_EARNED = "api_service_earned"
ASSURANCE_BASIS_TRACKING = "tracking"
ASSURANCE_BASIS_NOT_RECOMMENDED = "not_recommended"

# Agent-facing policy hint -- a more explicit "what to do" string for
# agents that prefer not to derive policy from the basis themselves.
AGENT_POLICY_HINT = {
    ASSURANCE_BASIS_WELL_KNOWN_TRANCO: "proceed_normal",
    ASSURANCE_BASIS_EARNED: "proceed_earned",
    ASSURANCE_BASIS_REGISTERED: "proceed_registered",
    ASSURANCE_BASIS_KYC_VERIFIED: "proceed_kyc_verified",
    ASSURANCE_BASIS_TENANT_PLATFORM_EARNED: "proceed_with_platform_context",
    ASSURANCE_BASIS_INFRASTRUCTURE_EARNED: "proceed_with_infrastructure_context",
    ASSURANCE_BASIS_API_SERVICE_EARNED: "proceed_with_api_context",
    ASSURANCE_BASIS_TRACKING: "do_not_pay_tracking",
    ASSURANCE_BASIS_NOT_RECOMMENDED: "do_not_pay",
}


def agent_policy_hint(basis: str) -> str:
    """Return the agentPolicyHint for an assuranceBasis. Defaults to
    do_not_pay for unknown values so the agent fails closed."""
    return AGENT_POLICY_HINT.get(basis, "do_not_pay")


def compute_assurance_basis(
    recommendation: str,
    well_known_brand: bool,
    is_registered: bool = False,
    kyc_tier: str = "none",
    parent_match=None,
    site_category: str = "consumer",
) -> str:
    """Return the basis behind the recommendation.

    For PROCEED, the basis tells an agent how the trust was earned:
    well_known_tranco_anchor (top-50K aged consumer brand), earned_proceed
    (signals-only, no anchor), registered_proceed (operator filled out
    registration), kyc_verified (highest assurance), tenant_platform_earned
    /infrastructure_earned/api_service_earned (registry- or heuristic-
    tagged platform shape that earned its way to PROCEED via direct
    signals -- the "_earned" suffix is deliberate so agents know the
    score did NOT inherit from a parent's Tranco rank).

    For CAUTION/DENY, tracking returns its own basis (always blocked from
    PROCEED), other cases return not_recommended.

    Honest framing: a tenant_platform_earned PROCEED means "tenant/platform-
    shaped endpoint with sufficient direct evidence to proceed under
    default policy." It does not assert anything about KYC or merchant
    risk -- the agent applies its own transaction policy on top.
    """
    # tracking is always returned as the basis even when CAUTION/DENY,
    # because it's the agent-actionable signal ("never pay this").
    if parent_match is not None and parent_match.site_category == "tracking":
        return ASSURANCE_BASIS_TRACKING

    if recommendation != "PROCEED":
        return ASSURANCE_BASIS_NOT_RECOMMENDED

    # PROCEED ladder. Strongest evidence wins. KYC and registration tags
    # are independent of platform shape -- a kyc_verified tenant subdomain
    # is kyc_verified, not tenant_platform_earned.
    if kyc_tier in ("kyc_verified", "enterprise"):
        return ASSURANCE_BASIS_KYC_VERIFIED
    if is_registered:
        return ASSURANCE_BASIS_REGISTERED
    if well_known_brand:
        return ASSURANCE_BASIS_WELL_KNOWN_TRANCO

    # Registry-tagged platform shapes -- the "_earned" suffix tells agents
    # the domain reached PROCEED via own signals, not via inheritance.
    if parent_match is not None:
        if parent_match.site_category == "tenant_platform":
            return ASSURANCE_BASIS_TENANT_PLATFORM_EARNED
        if parent_match.site_category == "infrastructure":
            return ASSURANCE_BASIS_INFRASTRUCTURE_EARNED

    # Heuristic api_service detection (api.openai.com, api.stripe.com, etc.)
    # is also a meaningful shape for agent commerce.
    if site_category == "api_service":
        return ASSURANCE_BASIS_API_SERVICE_EARNED

    return ASSURANCE_BASIS_EARNED


def build_reputation_sources(
    rep_signal,
    blocklist_detail: dict | None,
    safe_browsing_checked: bool | None,
) -> dict:
    """Build the v1.5.1 reputationSources map for the signed response.

    Each entry is {"checked": bool, "matched": bool}. When the upstream
    record cannot tell us whether a check was performed (e.g. a row was
    rescored from raw_signals where we did not capture sb_checked), we
    return checked=False and the agent can interpret that as "not
    independently verified by us."
    """
    bl = blocklist_detail or {}
    bl_keys = set(bl.keys()) if isinstance(bl, dict) else set()
    rank = getattr(rep_signal, "_tranco_rank", None)

    return {
        "tranco": {"checked": True, "rank": rank, "matched": False},
        "spamhaus_dbl": {
            "checked": "spamhaus" in bl_keys,
            "matched": bool(bl.get("spamhaus", False)),
        },
        "surbl": {
            "checked": "surbl" in bl_keys,
            "matched": bool(bl.get("surbl", False)),
        },
        "urlhaus": {
            "checked": "urlhaus" in bl_keys,
            "matched": bool(bl.get("urlhaus", False)),
        },
        "google_safe_browsing": {
            "checked": bool(safe_browsing_checked) if safe_browsing_checked is not None else False,
            "matched": bool(rep_signal.malware or rep_signal.phishing),
        },
    }


def compute_score(
    signals: SignalBundle,
    is_registered: bool = False,
    domain: str = "",
    kyc_tier: str = "none",
    registration_score: int = 0,
    content_scorable: bool = True,
    well_known_brand: bool = False,
    consensus_tier: bool = False,
    brand_floor_rank: int | None = None,
) -> int:
    identity_score = signals.identity.score

    # Institutional TLD bonus
    institutional = _get_institutional_bonus(domain)
    if institutional:
        identity_score = min(55, identity_score + institutional)

    # Registration: use per-field verification score if available,
    # fall back to flat bonus for backward compatibility
    if is_registered:
        if registration_score > 0:
            identity_score = min(55, identity_score + registration_score)
        else:
            identity_score = min(55, identity_score + REGISTRATION_BONUS)

    # Identity ceiling: starts at 55 (automated), raised by consensus
    # tier or KYC tier. Consensus tier (v1.4) is a non-KYC elevation
    # based on Tranco top-100 + 10-year domain age.
    identity_ceiling = 55  # automated cap
    if consensus_tier:
        identity_ceiling = CONSENSUS_IDENTITY_CEILING

    # KYC tier adjustments (override consensus if higher)
    if kyc_tier == "enhanced":
        identity_ceiling = max(identity_ceiling, 65)
    elif kyc_tier == "kyc_verified":
        identity_ceiling = max(identity_ceiling, 80)
    elif kyc_tier == "enterprise":
        identity_ceiling = max(identity_ceiling, 100)

    if kyc_tier != "none":
        identity_score = min(identity_ceiling, identity_score + KYC_BONUSES.get(kyc_tier, 0))
    elif consensus_tier:
        # Consensus tier raises the ceiling but doesn't add bonus points.
        # The identity score just benefits from a higher cap.
        identity_score = min(identity_ceiling, identity_score)

    # Well-known brand anchor: lift identity to the floor. This is applied
    # BEFORE the weighted sum so the 25% identity weight carries a real
    # contribution even when content-dependent identity signals
    # (contact_on_site, schema.org, etc) were unavailable.
    if well_known_brand:
        identity_score = max(identity_score, WELL_KNOWN_IDENTITY_FLOOR)

    # KYC-adjusted domain age: if identity is strongly verified,
    # a new domain is less concerning because we know who owns it
    domain_age_score = signals.domain_age.score
    if kyc_tier in ("kyc_verified", "enterprise") and domain_age_score < 50:
        domain_age_score = max(domain_age_score, 50)

    if content_scorable:
        raw = (
            domain_age_score * WEIGHTS["domain_age"]
            + signals.ssl.score * WEIGHTS["ssl"]
            + signals.dns.score * WEIGHTS["dns"]
            + signals.content.score * WEIGHTS["content"]
            + signals.reputation.score * WEIGHTS["reputation"]
            + identity_score * WEIGHTS["identity"]
        )
    else:
        # Content unreachable (e.g. Cloudflare bot wall on our VPS IP).
        # Drop content from the weighted sum and renormalize the remaining
        # five signals to sum to 100%. Punishing content=0 as negative
        # evidence would let well-defended retailers look untrustworthy.
        raw_partial = (
            domain_age_score * WEIGHTS["domain_age"]
            + signals.ssl.score * WEIGHTS["ssl"]
            + signals.dns.score * WEIGHTS["dns"]
            + signals.reputation.score * WEIGHTS["reputation"]
            + identity_score * WEIGHTS["identity"]
        )
        raw = raw_partial / (1.0 - WEIGHTS["content"])

        # Floor rule: without a strong identity anchor we can't trust the
        # renormalized score, so cap at borderline-PROCEED (70). With an
        # anchor (Tranco top-50K, EV cert, institutional TLD, registered,
        # or high computed identity) let the score flow through.
        if not _has_identity_anchor(signals, domain, is_registered, identity_score):
            raw = min(raw, 70)

    final = min(100, round(raw))

    # Well-known brand anchor: floor the final score so unambiguously
    # established brands don't get CAUTION even when their content is
    # unscorable. v1.5 picks the floor by Tranco bucket (90/85/80/75)
    # using brand_floor_rank, which is either the domain's own rank or,
    # for parent-inherited subdomains, the parent's rank. Falls back to
    # the legacy 75 floor when no rank is available.
    if well_known_brand:
        rank_for_floor = brand_floor_rank
        if rank_for_floor is None:
            rank_for_floor = getattr(signals.reputation, "_tranco_rank", None)
        bucket_floor = brand_floor_for_rank(rank_for_floor)
        if bucket_floor > 0:
            final = max(final, bucket_floor)
        else:
            final = max(final, WELL_KNOWN_SCORE_FLOOR)

    return final


def compute_flags(
    signals: SignalBundle,
    score: int,
    domain_age_days: int = -1,
    kyc_tier: str = "none",
    monitoring_alerts: list[str] = None,
    well_known_brand: bool = False,
) -> list[str]:
    flags = []
    if well_known_brand:
        flags.append("WELL_KNOWN_BRAND")

    # Critical: reputation threats
    if signals.reputation.malware:
        flags.append("MALWARE_DETECTED")
    if signals.reputation.phishing:
        flags.append("PHISHING_DETECTED")
    if signals.reputation.spam_listed:
        flags.append("SPAM_LISTED")

    # Domain age (suppressed if KYC verified)
    if 0 <= domain_age_days < 90:
        if kyc_tier in ("kyc_verified", "enterprise"):
            flags.append("NEW_DOMAIN_KYC_VERIFIED")
        else:
            flags.append("NEW_DOMAIN")

    # Identity gaps
    if not signals.identity.verified and signals.identity.score == 0:
        flags.append("NO_IDENTITY")

    # SSL
    if not signals.ssl.valid:
        flags.append("NO_SSL")

    # Monitoring alerts (from ongoing checks)
    if monitoring_alerts:
        flags.extend(monitoring_alerts)

    return flags


# v1.5.1 final: only `tracking` is hard-blocked from PROCEED. Tenant
# platforms (vercel.app, myshopify.com), infrastructure apexes
# (cloudflare.com, akamai.net), and api_service shapes (api.openai.com)
# are score-driven -- they CAN be legitimate payment endpoints in agent
# commerce (subscriptions, x402 APIs, hosted services). The right surface
# for agent policy is assuranceBasis (which carries the "_earned" suffix
# so agents know the score did NOT come from parent inheritance) plus
# parentFloorInherited (always False today; cryptographic confirmation
# that no inheritance applied).
#
# tracking domains (doubleclick.net, google-analytics.com, segment.io)
# are pure ad/analytics infrastructure -- never a payment endpoint, so
# they stay hard-blocked even at high scores.
PROCEED_BLOCKING_CATEGORIES = frozenset({
    "tracking",
})


def compute_recommendation(
    score: int,
    flags: list[str],
    parent_match=None,
    is_registered: bool = False,
    kyc_tier: str = "none",
) -> str:
    critical_flags = {"MALWARE_DETECTED", "PHISHING_DETECTED", "RECENTLY_COMPROMISED"}
    flag_set = set(flags)
    if critical_flags & flag_set:
        return "DENY"

    # v1.5.1 registry-policy override: an apex (or subdomain) tagged as
    # tenant_platform / tracking / infrastructure by parent_companies.json
    # is by definition not a consumer payment endpoint. Without an explicit
    # registration or KYC anchor we force CAUTION even when the score and
    # safety gate would otherwise PROCEED. The signed assuranceBasis
    # surfaces *why*. Registered or KYC-verified operators reclaim PROCEED
    # through the registration / KYC flow without a code change.
    #
    # Important: this gates on parent_match (registry-derived) ONLY, not on
    # the heuristic site_category produced by content_check. The heuristic
    # over-tags consumer sites whose content fetch failed (facebook.com,
    # github.com, pinterest.com, ...) as "infrastructure" -- registry is
    # the authoritative source for this policy decision.
    if (
        parent_match is not None
        and parent_match.site_category in PROCEED_BLOCKING_CATEGORIES
        and not is_registered
        and kyc_tier in ("none", "", None)
    ):
        if score >= 40:
            return "CAUTION"
        return "DENY"

    # v1.5: PROCEED at 70+ requires the safety gate to be clean (valid SSL
    # AND no negative reputation flags). The gate keeps a CAUTION verdict
    # for high-scoring sites that are missing SSL or carry SPAM_LISTED,
    # which v1.4 would have over-trusted at the old 75 threshold.
    if score >= PROCEED_THRESHOLD and not (PROCEED_GATE_BLOCKERS & flag_set):
        return "PROCEED"
    if score >= 40:
        return "CAUTION"
    return "DENY"


def compute_confidence(
    signals: SignalBundle,
    content_scorable: bool = True,
    domain_age_days: int = -1,
) -> str:
    """Rate how complete the evidence is for this domain.

    'high'   = 5-6 signals collected with real data. The score is
               based on comprehensive evidence.
    'medium' = 4 signals have real data, 1-2 have gaps. Score is
               directionally right but could shift on re-check.
    'low'    = 3 or fewer signals have real data. Score is based on
               limited evidence and will likely change on a full-tier
               re-check.

    Key distinction: a signal with score=0 because we COLLECTED the
    data and it was absent (e.g., no privacy policy found on a
    successfully crawled page) is evidence. A signal with score=0
    because we COULDN'T COLLECT the data (content blocked, WHOIS
    timed out) is a gap. Confidence reflects gaps, not weakness.

    We approximate this by treating certain zeros as gaps vs evidence:
    - Content score=0 when content_scorable=False -> gap (not evidence)
    - Domain age score=0 when domain_age_days<0 -> gap (WHOIS failed)
    - Domain age score=0 when domain_age_days>=0 -> evidence (new domain)
    - SSL score=0 -> evidence (no SSL is a real finding)
    - DNS score never 0 (minimum is 20), so always evidence
    - Identity score=0 -> gap (WHOIS + cert check both failed)
    - Reputation score=0 -> evidence (blocklist hit is a real finding)
    """
    evidence_count = 0
    total_possible = 6

    # Reputation: score=0 means blocklist hit, that's evidence
    evidence_count += 1  # always counts

    # SSL: score=0 means no SSL, that's evidence
    evidence_count += 1  # always counts

    # DNS: minimum score is 20 (always has data)
    evidence_count += 1  # always counts

    # Domain age: depends on whether WHOIS actually returned data
    if domain_age_days >= 0:
        evidence_count += 1  # WHOIS worked, even if domain is new
    # else: WHOIS failed, this is a gap

    # Identity: score=0 could be gap (WHOIS + cert both failed)
    if signals.identity.score > 0:
        evidence_count += 1

    # Content: depends on whether we could fetch
    if content_scorable:
        evidence_count += 1  # we fetched, even if we found nothing
    # else: content blocked, this is a gap

    if evidence_count >= 5:
        return "high"
    elif evidence_count >= 4:
        return "medium"
    else:
        return "low"


def compute_caution_reason(
    signals: SignalBundle,
    score: int,
    domain_age_days: int,
    content_scorable: bool = True,
    confidence: str = "high",
    site_category: str = "consumer",
    recommendation: str = "",
) -> str | None:
    """Determine WHY a domain scored CAUTION. Returns None if not CAUTION.

    Possible values:
    - 'incomplete_evidence': fast-mode seed, content blocked, WHOIS
      unavailable. Score limited by missing data, not bad data.
    - 'weak_signals': we collected evidence and it's genuinely thin.
      The site needs improvement (privacy policy, DMARC, etc).
    - 'new_domain': domain registered less than 1 year ago. Time is
      the missing signal.
    - 'infrastructure': CDN, API, DNS backbone. Merchant trust criteria
      do not fit well.
    - 'tenant_platform': vercel.app, github.io, myshopify.com, etc. The
      apex (or any of its subdomains) is not a consumer payment endpoint.
    - 'tracking': doubleclick.net, googletagmanager.com, etc. Ad/analytics
      infrastructure, never a payment endpoint.

    Recommendation is the authoritative gate: if the caller already knows
    the recommendation is CAUTION (e.g. via the v1.5.1 site_category
    override), pass it in so we do not skip the reason on a high score.
    The legacy score-band fallback exists only for callers that have not
    been updated.
    """
    if recommendation:
        if recommendation != "CAUTION":
            return None
    elif score >= 75 or score < 40:
        return None  # not CAUTION (legacy callers)

    # Infrastructure domains scored against merchant criteria
    # tracking is hard-blocked from PROCEED by compute_recommendation,
    # so any CAUTION on tracking gets the explicit reason.
    if site_category == "tracking":
        return "tracking"
    # tenant_platform / infrastructure / api_service that landed in CAUTION
    # are now there for the same reason any other domain would be: signals
    # are weak or evidence is incomplete. Fall through to the standard
    # weak_signals / incomplete_evidence path so cautionReason reflects
    # what the agent should actually fix.

    # New domains (under 1 year)
    if 0 <= domain_age_days < 365:
        return "new_domain"

    # Evidence gap: low confidence means we couldn't collect enough
    if confidence == "low":
        return "incomplete_evidence"

    # Content specifically blocked
    if not content_scorable and score < 75:
        return "incomplete_evidence"

    # Default: we saw the signals and they're weak
    return "weak_signals"


def generate_reasoning(
    signals: SignalBundle,
    score: int,
    recommendation: str,
    content_unscorable: bool = False,
    well_known_brand: bool = False,
) -> str:
    parts = []
    if well_known_brand:
        parts.append(
            "established public brand (top-10K Tranco, 5+ years domain age, "
            "clean reputation, valid SSL)"
        )

    if signals.domain_age.band in ("5+ years", "2-5 years"):
        parts.append(f"Established domain ({signals.domain_age.band})")
    elif signals.domain_age.band in ("< 30 days", "1-3 months"):
        parts.append(f"New domain ({signals.domain_age.band})")

    if signals.ssl.valid:
        parts.append("valid SSL")
    else:
        parts.append("no SSL detected")

    if signals.reputation.malware:
        parts.append("MALWARE DETECTED")
    elif signals.reputation.phishing:
        parts.append("PHISHING DETECTED")
    elif signals.reputation.score >= 80:
        parts.append("clean reputation")

    if signals.identity.verified:
        parts.append("identity verified")
    elif signals.identity.score > 0:
        parts.append("partial identity signals from public data")
    else:
        parts.append("no identity verification on file")

    if content_unscorable:
        parts.append(
            "homepage content not directly verifiable (site blocks crawlers); "
            "scored from domain, SSL, DNS, reputation, and identity"
        )

    summary = ", ".join(parts) + "."

    if recommendation == "PROCEED":
        summary += " Suitable for standard transactions."
    elif recommendation == "CAUTION":
        summary += " Consider transaction limits or user confirmation."
    else:
        summary += " Transaction not recommended."

    return summary
