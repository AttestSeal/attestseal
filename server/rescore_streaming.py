#!/usr/bin/env python3
"""Streaming rescore: backfill confidence + cautionReason for all 994K rows
that lack it, using the same scoring logic as the live pipeline.

Memory-efficient: streams through scored_results one row at a time, fetches
that row's raw_signals, recomputes score/confidence/cautionReason, re-signs,
updates response_json. Batched commits every 1000 rows. Should fit in 2GB.

Run on ats-api-1 as the ats user. Stops the attestseal service first to
avoid concurrent writes.
"""
import sys, os, json, sqlite3, time
from datetime import datetime, timedelta, timezone

# Make app/ importable
sys.path.insert(0, "/opt/attestseal/server")

# Tranco list lives next to the production DB. Setting ATS_DATA_DIR before
# any app import ensures collectors.tranco resolves to the right file.
# Same for the signing key dir -- without this, signing.py defaults to
# the relative ./keys path which only resolves correctly when the script
# is launched with cwd=/opt/attestseal. Setting ATS_KEY_DIR explicitly
# makes the script self-contained regardless of cwd.
os.environ.setdefault("ATS_DATA_DIR", "/opt/attestseal/data")
os.environ.setdefault("ATS_KEY_DIR", "/opt/attestseal/keys")

from app.scoring import (
    compute_score, compute_flags, compute_recommendation, generate_reasoning,
    compute_confidence, compute_caution_reason, SCORING_MODEL,
    is_consensus_tier, determine_brand_anchor,
    compute_assurance_basis, build_reputation_sources, agent_policy_hint,
)
from app.checklist import generate_checklist, checklist_summary
from app.models.signals import (
    SignalBundle, DomainAgeSignal, SSLSignal, DNSSignal,
    ContentSignal, ReputationSignal, IdentitySignal,
)
from app.signing import sign_payload
from app.collectors import tranco as _tranco
from app.collectors.tranco import rank_to_score
from app.collectors import parent_company as _pc_lookup

DB = "/opt/attestseal/data/attestseal.db"

def rebuild_signals(raw, domain):
    """Reconstruct SignalBundle from stored raw_signals JSON. Mirrors
    rescore.py rebuild_signals() exactly."""
    da = raw.get("domainAge", {})
    ssl_d = raw.get("ssl", {})
    dns_d = raw.get("dns", {})
    con = raw.get("content", {})
    rep = raw.get("reputation", {})
    iden = raw.get("identity", {})

    tranco_rank = rep.get("trancoRank")
    tranco_score = rank_to_score(tranco_rank)
    if tranco_score >= 0:
        rep_score = tranco_score
    elif not rep.get("malware") and not rep.get("phishing"):
        rep_score = 80
    else:
        rep_score = 0

    found = sum([con.get("privacyPolicy", False), con.get("termsOfService", False), con.get("contactInfo", False)])
    content_score = 0
    if found == 1: content_score = 30
    elif found == 2: content_score = 50
    elif found >= 3: content_score = 70
    if con.get("hasRobots"): content_score += 5
    if con.get("hasSecurityTxt"): content_score += 10
    shc = con.get("securityHeaderCount", 0)
    if shc >= 3: content_score += 15
    elif shc >= 1: content_score += 5
    content_score = min(100, content_score)

    ssl_score = 0
    if ssl_d.get("valid"):
        ssl_score = 60
        tlsv = ssl_d.get("tlsVersion", "")
        if tlsv in ("TLSv1.2", "TLSv1.3"): ssl_score = 80
        if tlsv == "TLSv1.3": ssl_score = 90
        if tlsv == "TLSv1.3" and ssl_d.get("hsts"): ssl_score = 100

    spf = dns_d.get("spf", False); dmarc = dns_d.get("dmarc", False)
    dnssec = dns_d.get("dnssec", False); caa = dns_d.get("caa", False)
    dns_score = 20
    if spf: dns_score = 40
    if spf and dmarc: dns_score = 60
    if spf and dmarc and dnssec: dns_score = 90
    if spf and dmarc and dnssec and caa: dns_score = 100

    age_score = 0
    reg_date = da.get("registeredDate")
    if reg_date:
        try:
            reg = datetime.strptime(reg_date, "%Y-%m-%d")
            days = (datetime.now() - reg).days
            if days <= 30: age_score = 0
            elif days <= 90: age_score = 20
            elif days <= 180: age_score = 40
            elif days <= 365: age_score = 60
            elif days <= 730: age_score = 75
            elif days <= 1825: age_score = 90
            else: age_score = 100
        except ValueError:
            pass

    id_score = 0
    if tranco_rank is not None:
        if tranco_rank <= 100: id_score += 25
        elif tranco_rank <= 1000: id_score += 20
        elif tranco_rank <= 5000: id_score += 15
        elif tranco_rank <= 10000: id_score += 12
        elif tranco_rank <= 50000: id_score += 8
        elif tranco_rank <= 100000: id_score += 5
        elif tranco_rank <= 500000: id_score += 3
    if iden.get("hasOttFile"): id_score += 20
    if iden.get("whoisDisclosed"): id_score += 15
    if iden.get("sslCertOrg"): id_score += 5
    if iden.get("schemaOrgPresent"): id_score += 3
    id_score = min(100, id_score)

    signals = SignalBundle(
        domain_age=DomainAgeSignal(
            registered_date=reg_date or "",
            domain_age_days=da.get("domainAgeDays", -1),
            band=da.get("band", "unknown"),
            score=age_score,
        ),
        ssl=SSLSignal(
            valid=ssl_d.get("valid", False),
            issuer=ssl_d.get("issuer", ""),
            tls_version=ssl_d.get("tlsVersion", ""),
            hsts=ssl_d.get("hsts", False),
            ovev_org=ssl_d.get("ovevOrg", ""),
            score=ssl_score,
        ),
        dns=DNSSignal(spf=spf, dmarc=dmarc, dnssec=dnssec, caa=caa, score=dns_score),
        content=ContentSignal(
            privacy_policy=con.get("privacyPolicy", False),
            terms_of_service=con.get("termsOfService", False),
            contact_info=con.get("contactInfo", False),
            score=content_score,
        ),
        reputation=ReputationSignal(
            malware=rep.get("malware", False),
            phishing=rep.get("phishing", False),
            spam_listed=rep.get("spamListed", False),
            score=rep_score,
        ),
        identity=IdentitySignal(
            verified=iden.get("verified", False),
            verification_tier=iden.get("verificationTier", "automated"),
            whois_disclosed=iden.get("whoisDisclosed", False),
            business_directory=iden.get("businessDirectory", False),
            contact_on_site=iden.get("contactOnSite", False),
            score=id_score,
        ),
    )
    # The brand-anchor and consensus-tier helpers in app.scoring read the
    # rank from signals.reputation._tranco_rank, mirroring the live pipeline
    # where reputation_check sets it on the reputation sub-signal directly.
    # Setting it on the SignalBundle instead would silently bypass the brand
    # anchor for every rescored row.
    setattr(signals.reputation, "_tranco_rank", tranco_rank)
    return signals, raw

def main():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    write_con = sqlite3.connect(DB)

    # Eagerly load the Tranco list so per-row parent-rank lookups are
    # in-memory dict reads, not file I/O on every iteration.
    _tranco._load()
    if not _tranco._loaded:
        print(f"WARN: Tranco list not loaded; parent inheritance will be disabled")

    total = con.execute("SELECT COUNT(*) FROM scored_results").fetchone()[0]
    print(f"Total scored_results: {total:,}")

    start = time.time()
    processed = 0; updated = 0; errors = 0; skipped_no_raw = 0
    batch = []
    BATCH_SIZE = 1000

    cur = con.cursor()
    cur.execute("SELECT domain FROM scored_results")
    for row in cur:
        processed += 1
        domain = row["domain"]
        try:
            # Fetch the LATEST raw_signals row for this domain
            raw_row = con.execute(
                "SELECT signal_data FROM raw_signals WHERE domain = ? ORDER BY checked_at DESC LIMIT 1",
                (domain,)
            ).fetchone()
            if not raw_row:
                skipped_no_raw += 1
                continue
            raw = json.loads(raw_row[0])

            signals, raw_full = rebuild_signals(raw, domain)

            domain_age_days = -1
            reg_date = raw.get("domainAge", {}).get("registeredDate")
            if reg_date:
                try:
                    domain_age_days = (datetime.now() - datetime.strptime(reg_date, "%Y-%m-%d")).days
                except ValueError:
                    pass

            # v1.5.1 brand anchor + parent-policy. We always do a fresh
            # registry lookup so the rescore picks up the per-entry policy
            # fields (apex_floor, subdomain_inherits, site_category) that
            # may have been added or revised since the row was crawled. The
            # raw_signals.identity.parentCompany payload from the crawl is
            # left untouched -- it is just a snapshot of what was in the
            # registry at crawl time, not the source of truth for scoring.
            live_match = _pc_lookup.lookup(domain)

            parent_rank = None
            if live_match is not None:
                parent_rank = _tranco.get_rank(live_match.parent)

            well_known, brand_floor_rank = determine_brand_anchor(
                signals, domain_age_days, parent_rank=parent_rank,
                parent_match=live_match,
            )
            consensus = is_consensus_tier(signals, domain_age_days)
            content_unscorable = bool(raw.get("content", {}).get("_unscorable", False))

            score = compute_score(
                signals, is_registered=False, domain=domain,
                content_scorable=not content_unscorable,
                well_known_brand=well_known,
                consensus_tier=consensus,
                brand_floor_rank=brand_floor_rank,
            )
            flags = compute_flags(signals, score, domain_age_days, well_known_brand=well_known)
            if content_unscorable:
                flags.append("CONTENT_UNSCORABLE")
                if well_known:
                    flags.append("ANCHOR_ONLY")

            # site_category resolution order:
            #   1. Registry override (tenant_platform/infrastructure/tracking)
            #   2. Well-known brand anchor -> consumer (overrides heuristic
            #      mistag for adidas.com, fly.io, muji.com, etc.)
            #   3. Whatever the original crawl recorded
            if live_match is not None and live_match.site_category in (
                "tenant_platform", "infrastructure", "tracking"
            ):
                site_category = live_match.site_category
            elif well_known:
                site_category = "consumer"
            else:
                site_category = raw.get("content", {}).get("siteCategory") or "consumer"

            recommendation = compute_recommendation(
                score, flags,
                parent_match=live_match,
                is_registered=False,
                kyc_tier="none",
            )
            confidence = compute_confidence(
                signals, content_scorable=not content_unscorable,
                domain_age_days=domain_age_days,
            )
            caution_reason = compute_caution_reason(
                signals, score, domain_age_days,
                content_scorable=not content_unscorable,
                confidence=confidence,
                site_category=site_category,
                recommendation=recommendation,
            )

            # v1.5.1: assuranceBasis + agentPolicyHint + parentCompany +
            # parentFloorInherited + reputationSources, all signed.
            assurance_basis = compute_assurance_basis(
                recommendation,
                well_known_brand=well_known,
                is_registered=False,
                kyc_tier="none",
                parent_match=live_match,
                site_category=site_category,
            )
            agent_hint = agent_policy_hint(assurance_basis)
            parent_company_name = live_match.parent_name if live_match is not None else None
            parent_floor_inherited = False  # subdomain_inherits=False registry-wide
            rep_raw = raw.get("reputation", {}) or {}
            reputation_sources = build_reputation_sources(
                signals.reputation,
                rep_raw.get("blocklists"),
                # raw_signals only carries safeBrowsingChecked from v1.5.1+
                # crawls; older rows do not, so we get a False here that
                # honestly reflects "we cannot prove GSB ran on this row."
                rep_raw.get("safeBrowsingChecked"),
            )

            reasoning = generate_reasoning(
                signals, score, recommendation,
                content_unscorable=content_unscorable,
                well_known_brand=well_known,
            )

            cl = generate_checklist(signals, is_registered=False)
            cl_summary = checklist_summary(cl)

            now = datetime.now(timezone.utc)
            expires = now + timedelta(days=7)

            signable = {
                "domain": domain,
                "signals": signals.model_dump(by_alias=True),
                "flags": flags,
                "trustScore": score,
                "scoringModel": SCORING_MODEL,
                "recommendation": recommendation,
                "confidence": confidence,
                "cautionReason": caution_reason,
                "assuranceBasis": assurance_basis,
                "agentPolicyHint": agent_hint,
                "siteCategory": site_category,
                "parentCompany": parent_company_name,
                "parentFloorInherited": parent_floor_inherited,
                "reputationSources": reputation_sources,
            }
            signature = sign_payload(signable)

            response = {
                "domain": domain,
                "checkedAt": now.isoformat(timespec="seconds") + "Z",
                "expiresAt": expires.isoformat(timespec="seconds") + "Z",
                "signals": signals.model_dump(by_alias=True),
                "flags": flags,
                "trustScore": score,
                "scoringModel": SCORING_MODEL,
                "recommendation": recommendation,
                "confidence": confidence,
                "cautionReason": caution_reason,
                "assuranceBasis": assurance_basis,
                "agentPolicyHint": agent_hint,
                "siteCategory": site_category,
                "parentCompany": parent_company_name,
                "parentFloorInherited": parent_floor_inherited,
                "reputationSources": reputation_sources,
                "reasoning": reasoning,
                "crawlability": "blocked" if content_unscorable else "ok",
                "brandTier": "well_known" if well_known else "scored",
                "checklist": cl,
                "checklistSummary": cl_summary,
                "signature": signature,
                "signatureKeyId": "did:web:attestseal.com#signing-key-1",
                "issuer": "did:web:attestseal.com",
            }

            batch.append((json.dumps(response, separators=(",", ":")), score, recommendation, SCORING_MODEL, domain))

            if len(batch) >= BATCH_SIZE:
                write_con.executemany(
                    "UPDATE scored_results SET response_json = ?, trust_score = ?, recommendation = ?, scoring_model = ? WHERE domain = ?",
                    batch
                )
                write_con.commit()
                updated += len(batch)
                batch.clear()

            if processed % 25000 == 0:
                el = time.time() - start
                rate = processed / el
                eta = (total - processed) / rate / 60
                print(f"  {processed:,}/{total:,} ({processed*100/total:.1f}%) rate={rate:.0f}/s eta={eta:.1f}min skipped_no_raw={skipped_no_raw} errors={errors}")
        except Exception as e:
            errors += 1
            if errors <= 10:
                print(f"  ERR {domain}: {type(e).__name__}: {e}")

    if batch:
        write_con.executemany(
            "UPDATE scored_results SET response_json = ?, trust_score = ?, recommendation = ?, scoring_model = ? WHERE domain = ?",
            batch
        )
        write_con.commit()
        updated += len(batch)

    el = time.time() - start
    print(f"\n=== complete ===")
    print(f"processed: {processed:,}")
    print(f"updated:   {updated:,}")
    print(f"skipped (no raw_signals): {skipped_no_raw:,}")
    print(f"errors:    {errors}")
    print(f"elapsed:   {el:.0f}s ({el/60:.1f}min)")
    print(f"rate:      {processed/el:.0f}/s")

    con.close()
    write_con.close()

if __name__ == "__main__":
    main()
