"""Codex pre-commit audits for v1.5:
A. telekom.de deep dive (why it's CAUTION at rank 74 with no NO_SSL flag)
B. 70-74 earned-PROCEED sample (the new band that v1.5 opens up)
C. Parent-inheritance lift: which 37 infrastructure rows got PROCEED via parent
D. Reputation-source coverage: are non-Tranco signals actually firing or
   are we calling everything 'clean' just because Tranco-ranked?
"""
import sqlite3, json, random
from collections import Counter

DB = "/opt/attestseal/data/attestseal.db"
con = sqlite3.connect(DB)
con.row_factory = sqlite3.Row

print("=" * 86)
print("A. telekom.de DEEP DIVE")
print("=" * 86)
row = con.execute(
    "SELECT trust_score, recommendation, response_json FROM scored_results WHERE domain = ?",
    ("telekom.de",),
).fetchone()
raw_row = con.execute(
    "SELECT signal_data FROM raw_signals WHERE domain = ? ORDER BY checked_at DESC LIMIT 1",
    ("telekom.de",),
).fetchone()
if row:
    r = json.loads(row[2])
    raw = json.loads(raw_row[0]) if raw_row else {}
    print(f"  trustScore={row[0]} recommendation={row[1]} brandTier={r.get('brandTier')}")
    print(f"  flags={r.get('flags')}")
    print(f"  reputation.trancoRank={raw.get('reputation', {}).get('trancoRank')}")
    print(f"  reputation: malware={raw.get('reputation', {}).get('malware')} "
          f"phishing={raw.get('reputation', {}).get('phishing')} "
          f"spamListed={raw.get('reputation', {}).get('spamListed')}")
    print(f"  reputation.score (raw)={raw.get('reputation', {}).get('score')}")
    print(f"  ssl.valid={raw.get('ssl', {}).get('valid')}")
    print(f"  ssl.tlsVersion={raw.get('ssl', {}).get('tlsVersion')}")
    print(f"  domainAge.registeredDate={raw.get('domainAge', {}).get('registeredDate')}")
    print(f"  domainAge.band={raw.get('domainAge', {}).get('band')}")
    print(f"  identity={raw.get('identity', {})}")
    print(f"  signals.scores: rep={r.get('signals', {}).get('reputation', {}).get('score')} "
          f"id={r.get('signals', {}).get('identity', {}).get('score')} "
          f"age={r.get('signals', {}).get('domainAge', {}).get('score')} "
          f"ssl={r.get('signals', {}).get('ssl', {}).get('score')} "
          f"content={r.get('signals', {}).get('content', {}).get('score')} "
          f"dns={r.get('signals', {}).get('dns', {}).get('score')}")

print("\n" + "=" * 86)
print("B. 70-74 EARNED-PROCEED SAMPLE (10 random rows; flag profile of band)")
print("=" * 86)
sample = con.execute(
    "SELECT domain, trust_score, response_json FROM scored_results "
    "WHERE trust_score BETWEEN 70 AND 74 AND recommendation = 'PROCEED' "
    "ORDER BY random() LIMIT 10"
).fetchall()
flag_band = Counter()
brand_band = Counter()
total_70_74 = con.execute(
    "SELECT COUNT(*) FROM scored_results "
    "WHERE trust_score BETWEEN 70 AND 74 AND recommendation = 'PROCEED'"
).fetchone()[0]
print(f"  total earned-PROCEED in 70-74 band: {total_70_74:,}")
print(f"\n  Sample:")
for r in sample:
    j = json.loads(r[2])
    print(f"    {r[0]:<35} score={r[1]} brandTier={j.get('brandTier')} "
          f"confidence={j.get('confidence')} flags={j.get('flags')}")
# Brand tier breakdown of the 70-74 band
for r in con.execute(
    "SELECT json_extract(response_json, '$.brandTier'), COUNT(*) "
    "FROM scored_results WHERE trust_score BETWEEN 70 AND 74 AND recommendation = 'PROCEED' "
    "GROUP BY 1"
):
    print(f"  brandTier {r[0]:<15} {r[1]:,}")

print("\n" + "=" * 86)
print("C. INFRASTRUCTURE-PROCEED ROWS (the 37 that landed PROCEED via parent)")
print("=" * 86)
rows = con.execute(
    "SELECT domain, trust_score, response_json FROM scored_results "
    "WHERE json_extract(response_json, '$.siteCategory') = 'infrastructure' "
    "AND recommendation = 'PROCEED' "
    "ORDER BY trust_score DESC"
).fetchall()
print(f"  count: {len(rows)}")
for r in rows:
    j = json.loads(r[2])
    raw_r = con.execute(
        "SELECT signal_data FROM raw_signals WHERE domain = ? ORDER BY checked_at DESC LIMIT 1",
        (r[0],),
    ).fetchone()
    raw_d = json.loads(raw_r[0]) if raw_r else {}
    pc = raw_d.get("identity", {}).get("parentCompany") or {}
    print(f"    {r[0]:<35} score={r[1]} brandTier={j.get('brandTier'):<10} "
          f"parent={pc.get('parent','-'):<20} category={pc.get('category','-')}")

print("\n" + "=" * 86)
print("D. REPUTATION-SOURCE COVERAGE (sample rep score=82+, what evidence?)")
print("=" * 86)
# Spamhaus, SURBL, URLhaus, Google Safe Browsing all leave per-source detail
# in raw_signals.reputation.blocklists. Let's see how many rows have non-empty
# blocklist detail vs Tranco-only.
counts = {"has_blocklist_detail": 0, "tranco_only": 0, "no_data": 0}
sample_per_source = {"spamhaus": [], "surbl": [], "urlhaus": [], "safe_browsing": [], "tranco_only": []}
TOTAL_SAMPLE = 50000
processed = 0
for r in con.execute(
    f"SELECT domain, signal_data FROM raw_signals ORDER BY random() LIMIT {TOTAL_SAMPLE}"
):
    raw_d = json.loads(r[1])
    rep = raw_d.get("reputation", {})
    bl = rep.get("blocklists") or {}
    if bl:
        counts["has_blocklist_detail"] += 1
        for src in ["spamhaus", "surbl", "urlhaus", "safe_browsing"]:
            if src in str(bl).lower() and len(sample_per_source[src]) < 3:
                sample_per_source[src].append((r[0], bl))
    elif rep.get("trancoRank") is not None:
        counts["tranco_only"] += 1
        if len(sample_per_source["tranco_only"]) < 3:
            sample_per_source["tranco_only"].append((r[0], rep))
    else:
        counts["no_data"] += 1
    processed += 1
print(f"  Sample size: {processed:,}")
for k, v in counts.items():
    pct = (v * 100 / processed) if processed else 0
    print(f"  {k:<25} {v:>10,}  ({pct:.2f}%)")
# Also print the structure shape of raw_signals.reputation.blocklists for one
# row that has it
print("\n  Sample raw_signals.reputation.blocklists shape:")
for src, samples in sample_per_source.items():
    if samples:
        for dom, payload in samples[:1]:
            short = json.dumps(payload, indent=2)[:400]
            print(f"    [{src}] {dom}:\n      {short}")
            print()

con.close()
