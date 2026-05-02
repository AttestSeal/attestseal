"""Diagnose the score distribution problems:
1. Why are 137K DENY -- are they all really bad, or are they unscorable?
2. Why are only 30 PROCEED in 100K-1M -- is the threshold too high?
3. What does the long-tail signal profile look like?
"""
import sqlite3, json
from collections import Counter

con = sqlite3.connect('/opt/attestseal/data/attestseal.db')
con.row_factory = sqlite3.Row

# === DENY breakdown: WHY are these DENY? ===
print('=== DENY analysis: 100 sample rows ===')
deny_flags = Counter()
deny_signals_zero = 0; deny_real_problems = 0; deny_unscorable = 0
sample = con.execute("SELECT response_json FROM scored_results WHERE recommendation = 'DENY' LIMIT 5000").fetchall()
deny_signal_avgs = {'reputation': 0, 'identity': 0, 'content': 0, 'domain_age': 0, 'ssl': 0, 'dns': 0}
for row in sample:
    r = json.loads(row[0])
    flags = r.get('flags', [])
    for f in flags: deny_flags[f] += 1
    s = r.get('signals', {})
    for k in deny_signal_avgs:
        # signals.json uses camelCase from model_dump(by_alias=True)
        camel = {'reputation':'reputation','identity':'identity','content':'content','domain_age':'domainAge','ssl':'ssl','dns':'dns'}[k]
        deny_signal_avgs[k] += s.get(camel, {}).get('score', 0)
    if any(s.get(k, {}).get('score', 0) == 0 for k in ['ssl', 'reputation']):
        deny_signals_zero += 1
    if r.get('crawlability') == 'blocked':
        deny_unscorable += 1
    if 'MALWARE_DETECTED' in flags or 'PHISHING_DETECTED' in flags or 'SPAM_LISTED' in flags:
        deny_real_problems += 1
print(f"Sample size: {len(sample):,}")
print(f"Sample with crawlability=blocked: {deny_unscorable:,} ({deny_unscorable*100/len(sample):.1f}%)")
print(f"Sample with real reputation problems (malware/phishing/spam): {deny_real_problems:,}")
print(f"Sample with ssl OR reputation score=0: {deny_signals_zero:,}")
print(f"Average signal scores in DENY:")
for k, v in deny_signal_avgs.items():
    print(f"  {k}: {v/len(sample):.1f}")
print(f"Top flags in DENY:")
for f, n in deny_flags.most_common(15):
    print(f"  {f}: {n}")

# === PROCEED in 100K-1M: very few -- what's the score profile? ===
print()
print('=== PROCEED in 100K-1M analysis ===')
tranco = {}
with open('/opt/attestseal/data/tranco.csv') as f:
    for line in f:
        p = line.rstrip('\r\n').split(',', 1)
        if len(p) == 2:
            try: tranco[p[1]] = int(p[0])
            except: pass

# What's the score distribution at 70-79 in 100K-1M? These are the "almost PROCEED" candidates
candidates = []
for row in con.execute("SELECT domain, trust_score, recommendation, response_json FROM scored_results WHERE trust_score BETWEEN 70 AND 79"):
    r = tranco.get(row['domain'])
    if r and r > 100000 and row['recommendation'] == 'CAUTION':
        candidates.append((row['domain'], row['trust_score'], r))
print(f"100K-1M domains scoring 70-79 but CAUTION: {len(candidates):,}")
print("If we lowered PROCEED threshold to 70, this many would shift CAUTION->PROCEED in long tail.")

# Same for 65-69
near_misses = 0
for row in con.execute("SELECT domain, trust_score FROM scored_results WHERE trust_score BETWEEN 65 AND 69 AND recommendation = 'CAUTION'"):
    r = tranco.get(row[0])
    if r and r > 100000:
        near_misses += 1
print(f"100K-1M scoring 65-69: {near_misses:,}")

# === infrastructure inheritance: how many cloudfront.net subdomains are in the DB? ===
print()
print('=== infrastructure-suffix domains in DB ===')
suffixes = ['.cloudfront.net', '.akamaiedge.net', '.googleusercontent.com', '.azurewebsites.net', '.windows.net']
for s in suffixes:
    n = con.execute(f"SELECT COUNT(*) FROM scored_results WHERE domain LIKE '%{s}'").fetchone()[0]
    print(f"  domains ending in {s}: {n:,}")

# Score range histogram for the 30 PROCEED in long tail
print()
print('=== are PROCEED domains actually well-anchored? ===')
print('Score range for the 30 PROCEED in 100K-1M (above):')
for row in con.execute("SELECT domain, trust_score, response_json FROM scored_results WHERE recommendation = 'PROCEED' LIMIT 50"):
    r = tranco.get(row[0])
    if r and r > 100000:
        d = json.loads(row[2])
        print(f"  rank {r:>6} {row[0]:<35} score={row[1]} brand={d.get('brandTier')} cat={d.get('siteCategory')}")
