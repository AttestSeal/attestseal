"""Post-v1.5 audit: reads actual scored_results to verify the rescore
landed and the distribution matches the projection.
"""
import sqlite3, json, random, sys
from collections import Counter

DB = '/opt/attestseal/data/attestseal.db'
con = sqlite3.connect(DB)
con.row_factory = sqlite3.Row

print('=' * 78)
print('POST v1.5 RESCORE AUDIT')
print('=' * 78)

# 1. Scoring model coverage
rows = con.execute(
    "SELECT scoring_model, COUNT(*) FROM scored_results GROUP BY scoring_model"
).fetchall()
print('\nScoring model coverage:')
for r in rows:
    print(f"  {r[0]:<30} {r[1]:>10,}")

# 2. Recommendation distribution
total = con.execute("SELECT COUNT(*) FROM scored_results").fetchone()[0]
rec_rows = con.execute(
    "SELECT recommendation, COUNT(*) FROM scored_results GROUP BY recommendation"
).fetchall()
print('\nRecommendation distribution (target: ~50K PROCEED, ~795K CAUTION, ~155K DENY):')
for r in rec_rows:
    pct = r[1] * 100 / total
    print(f"  {r[0]:<10} {r[1]:>10,}  ({pct:.2f}%)")

# 3. Score histogram
print('\nScore histogram (5-point buckets):')
hist = Counter()
for row in con.execute("SELECT trust_score FROM scored_results"):
    hist[(row[0] // 5) * 5] += 1
for b in sorted(hist):
    bar = '#' * int(60 * hist[b] / total)
    print(f"  {b:>3}-{b+4:<3}  {hist[b]:>8,}  {bar}")

# 4. PROCEED / CAUTION / DENY rate by Tranco rank bucket
tranco = {}
with open('/opt/attestseal/data/tranco.csv') as f:
    for line in f:
        p = line.rstrip('\r\n').split(',', 1)
        if len(p) == 2:
            try: tranco[p[1]] = int(p[0])
            except: pass

print(f'\nDistribution by Tranco bucket (target top-100: 95+ PROCEED, top-10K: ~81%):')
print(f"{'bucket':<14} {'count':<10} {'P':<8} {'C':<8} {'D':<8} {'P%':<6} {'avg':<6} {'med':<6}")
buckets = [
    (1, 100, 'top-100'),
    (101, 1000, 'top-1K'),
    (1001, 10000, 'top-10K'),
    (10001, 100000, 'top-100K'),
    (100001, 500000, '100K-500K'),
    (500001, 1000000, '500K-1M'),
]
for lo, hi, name in buckets:
    domains_in_bucket = [d for d, r in tranco.items() if lo <= r <= hi]
    p = c = d = 0; scores = []
    for dn in domains_in_bucket:
        row = con.execute(
            'SELECT trust_score, recommendation FROM scored_results WHERE domain = ?',
            (dn,)
        ).fetchone()
        if row:
            scores.append(row[0])
            r = row[1][0]
            if r == 'P': p += 1
            elif r == 'C': c += 1
            elif r == 'D': d += 1
    total_b = p + c + d
    if scores:
        scores_sorted = sorted(scores)
        med = scores_sorted[len(scores_sorted)//2]
        avg = sum(scores) / len(scores)
        print(f"{name:<14} {total_b:<10,} {p:<8,} {c:<8,} {d:<8,} "
              f"{p*100/max(total_b,1):<6.1f} {avg:<6.1f} {med}")

# 5. Top-100 sanity: list any top-100 domains still NOT PROCEED, with score
print('\nTop-100 domains NOT PROCEED (target: <5):')
violators = []
for dn, rank in sorted(tranco.items(), key=lambda kv: kv[1])[:100]:
    row = con.execute(
        'SELECT trust_score, recommendation FROM scored_results WHERE domain = ?',
        (dn,)
    ).fetchone()
    if row and row[1] != 'PROCEED':
        violators.append((rank, dn, row[0], row[1]))
print(f"  count: {len(violators)}")
for rank, dn, score, rec in violators[:20]:
    print(f"    rank={rank:>3}  {dn:<35} score={score} {rec}")

# 6. Signature integrity on a 1000-row random sample
print('\nSignature integrity check (1000 random sample):')
sys.path.insert(0, '/opt/attestseal/server')
import os
os.environ.setdefault("ATS_DATA_DIR", "/opt/attestseal/data")
os.environ.setdefault("ATS_KEY_DIR", "/opt/attestseal/keys")
from app.signing import verify_signature

domains_sample = [r[0] for r in con.execute(
    "SELECT domain FROM scored_results ORDER BY random() LIMIT 1000"
).fetchall()]

passed = failed = 0
for dn in domains_sample:
    row = con.execute(
        "SELECT response_json FROM scored_results WHERE domain = ?", (dn,)
    ).fetchone()
    if not row: continue
    r = json.loads(row[0])
    signable = {
        "domain": r["domain"],
        "signals": r["signals"],
        "flags": r["flags"],
        "trustScore": r["trustScore"],
        "scoringModel": r["scoringModel"],
        "recommendation": r["recommendation"],
        "confidence": r.get("confidence"),
        "cautionReason": r.get("cautionReason"),
    }
    try:
        ok = verify_signature(signable, r["signature"])
        if ok: passed += 1
        else: failed += 1
    except Exception as e:
        failed += 1
print(f"  {passed} pass / {failed} fail of {passed+failed}")

# 7. Confidence + cautionReason coverage
print('\nConfidence coverage:')
for row in con.execute(
    "SELECT json_extract(response_json, '$.confidence'), COUNT(*) "
    "FROM scored_results GROUP BY 1"
):
    print(f"  {str(row[0]):<10} {row[1]:>10,}")

print('\ncautionReason coverage (CAUTION rows only):')
for row in con.execute(
    "SELECT json_extract(response_json, '$.cautionReason'), COUNT(*) "
    "FROM scored_results WHERE recommendation = 'CAUTION' GROUP BY 1"
):
    print(f"  {str(row[0]):<25} {row[1]:>10,}")

# 8. Brand tier coverage
print('\nbrandTier coverage:')
for row in con.execute(
    "SELECT json_extract(response_json, '$.brandTier'), COUNT(*) "
    "FROM scored_results GROUP BY 1"
):
    print(f"  {str(row[0]):<15} {row[1]:>10,}")

# 9. Site category (infrastructure vs consumer)
print('\nsiteCategory coverage:')
for row in con.execute(
    "SELECT json_extract(response_json, '$.siteCategory'), COUNT(*) "
    "FROM scored_results GROUP BY 1"
):
    print(f"  {str(row[0]):<20} {row[1]:>10,}")

print()
print('=' * 78)
print('AUDIT COMPLETE')
print('=' * 78)
