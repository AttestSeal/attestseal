"""Visualize the current distribution + simulate what alternative
scoring rules would do, so we can decide the cleanest path."""
import sqlite3, json
from collections import Counter

con = sqlite3.connect('/opt/attestseal/data/attestseal.db')
con.row_factory = sqlite3.Row

# Load Tranco rank lookup
tranco = {}
with open('/opt/attestseal/data/tranco.csv') as f:
    for line in f:
        p = line.rstrip('\r\n').split(',', 1)
        if len(p) == 2:
            try: tranco[p[1]] = int(p[0])
            except: pass

print('=' * 78)
print('CURRENT DISTRIBUTION (post v1.4, post-rescore #2)')
print('=' * 78)

# Score histogram with PROCEED/CAUTION/DENY split
bucket_data = {}
for row in con.execute("SELECT trust_score, recommendation FROM scored_results"):
    b = (row[0] // 5) * 5  # 5-point buckets for finer view
    if b not in bucket_data:
        bucket_data[b] = {'P': 0, 'C': 0, 'D': 0}
    bucket_data[b][row[1][0]] += 1

print('\nScore histogram (5-point buckets, P=PROCEED C=CAUTION D=DENY):')
print(f"{'score':<10} {'PROCEED':<10} {'CAUTION':<10} {'DENY':<10} {'total':<10} bar")
total_all = sum(sum(v.values()) for v in bucket_data.values())
for b in sorted(bucket_data):
    bd = bucket_data[b]
    total = bd['P'] + bd['C'] + bd['D']
    bar_p = '#' * int(40 * bd['P'] / total_all)
    bar_c = '.' * int(40 * bd['C'] / total_all)
    bar_d = 'x' * int(40 * bd['D'] / total_all)
    print(f"{b:>3}-{b+4:<3}    {bd['P']:<10,} {bd['C']:<10,} {bd['D']:<10,} {total:<10,} {bar_p}{bar_c}{bar_d}")

print()
print('=' * 78)
print('PROCEED RATE BY TRANCO RANK BUCKET (does the score follow rank?)')
print('=' * 78)
print(f"{'bucket':<14} {'count':<10} {'P':<8} {'C':<8} {'D':<8} {'P%':<6} {'avg score':<10} {'med score':<10}")
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
        row = con.execute('SELECT trust_score, recommendation FROM scored_results WHERE domain = ?', (dn,)).fetchone()
        if row:
            scores.append(row[0])
            r = row[1][0]
            if r == 'P': p += 1
            elif r == 'C': c += 1
            elif r == 'D': d += 1
    total = p + c + d
    if scores:
        scores_sorted = sorted(scores)
        med = scores_sorted[len(scores_sorted)//2]
        avg = sum(scores)/len(scores)
        print(f"{name:<14} {total:<10,} {p:<8,} {c:<8,} {d:<8,} {p*100/max(total,1):<6.1f} {avg:<10.1f} {med}")

print()
print('=' * 78)
print('SIMULATION 1: just lower PROCEED threshold to 70 (clean, no rank logic)')
print('=' * 78)
# Re-classify based on score >= 70 (with valid SSL + clean rep would be the actual rule, but let's see threshold-only first)
new_p = new_c = new_d = 0
for row in con.execute("SELECT trust_score, response_json FROM scored_results"):
    r = json.loads(row[1])
    flags = r.get('flags', [])
    has_rep_problem = any(f in flags for f in ['MALWARE_DETECTED', 'PHISHING_DETECTED', 'SPAM_LISTED'])
    has_no_ssl = 'NO_SSL' in flags
    if has_no_ssl or has_rep_problem:
        new_d += 1
    elif row[0] >= 70:
        new_p += 1
    else:
        new_c += 1
total = new_p + new_c + new_d
print(f"PROCEED: {new_p:,} ({new_p*100/total:.1f}%)  -- was 31,571 (3.2%)")
print(f"CAUTION: {new_c:,} ({new_c*100/total:.1f}%)  -- was 832,510 (83.2%)")
print(f"DENY:    {new_d:,} ({new_d*100/total:.1f}%)  -- was 136,977 (13.7%)")

print()
print('=' * 78)
print('SIMULATION 2: lower threshold to 70 + brand anchor floors by bucket')
print('=' * 78)
# Apply per-bucket floors then threshold 70
new_p = new_c = new_d = 0
for row in con.execute("SELECT domain, trust_score, response_json FROM scored_results"):
    r = json.loads(row[2])
    flags = r.get('flags', [])
    has_rep_problem = any(f in flags for f in ['MALWARE_DETECTED', 'PHISHING_DETECTED', 'SPAM_LISTED'])
    has_no_ssl = 'NO_SSL' in flags
    score = row[1]
    rank = tranco.get(row[0])
    # Apply per-bucket floor (only if SSL valid + clean rep)
    if not has_no_ssl and not has_rep_problem and rank:
        if rank <= 100: score = max(score, 90)
        elif rank <= 1000: score = max(score, 85)
        elif rank <= 10000: score = max(score, 80)
        elif rank <= 50000: score = max(score, 75)
    if has_no_ssl or has_rep_problem:
        new_d += 1
    elif score >= 70:
        new_p += 1
    else:
        new_c += 1
total = new_p + new_c + new_d
print(f"PROCEED: {new_p:,} ({new_p*100/total:.1f}%)")
print(f"CAUTION: {new_c:,} ({new_c*100/total:.1f}%)")
print(f"DENY:    {new_d:,} ({new_d*100/total:.1f}%)")

print()
print('=' * 78)
print('SIMULATION 3: tune Tranco curve so high-rank reputation gets more credit')
print('=' * 78)
# Current rank_to_score curve probably crushes long tail. What if we boost?
# Heuristic: any domain in top-300K gets a baseline reputation lift
# (Need to re-derive scores to do this properly; here just simulate by adding bonus)
# Skip this without rerun; show what RE-RANKED would look like with PROCEED threshold 70

# Also: what's the rank_to_score curve actually look like?
import sys
sys.path.insert(0, '/opt/attestseal/server')
from app.collectors.tranco import rank_to_score
print(f"Current rank_to_score curve:")
for r in [1, 10, 100, 1000, 5000, 10000, 50000, 100000, 250000, 500000, 750000, 999000]:
    print(f"  rank {r:>7}: rep_score = {rank_to_score(r)}")

print()
print('=' * 78)
print('CHART: PROCEED %% by Tranco bucket -- current vs simulation 2')
print('=' * 78)
print(f"{'bucket':<14} {'current %P':<14} {'sim 2 %P':<14}")
for lo, hi, name in buckets:
    domains_in_bucket = [d for d, r in tranco.items() if lo <= r <= hi]
    cur_p = 0; sim2_p = 0; total = 0
    for dn in domains_in_bucket:
        row = con.execute('SELECT trust_score, recommendation, response_json FROM scored_results WHERE domain = ?', (dn,)).fetchone()
        if row:
            total += 1
            if row[1] == 'PROCEED': cur_p += 1
            r = json.loads(row[2])
            flags = r.get('flags', [])
            has_rep_problem = any(f in flags for f in ['MALWARE_DETECTED', 'PHISHING_DETECTED', 'SPAM_LISTED'])
            has_no_ssl = 'NO_SSL' in flags
            score = row[0]
            rank = tranco.get(dn)
            if not has_no_ssl and not has_rep_problem and rank:
                if rank <= 100: score = max(score, 90)
                elif rank <= 1000: score = max(score, 85)
                elif rank <= 10000: score = max(score, 80)
                elif rank <= 50000: score = max(score, 75)
            if not has_no_ssl and not has_rep_problem and score >= 70:
                sim2_p += 1
    print(f"{name:<14} {cur_p*100/max(total,1):<14.1f} {sim2_p*100/max(total,1):<14.1f}")
