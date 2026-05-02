import sqlite3, json
con = sqlite3.connect('/opt/attestseal/data/attestseal.db')

# Load Tranco top-100
top100 = []
with open('/opt/attestseal/data/tranco.csv') as f:
    for line in f:
        p = line.rstrip('\r\n').split(',', 1)
        if len(p) == 2:
            try:
                r = int(p[0])
                if r <= 100:
                    top100.append((r, p[1]))
                if r > 100: break
            except: pass

p_count = c_count = d_count = m_count = 0
non_proceed = []
proceed_scores = []
for rank, domain in top100:
    row = con.execute('SELECT trust_score, recommendation, response_json FROM scored_results WHERE domain = ?', (domain,)).fetchone()
    if row:
        rec = row[1]
        if rec == 'PROCEED':
            p_count += 1
            proceed_scores.append(row[0])
        elif rec == 'CAUTION':
            c_count += 1
        elif rec == 'DENY':
            d_count += 1
        if rec != 'PROCEED' and len(non_proceed) < 30:
            r = json.loads(row[2])
            non_proceed.append((rank, domain, row[0], rec, r.get('confidence'), r.get('cautionReason'), r.get('siteCategory'), r.get('brandTier')))
    else:
        m_count += 1

print(f"Top-100 -- PROCEED: {p_count} | CAUTION: {c_count} | DENY: {d_count} | NOT_IN_DB: {m_count}")
print(f"PROCEED score range: {min(proceed_scores)} - {max(proceed_scores)} avg={sum(proceed_scores)/len(proceed_scores):.1f}")
print()
print("Top-100 not PROCEED:")
for rank, d, ts, rec, conf, cr, cat, bt in non_proceed:
    print(f"  rank {rank:>3} {d:<30} {ts:>3} {rec:<8} conf={conf:<7} cat={cat:<14} brand={bt:<11} cr={cr}")

# Score histogram
print()
print("=== histogram (10-pt buckets) ===")
buckets = con.execute('SELECT (trust_score / 10) * 10 AS b, COUNT(*) FROM scored_results GROUP BY b ORDER BY b').fetchall()
total = sum(b[1] for b in buckets)
for b, n in buckets:
    bar = '#' * int(60 * n / total)
    print(f"  {b:3d}-{b+9:3d}: {n:>7,} ({n*100/total:>5.2f}%)  {bar}")
