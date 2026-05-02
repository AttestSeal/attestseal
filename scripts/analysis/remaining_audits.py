"""Remaining v1.0 pre-publish audits:
1. False-positive sample (random PROCEED rows from low-rank Tranco)
2. Stale data check (rows checked before rebrand)
3. Signature integrity (random sample re-verify)
4. PII leak check (registrations content; no PII in scored_results)
"""
import sqlite3, json, hashlib, base64, random
from nacl.signing import VerifyKey

con = sqlite3.connect('/opt/attestseal/data/attestseal.db')
con.row_factory = sqlite3.Row

print('=== AUDIT 1: false-positive sample (random PROCEED in 100K-1M range) ===')
# Load Tranco rank lookup
tranco = {}
with open('/opt/attestseal/data/tranco.csv') as f:
    for line in f:
        p = line.rstrip('\r\n').split(',', 1)
        if len(p) == 2:
            try: tranco[p[1]] = int(p[0])
            except: pass

# Random 30 PROCEED domains in 100K+ range
proceed_low_rank = []
for row in con.execute("SELECT domain, trust_score FROM scored_results WHERE recommendation = 'PROCEED'"):
    rank = tranco.get(row[0])
    if rank and rank > 100000:
        proceed_low_rank.append((row[0], row[1], rank))

random.seed(42)
sample = random.sample(proceed_low_rank, min(30, len(proceed_low_rank)))
print(f"Total PROCEED in 100K-1M range: {len(proceed_low_rank):,}")
print("Random 30 (manual review needed -- spot check for false positives):")
for d, ts, rank in sorted(sample, key=lambda x: x[2]):
    print(f"  rank {rank:>6} {d:<35} score={ts}")

print()
print('=== AUDIT 2: stale data check ===')
# Year-month distribution of checked_at
ym_counts = {}
for row in con.execute('SELECT response_json FROM scored_results'):
    try:
        d = json.loads(row[0])
        ym = (d.get('checkedAt') or '')[:7]
        ym_counts[ym] = ym_counts.get(ym, 0) + 1
    except: pass
for ym in sorted(ym_counts):
    print(f"  {ym}: {ym_counts[ym]:,}")

print()
print('=== AUDIT 3: signature integrity (random 1000 re-verify) ===')
pub = open('/opt/attestseal/keys/signing.pub', 'rb').read()
vk = VerifyKey(pub)
ok = 0; fail = 0
random.seed(7)
all_domains = [r[0] for r in con.execute('SELECT domain FROM scored_results').fetchall()]
sample_domains = random.sample(all_domains, 1000)
fail_examples = []
for d in sample_domains:
    row = con.execute('SELECT response_json FROM scored_results WHERE domain = ?', (d,)).fetchone()
    try:
        r = json.loads(row[0])
        signable = {
            'domain': r['domain'], 'signals': r.get('signals', {}), 'flags': r.get('flags', []),
            'trustScore': r['trustScore'], 'scoringModel': r['scoringModel'],
            'recommendation': r['recommendation'], 'confidence': r.get('confidence'),
            'cautionReason': r.get('cautionReason'),
        }
        canonical = json.dumps(signable, sort_keys=True, separators=(',', ':'))
        digest = hashlib.sha256(canonical.encode()).digest()
        sig_bytes = base64.b64decode(r['signature'][1:])
        vk.verify(digest, sig_bytes)
        ok += 1
    except Exception as e:
        fail += 1
        if len(fail_examples) < 3:
            fail_examples.append((d, str(e)[:80]))
print(f"verified: {ok}/{ok+fail}")
if fail_examples:
    print("failures:")
    for d, e in fail_examples:
        print(f"  {d}: {e}")

print()
print('=== AUDIT 4: PII leak check ===')
# scored_results.response_json should NEVER contain registration PII
# Search a sample for telltale patterns
pii_patterns = ['contact_email', 'ein_tax_id', 'phone_number_pii', 'home_address']
hits = 0
for row in con.execute('SELECT response_json FROM scored_results LIMIT 50000'):
    txt = row[0]
    for p in pii_patterns:
        if p in txt:
            hits += 1
            break
print(f"Sample 50K rows; PII pattern hits: {hits}")

# Also check raw_signals
hits = 0
for row in con.execute('SELECT signal_data FROM raw_signals LIMIT 50000'):
    txt = row[0]
    for p in pii_patterns:
        if p in txt:
            hits += 1
            break
print(f"Sample 50K raw_signals; PII pattern hits: {hits}")

# registrations table -- should have ENCRYPTED values (enc:v1: prefix)
print()
print("=== registrations PII encryption ===")
for row in con.execute('SELECT contact_email, phone, address FROM registrations'):
    for col in ['contact_email', 'phone', 'address']:
        v = row[col]
        if v:
            if v.startswith('enc:v1:'):
                print(f"  {col}: ENCRYPTED ({len(v)} chars)")
            else:
                print(f"  {col}: PLAINTEXT (len {len(v)}) -- LEAK!")
        else:
            print(f"  {col}: empty/null")
