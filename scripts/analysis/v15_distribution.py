"""Comprehensive v1.5 distribution audit. Single streaming pass over
scored_results so we can cross-tab everything without re-querying."""
import sqlite3, json, time
from collections import Counter, defaultdict

DB = "/opt/attestseal/data/attestseal.db"

# Load Tranco rank lookup once (fast, ~200ms)
tranco = {}
with open("/opt/attestseal/data/tranco.csv") as f:
    for line in f:
        p = line.rstrip("\r\n").split(",", 1)
        if len(p) == 2:
            try:
                tranco[p[1]] = int(p[0])
            except ValueError:
                pass

con = sqlite3.connect(DB)
con.row_factory = sqlite3.Row

def bucket_for_rank(r):
    if r is None: return "no-rank"
    if r <= 100: return "top-100"
    if r <= 1000: return "top-1K"
    if r <= 10000: return "top-10K"
    if r <= 50000: return "top-50K"
    if r <= 100000: return "top-100K"
    if r <= 500000: return "100K-500K"
    if r <= 1000000: return "500K-1M"
    return "no-rank"

BUCKET_ORDER = ["top-100", "top-1K", "top-10K", "top-50K", "top-100K",
                "100K-500K", "500K-1M", "no-rank"]

# Streaming counters
total = 0
score_hist = Counter()                        # 5-pt bucket -> count
rec = Counter()                               # PROCEED/CAUTION/DENY -> count
brand = Counter()                             # well_known/scored -> count
site_cat = Counter()                          # consumer/infrastructure -> count
confidence = Counter()
caution_reason = Counter()                    # only CAUTION rows
flag_count = Counter()                        # individual flag -> count
model = Counter()                             # scoring_model -> count

# Cross-tabs
rec_by_brand = defaultdict(Counter)           # brand_tier -> rec -> count
rec_by_site_cat = defaultdict(Counter)        # site_cat -> rec -> count
rec_by_bucket = defaultdict(Counter)          # rank_bucket -> rec -> count
score_stats_by_bucket = defaultdict(list)     # rank_bucket -> [scores]
rec_by_confidence = defaultdict(Counter)      # confidence -> rec -> count
caution_reason_by_bucket = defaultdict(Counter)  # bucket -> reason -> count

# Top-N
top100_violators = []                         # list of (rank, domain, score, rec, flags)
proceed_high_score = []                       # 90+ PROCEED, sample
deny_with_high_signals = []                   # DENY with rep>=80

t0 = time.time()
cur = con.cursor()
cur.execute("SELECT domain, trust_score, recommendation, scoring_model, response_json FROM scored_results")

for row in cur:
    total += 1
    domain = row[0]
    score = row[1]
    rec_val = row[2]
    sm = row[3]
    r = json.loads(row[4])

    score_hist[(score // 5) * 5] += 1
    rec[rec_val] += 1
    model[sm] += 1
    brand[r.get("brandTier") or "scored"] += 1
    site_cat[r.get("siteCategory") or "consumer"] += 1
    conf = r.get("confidence") or "unknown"
    confidence[conf] += 1

    flags = r.get("flags") or []
    for f in flags:
        flag_count[f] += 1

    rank = tranco.get(domain)
    bkt = bucket_for_rank(rank)
    rec_by_bucket[bkt][rec_val] += 1
    score_stats_by_bucket[bkt].append(score)
    rec_by_brand[r.get("brandTier") or "scored"][rec_val] += 1
    rec_by_site_cat[r.get("siteCategory") or "consumer"][rec_val] += 1
    rec_by_confidence[conf][rec_val] += 1

    if rec_val == "CAUTION":
        cr = r.get("cautionReason") or "unknown"
        caution_reason[cr] += 1
        caution_reason_by_bucket[bkt][cr] += 1

    if rank is not None and rank <= 100 and rec_val != "PROCEED":
        top100_violators.append((rank, domain, score, rec_val, flags))

    if score >= 90 and rec_val == "PROCEED" and len(proceed_high_score) < 10:
        proceed_high_score.append((rank, domain, score))

    if rec_val == "DENY" and r.get("signals", {}).get("reputation", {}).get("score", 0) >= 80 \
            and len(deny_with_high_signals) < 10:
        deny_with_high_signals.append((rank, domain, score, flags[:5]))

con.close()
elapsed = time.time() - t0


def pct(n, d): return (n * 100 / d) if d else 0


def fmt_n(x): return f"{x:,}"


print("=" * 86)
print("ATTESTSEAL v1.5 DISTRIBUTION AUDIT")
print("=" * 86)
print(f"Rows scanned: {fmt_n(total)} in {elapsed:.1f}s\n")

print("[1] SCORING MODEL COVERAGE")
print("-" * 86)
for k, v in model.most_common():
    print(f"  {k:<35} {fmt_n(v):>12}  ({pct(v,total):.2f}%)")

print("\n[2] RECOMMENDATION DISTRIBUTION")
print("-" * 86)
for k in ["PROCEED", "CAUTION", "DENY"]:
    print(f"  {k:<10} {fmt_n(rec[k]):>12}  ({pct(rec[k],total):.2f}%)")

print("\n[3] SCORE HISTOGRAM (5-point buckets)")
print("-" * 86)
print(f"  {'range':<10} {'count':<10} {'%':<6}  bar (1 char per 0.4%)")
for b in sorted(score_hist):
    cnt = score_hist[b]
    bar = "#" * int(pct(cnt, total) / 0.4)
    print(f"  {b}-{b+4:<6} {fmt_n(cnt):<10} {pct(cnt,total):>5.2f}  {bar}")

print("\n[4] DISTRIBUTION BY TRANCO BUCKET")
print("-" * 86)
print(f"  {'bucket':<14} {'count':<10} {'P':<10} {'C':<10} {'D':<10} {'P%':<6} {'avg':<6} {'med':<6}")
for bkt in BUCKET_ORDER:
    if bkt not in rec_by_bucket: continue
    c = rec_by_bucket[bkt]
    p, ca, d = c["PROCEED"], c["CAUTION"], c["DENY"]
    tot = p + ca + d
    scores = score_stats_by_bucket[bkt]
    avg = sum(scores) / len(scores) if scores else 0
    med = sorted(scores)[len(scores)//2] if scores else 0
    print(f"  {bkt:<14} {fmt_n(tot):<10} {fmt_n(p):<10} {fmt_n(ca):<10} {fmt_n(d):<10} "
          f"{pct(p,tot):<6.1f} {avg:<6.1f} {med}")

print("\n[5] BRAND TIER x RECOMMENDATION")
print("-" * 86)
print(f"  {'brandTier':<15} {'count':<10} {'P':<10} {'C':<10} {'D':<10} {'P%':<6}")
for bt in ["well_known", "scored"]:
    if bt not in rec_by_brand: continue
    c = rec_by_brand[bt]
    p, ca, d = c["PROCEED"], c["CAUTION"], c["DENY"]
    tot = p + ca + d
    print(f"  {bt:<15} {fmt_n(tot):<10} {fmt_n(p):<10} {fmt_n(ca):<10} {fmt_n(d):<10} {pct(p,tot):<6.1f}")

print("\n[6] SITE CATEGORY x RECOMMENDATION")
print("-" * 86)
print(f"  {'siteCategory':<15} {'count':<10} {'P':<10} {'C':<10} {'D':<10} {'P%':<6}")
for sc in sorted(rec_by_site_cat):
    c = rec_by_site_cat[sc]
    p, ca, d = c["PROCEED"], c["CAUTION"], c["DENY"]
    tot = p + ca + d
    print(f"  {sc:<15} {fmt_n(tot):<10} {fmt_n(p):<10} {fmt_n(ca):<10} {fmt_n(d):<10} {pct(p,tot):<6.1f}")

print("\n[7] CONFIDENCE x RECOMMENDATION")
print("-" * 86)
print(f"  {'confidence':<15} {'count':<10} {'P':<10} {'C':<10} {'D':<10} {'P%':<6}")
for cf in ["high", "medium", "low", "unknown"]:
    if cf not in rec_by_confidence: continue
    c = rec_by_confidence[cf]
    p, ca, d = c["PROCEED"], c["CAUTION"], c["DENY"]
    tot = p + ca + d
    print(f"  {cf:<15} {fmt_n(tot):<10} {fmt_n(p):<10} {fmt_n(ca):<10} {fmt_n(d):<10} {pct(p,tot):<6.1f}")

print("\n[8] CAUTION REASON BREAKDOWN (CAUTION rows only)")
print("-" * 86)
caution_total = sum(caution_reason.values())
for k, v in caution_reason.most_common():
    print(f"  {str(k):<25} {fmt_n(v):>12}  ({pct(v,caution_total):.2f}%)")

print("\n[9] TOP FLAGS")
print("-" * 86)
for k, v in flag_count.most_common(15):
    print(f"  {k:<30} {fmt_n(v):>12}  ({pct(v,total):.2f}%)")

print("\n[10] TOP-100 TRANCO -- NOT PROCEED")
print("-" * 86)
print(f"  count: {len(top100_violators)} of 100")
infra_keywords = ["dns", "cdn", "akam", "cloudfront", "edge", "trafficmanager",
                  "windowsupdate", "office.net", "apple-dns", "gvt1", "gvt2",
                  "windows.net", "tiktokcdn", "aaplimg", "gtld", "domaincontrol",
                  "ezviz", "hicloudcam", "ripn", "googleusercontent"]
infra_violators = [v for v in top100_violators if any(kw in v[1] for kw in infra_keywords)]
nonssl_violators = [v for v in top100_violators if "NO_SSL" in v[4]]
print(f"  with NO_SSL flag: {len(nonssl_violators)}")
print(f"  matching infra keyword: {len(infra_violators)}")
print(f"\n  Full list:")
for rank, dom, sc, rc, fl in sorted(top100_violators):
    safety = "NO_SSL" if "NO_SSL" in fl else ("clean" if not fl else fl[0])
    print(f"    rank={rank:>3}  {dom:<35} score={sc} {rc:<8} {safety}")

print("\n[11] HIGH-SCORE PROCEED SAMPLE (score >= 90, first 10)")
print("-" * 86)
for rk, dom, sc in proceed_high_score:
    print(f"  rank={rk}  {dom}  score={sc}")

print("\n[12] DENY-WITH-HIGH-REP (sanity: do any look mis-classified?)")
print("-" * 86)
for rk, dom, sc, fl in deny_with_high_signals:
    print(f"  rank={rk}  {dom}  score={sc}  flags={fl}")

print()
print("=" * 86)
print("AUDIT COMPLETE")
print("=" * 86)
