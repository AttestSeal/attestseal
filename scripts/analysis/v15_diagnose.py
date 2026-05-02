"""Diagnose why specific top-100 violators didn't get the v1.5 bucket floor."""
import sqlite3, json, sys

con = sqlite3.connect("/opt/attestseal/data/attestseal.db")
con.row_factory = sqlite3.Row

domains = sys.argv[1:] or [
    "cloudfront.net", "akamai.net", "live.com", "msn.com", "gtld-servers.net",
    "akamaiedge.net", "trafficmanager.net", "windowsupdate.com", "office.net",
    "apple-dns.net", "amazon.com", "google.com", "microsoft.com",
]

for d in domains:
    row = con.execute(
        "SELECT trust_score, recommendation, response_json FROM scored_results WHERE domain = ?",
        (d,),
    ).fetchone()
    if not row:
        print(f"{d}: NOT FOUND")
        continue
    r = json.loads(row[2])
    raw_row = con.execute(
        "SELECT signal_data FROM raw_signals WHERE domain = ? ORDER BY checked_at DESC LIMIT 1",
        (d,),
    ).fetchone()
    raw = json.loads(raw_row[0]) if raw_row else {}
    sigs = r.get("signals", {})
    print(f"\n=== {d} ===")
    print(f"  trustScore={row[0]} recommendation={row[1]}")
    print(f"  scoringModel={r.get('scoringModel')} brandTier={r.get('brandTier')}")
    print(f"  flags={r.get('flags')}")
    print(f"  rank={raw.get('reputation', {}).get('trancoRank')}")
    print(f"  ssl.valid={raw.get('ssl', {}).get('valid')}")
    print(f"  age.registeredDate={raw.get('domainAge', {}).get('registeredDate')}")
    print(f"  age.band={raw.get('domainAge', {}).get('band')}")
    print(f"  reputation.malware={raw.get('reputation', {}).get('malware')}"
          f" phishing={raw.get('reputation', {}).get('phishing')}"
          f" spam={raw.get('reputation', {}).get('spamListed')}")
    print(f"  parentCompany={raw.get('identity', {}).get('parentCompany')}")
    print(f"  signals scores: rep={sigs.get('reputation', {}).get('score')}"
          f" id={sigs.get('identity', {}).get('score')}"
          f" age={sigs.get('domainAge', {}).get('score')}"
          f" ssl={sigs.get('ssl', {}).get('score')}"
          f" content={sigs.get('content', {}).get('score')}"
          f" dns={sigs.get('dns', {}).get('score')}")
