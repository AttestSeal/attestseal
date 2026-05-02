# Rebrand spec: OpenTrustSeal -> AttestSeal

Locked-in spec for the merge-time cutover. Designed so the code rename pass
is mechanical -- no judgment calls during execution.

**Trigger**: California SOS rejected "OpenTrustSeal Inc" (the word "Trust"
requires Department of Financial Protection and Innovation consent for
non-financial entities, ~60-90 days, denial likely). USPTO clearance found
"AttestSeal" clean: no Verisk-tier conflict in classes 9 / 42 / 45.

## Naming convention

Single source of truth for every form:

| Form | Use |
|---|---|
| **AttestSeal** | Prose, package descriptions, brand-facing copy, methodology doc titles |
| **attestseal** | Domain (`attestseal.com`), repo paths, package directory names, lowercase identifiers |
| **ATS** | Env var prefixes, log file prefixes, B2 bucket prefix, abbreviations in code comments |
| **ats** | User/group names (`ats:ats`), short prefixes for file paths and unit names |

The "OTS" -> "ATS" mapping is exact 3-letter substitution so the migration
is a single global find-and-replace per surface.

## Mechanical replacement table

Run these in order, top to bottom. Earlier rules win when they overlap.

| Find | Replace | Scope |
|---|---|---|
| `opentrustseal.com` | `attestseal.com` | All files |
| `api.opentrustseal.com` | `api.attestseal.com` | All files |
| `did:web:opentrustseal.com` | `did:web:attestseal.com` | All files |
| `OpenTrustSeal, Inc` | `AttestSeal, Inc` | All files |
| `OpenTrustSeal` | `AttestSeal` | All files (case-sensitive) |
| `opentrustseal/` | `attestseal/` | Path-suffix matches only |
| `opentrustseal` | `attestseal` | All remaining occurrences |
| `opentrusttoken/` | `attestseal/` | Path-suffix matches only (legacy alias path) |
| `opentrusttoken.com` | (unchanged, keep redirect target) | DNS-only references; do not rewrite |
| `OpenTrustToken` | `AttestSeal` | Legacy mentions |
| `opentrusttoken` | `attestseal` | All remaining occurrences |
| `OTS_` | `ATS_` | Env var names, identifier prefixes |
| `OTT_` | `ATS_` | Legacy env vars |
| `ots-v1.` | `attestseal-v1.` | Scoring model version strings |
| `ots-` | `ats-` | Service names, file prefixes (NOT raw 3-letter "ots" inside other words) |
| `ott-` | `ats-` | Legacy service prefixes |
| `OTS` (standalone, word boundary) | `ATS` | Comments, docstrings |
| `OTT` (standalone, word boundary) | `ATS` | Legacy mentions |
| `ots:ots` | `ats:ats` | User:group references in code |
| `ott:ott` | `ats:ats` | Legacy user:group references |

**Use `\b` word-boundary anchors** when running sed/regex on three-letter
matches so you don't catch substrings like "knots", "robots", "dots", etc.

## Files / paths to SKIP

The find-and-replace must NOT touch:

- `data/domains.txt` and `data/tranco.csv` -- real Tranco domains may contain "ots" / "trust" substrings
- `data/.seed-checkpoint*.json` -- contain crawled domains
- `data/ots-*.db` and `data/ott.db` -- SQLite per-process DBs (rename files separately, but don't rewrite content)
- `*.bak.*` and `.prev*.json` -- preserved historical snapshots, leave for rollback
- `venv/`, `node_modules/`, `.git/`
- Test fixtures referencing OTHER companies (e.g., domains being tested -- "amazon.com", "petco.com", etc)
- `docs/REBRAND-SPEC-ATTESTSEAL.md` (this file) -- documents the migration, references both names intentionally
- `docs/MIGRATION-OTT-OTS.md` (if exists) -- historical record

## VPS infrastructure plan

Build fresh, do not in-place rename:

```
ats-api-1   (DigitalOcean, 2 vCPU / 2 GB / 60 GB)
  /opt/attestseal/         service code
  /opt/attestseal/data/    attestseal.db (Litestream-restored from B2)
  /opt/attestseal/keys/    new Ed25519 keypair (registration_kek.bin reused if same KEK desired, or rotated)
  /opt/attestseal/logs/
  /etc/attestseal/         env files
  ats:ats                  service user/group
  attestseal.service       systemd unit (was opentrustseal.service)
  ats-crawler.service      systemd unit (was ots-crawler.service)
```

DB filename: `ots.db` -> `attestseal.db`. Move during Litestream restore.

## DID + signature migration

1. Generate fresh Ed25519 keypair on `ats-api-1`. Store at
   `/opt/attestseal/keys/signing_ed25519.{priv,pub}`.
2. Publish DID document at `https://attestseal.com/.well-known/did.json`
   AND `https://api.attestseal.com/.well-known/did.json` with the new
   public key, issuer `did:web:attestseal.com`.
3. Re-sign every row in `scored_results` under the new DID. One-shot
   script: iterate, recompute signable bytes, sign with new key, update
   `signature` column. Verify count matches.
4. Re-sign the seed dataset rows (~100K) post-merge under the new DID.
5. Old DID at `opentrustseal.com/.well-known/did.json` keeps resolving for
   180 days (legacy verification grace period). After 180 days, the old
   nginx vhost can drop the .well-known location block.

## Domain + DNS

| Domain | Action |
|---|---|
| `attestseal.com` | A record -> ats-api-1 IP, CF proxy ON |
| `www.attestseal.com` | same |
| `api.attestseal.com` | same |
| `mail.attestseal.com` | unchanged (existing CF Email Routing) |
| `opentrustseal.com` | reverse current redirect: 301 -> `attestseal.com` |
| `www.opentrustseal.com` | 301 -> `attestseal.com` |
| `api.opentrustseal.com` | 301 -> `api.attestseal.com` |
| `opentrusttoken.com` | already 301 -> `opentrustseal.com`. Cascades naturally. |
| `api.opentrusttoken.com` | same cascade |

SSL: certbot has already issued attestseal.com cert (Jul 25 expiry).
opentrustseal.com cert keeps renewing until we destroy the legacy box.

## Public surfaces checklist

- [ ] HuggingFace dataset: publish under `AttestSeal/dataset-v1` (drop the OpenTrustSeal account naming)
- [ ] CrewAI PR: tool class name `OpenTrustSealTool` -> `AttestSealTool`, retitle PR, update PR body
- [ ] GitHub org: rename `OpenTrustSeal` -> `AttestSeal` (auto-301 on old URLs)
- [ ] GitHub repo: rename to `attestseal/attestseal`
- [ ] Repo description, topics, social preview image
- [ ] README.md, SECURITY.md, CONTRIBUTING.md (if present)
- [ ] `docs/ARCHITECTURE.md`, `spec/PROTOCOL.md`, `spec/SCORING-V1.4.md`
- [ ] Landing page at attestseal.com (full copy rewrite)
- [ ] Marketing knowledge base at `attestseal.com/marketing/`
- [ ] Methodology page (the "Why independent" / "Confidence + cautionReason" / "Open methodology" sections)
- [ ] Dashboard UI (`/dashboard.html`)
- [ ] Registration page (`/register.html`)
- [ ] Email templates: `docs/MERCHANT-OUTREACH-EMAIL.md`
- [ ] Upptime status: rebuild as `AttestSeal/status` repo, CNAME `status.attestseal.com`
- [ ] Logos: replace placeholder `attestseal-logo.png` / `attestseal-seal.png` / `attestseal-logo-legacy.png` with real assets from `~/.../robots/attestseal/`:
  - `ATSLogoFull.png` (blue circle + green checkmark + ATTESTSEAL wordmark) -> use as primary logo, README header, social embed
  - `ATSLogoIcon.png` (mark only, no wordmark) -> use as favicon, app icon, dashboard nav
  - `ATSLogoFull.ai` and `ATSLogoIcon.ai` are Illustrator sources, kept in repo for future export size variants
- [ ] Python SDK: package name `opentrustseal` -> `attestseal` for PyPI
- [ ] TypeScript SDK: `@opentrustseal/sdk` -> `@attestseal/sdk` for npm

## Repo-level migration at cutover

Move `~/.../robots/opentrusttoken/` contents into `~/.../robots/attestseal/`
(the folder that already holds the new logo assets). At cutover:

```bash
cd ~/.../robots
# attestseal/ already exists with the logo assets; merge opentrusttoken/ into it
mv opentrusttoken/* attestseal/
mv opentrusttoken/.git attestseal/.git
rmdir opentrusttoken
# verify everything moved cleanly, then commit on rebrand-attestseal branch
```

After this, the local working dir is `~/.../robots/attestseal/` and the repo
remote can be renamed on GitHub (`OpenTrustSeal/opentrustseal` ->
`AttestSeal/attestseal`) -- automatic 301 redirects handle old clones.

## Cutover sequence

1. **Pre-merge (now)**: code rename pass on a `rebrand-attestseal` branch in the local repo. Run all tests. Don't merge to main yet.
2. **Merge**: pull all 23 seed DBs, run `merge_db.py --dry-run` then apply. Verify row count.
3. **Rescore**: `rescore.py` against merged DB to apply ATS-v1.4 scoring + sign with new DID.
4. **Cutover window (~2-3h scheduled maintenance)**:
   - Build `ats-api-1` droplet, bootstrap from rename branch
   - Litestream restore from B2 (new bucket `ats-db-backup`) into `attestseal.db`
   - Issue/copy SSL cert (already have attestseal.com)
   - Smoke-test: `/health`, `/stats`, `/v1/check/{domain}` for several known domains
   - DNS cutover: `attestseal.com` A records -> ats-api-1
   - Set up legacy redirects: `opentrustseal.com` 301 -> `attestseal.com` on the OLD `ots-ap-1` box (do NOT destroy yet)
5. **Re-sign records**: run signature migration script on `ats-api-1`. Verify all 1,232 + ~100K records have new issuer.
6. **Publish dataset**: HuggingFace, GitHub Release, with new brand. Update CrewAI PR draft.
7. **Submit CrewAI PR**.
8. **180 days later**: destroy `ots-ap-1`, drop `opentrustseal.com` domain renewal (or keep as defensive holding).

## Estimated effort

~1 working day of focused execution. The OTT->OTS migration laid the rails;
this is the same shape with a clearer target name.

## Origin

This spec replaces the earlier "Tier 2 item 0" pre-launch code review pass
in `project_post_launch_roadmap.md` -- that audit happens AGAINST this
rebrand-target codebase, not the OTS-named one.
