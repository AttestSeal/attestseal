# Next Session Bootstrap

Saved 2026-05-01 evening at end of long working session that hit context limit.

## Where the project is

**Cutover complete.** AttestSeal is live in production:
- API at https://api.attestseal.com (and apex)
- ats-api-1 droplet: 146.190.141.49 (DigitalOcean SFO3, Premium Intel)
- 1,003,196 domains in attestseal.db, 1,001,057 signed under did:web:attestseal.com
- 94.41% Tranco top-1M coverage
- New marketing site live, real ATSLogo assets
- opentrustseal.com cleanly redirects to attestseal.com
- Mac Air + gaming PC serving tier-4 routing

**This local folder is the new home.** `robots/opentrusttoken/` was renamed to `robots/attestseal/` at end of session. Git history intact, branch `rebrand-attestseal` checked out with the full content rename committed.

## What's NOT yet done -- read these memory files in order

1. `~/.claude/projects/.../memory/project_post_launch_roadmap.md` -- master sequenced todo
2. `~/.claude/projects/.../memory/project_attestseal_rebrand.md` -- cutover state, what's where
3. `~/.claude/projects/.../memory/project_attestseal_data_analysis.md` -- bug fixes + v1.5 scoring decision
4. `~/.claude/projects/.../memory/project_attestseal_x402_integration.md` -- the killer-feature x402 launch artifact plan
5. `~/.claude/projects/.../memory/project_attestseal_partnerships.md` -- Mercury/Brex/Stripe outreach

## First action in the next session

Apply v1.5 scoring tweaks to `server/app/scoring.py`:

1. Lower PROCEED threshold from 75 to 70 (with valid SSL + clean reputation gate)
2. Brand anchor floors by Tranco bucket: top-100→90, top-1K→85, top-10K→80, top-50K→75
3. Infrastructure inheritance via parent_companies registry
4. DENY definition unchanged (parked/dead/no-SSL stays DENY -- user explicit decision)

Then push to ats-api-1, run `server/rescore_streaming.py`, re-audit with `scripts/analysis/distribution_chart.py`.

Expected new distribution:
- PROCEED: ~48-50K (~5%)
- CAUTION: ~795K (~80%)
- DENY: ~155K (~15%)
- Top-100 PROCEED: 95+ of 100
- Top-10K PROCEED: ~81%

## Then the launch artifacts (in this order)

Per `project_attestseal_x402_integration.md`:

1. Write the X-AttestSeal-* HTTP header spec (markdown doc)
2. Build `attestseal-x402` Python package (server middleware + client verifier)
3. Build Cloudflare Worker template
4. Build x402 reference demo at demo.attestseal.com
5. Write launch blog post + Coinbase x402 GitHub Discussion content

## Then the publish

Per `project_post_launch_roadmap.md` Tier 2:

1. Push rebrand-attestseal branch to GitHub
2. GitHub org + repo rename
3. export_dataset.py against attestseal.db
4. Publish to HuggingFace
5. GitHub release v1.0
6. Publish attestseal-x402 to PyPI
7. Submit Coinbase x402 GitHub Discussion
8. Submit CrewAI PR (already staged at sdk/crewai-pr/)

## Critical fixes that landed in this session

Three bugs found and fixed during pre-publish analysis:
1. **Confidence missing on 99.33% of records** -- fixed via streaming rescore (`server/rescore_streaming.py`)
2. **signing.key was the wrong key** -- API was signing with auto-generated key not matching DID. Fixed by replacing signing.key with signing_ed25519.priv contents on ats-api-1.
3. **parent_companies.json missing on ats-api-1** -- pushed back to `/opt/attestseal/server/app/data/`

## Decisions locked in (don't relitigate)

- Brand: AttestSeal (USPTO clean), incorporated as AttestSeal, Inc.
- Naming: `ATS` (not `AS`) for env vars/abbrevs
- DENY stays inclusive of parked/dead/no-SSL -- "no one should pay a parked site"
- PROCEED threshold lowered to 70 (single rule, NOT rank-conditional)
- x402 hardcoded HTML headers as the killer launch feature
- Stripe CFO favor saved until 4-8 weeks post-launch with named integration in hand
- Pre-publish analysis is a real gate, not a checkbox

## Working tree status at handoff

- Branch: `rebrand-attestseal` (committed, NOT pushed to remote)
- 3 commits in branch: full content rename, Codex bug fixes, prior CLAUDE.md updates
- Modified (uncommitted): `docs/REBRAND-SPEC-ATTESTSEAL.md`, `public/index.html`
- Untracked: `ATSLogoFull.ai`, `ATSLogoFull.png`, `ATSLogoIcon.ai`, `ATSLogoIcon.png`, `public/assets/brand/ats-logo-*.png`, `NEXT-SESSION-START-HERE.md`, `server/rescore_streaming.py`, `scripts/analysis/*.py`

Suggested first commit in next session: `git add -A && git commit -m "post-cutover: add real ATSLogo assets, rescore_streaming, analysis scripts, session handoff doc"`

## Files that live ONLY on ats-api-1 (not in repo)

- `/opt/attestseal/data/attestseal.db` (11.6 GB) -- the production DB
- `/opt/attestseal/keys/signing.key` and `signing.pub` -- the canonical signing keypair
- `/opt/attestseal/keys/signing_ed25519.priv/.pub` -- redundant copy of same keypair
- `/opt/attestseal/data/.well-known/did.json` -- the published DID document

These are runtime data, not source. Don't try to commit them.
