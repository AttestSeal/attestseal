#!/usr/bin/env python3
"""Render docs/blog/*.md into public/blog/<slug>/index.html.

Idempotent: re-running overwrites the output. Run after editing any
article in docs/blog/.

Output structure:

  public/blog/index.html          -- hub page listing all articles
  public/blog/<slug>/index.html   -- one page per article

The layout matches public/index.html design tokens (--ink, --paper,
--text, Inter font) so the blog feels like part of the marketing site.
WCAG 2.2 AA: skip link, main landmark, h1->h2->h3 hierarchy, focus
indicators, prefers-reduced-motion, prefers-contrast support.
"""
from __future__ import annotations

import html
import re
from pathlib import Path
from typing import Any

import markdown


REPO = Path(__file__).resolve().parent.parent
SRC_DIR = REPO / "docs" / "blog"
OUT_DIR = REPO / "public" / "blog"


def parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    """Parse the YAML-ish frontmatter at the top of a markdown file.

    We don't use PyYAML because the frontmatter shape is simple
    (key: value, lists with [a, b], no nesting) and we want zero new
    dependencies for the build step.
    """
    if not text.startswith("---\n"):
        return {}, text
    end = text.find("\n---\n", 4)
    if end == -1:
        return {}, text

    front_text = text[4:end]
    body = text[end + 5:]

    meta: dict[str, Any] = {}
    for line in front_text.splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        value = value.strip()
        if value.startswith("[") and value.endswith("]"):
            inner = value[1:-1]
            meta[key.strip()] = [v.strip() for v in inner.split(",") if v.strip()]
        else:
            meta[key.strip()] = value
    return meta, body


CSS_BLOCK = """
:root{
  --ink:#07121f;
  --ink-2:#10243a;
  --ink-3:#193957;
  --ink-4:#2a4768;
  --paper:#ffffff;
  --paper-2:#f6f9fc;
  --paper-3:#eef5fb;
  --text:#142033;
  --text-soft:#3a4a63;
  --line:#d8e1ec;
  --line-2:#c0cfdf;
  --accent:#2563eb;
  --accent-soft:#dbeafe;
  --code-bg:#f4f7fb;
  --font:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  --mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth;background:var(--paper);font-size:18px;line-height:1.65}
body{margin:0;font-family:var(--font);color:var(--text);background:var(--paper);-webkit-font-smoothing:antialiased}
a{color:var(--accent);text-decoration:none;border-bottom:1px solid transparent;transition:border-color 144ms ease}
a:hover,a:focus{border-bottom-color:var(--accent)}
a:focus-visible{outline:3px solid var(--accent);outline-offset:3px;border-radius:2px}
.skip-link{position:absolute;top:-120px;left:20px;z-index:2000;background:var(--ink);color:#fff;padding:12px 16px;border-radius:0 0 8px 8px;font-weight:700;text-decoration:none}
.skip-link:focus{top:0}
.nav{position:sticky;top:0;z-index:100;background:rgba(255,255,255,0.92);backdrop-filter:saturate(180%) blur(12px);border-bottom:1px solid var(--line);padding:14px 24px}
.nav-inner{max-width:1080px;margin:0 auto;display:flex;align-items:center;justify-content:space-between;gap:24px}
.nav a{color:var(--ink);font-weight:600;border:0}
.nav a:hover{color:var(--accent)}
.brand{display:flex;align-items:center;gap:10px;font-size:1.05rem;font-weight:720}
.brand img{width:28px;height:28px}
.nav ul{display:flex;list-style:none;margin:0;padding:0;gap:24px;font-size:.95rem}
main{max-width:760px;margin:0 auto;padding:64px 24px 96px}
.article-header{margin-bottom:48px;padding-bottom:32px;border-bottom:1px solid var(--line)}
.eyebrow{font-size:.85rem;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:var(--ink-3);margin-bottom:14px}
h1{font-size:2.6rem;font-weight:760;color:var(--ink);line-height:1.15;margin:0 0 18px}
h2{font-size:1.65rem;font-weight:720;color:var(--ink);line-height:1.25;margin:48px 0 18px}
h3{font-size:1.2rem;font-weight:680;color:var(--ink);line-height:1.3;margin:36px 0 14px}
h4{font-size:1.05rem;font-weight:680;color:var(--ink);margin:28px 0 12px}
p{margin:0 0 1.1em;color:var(--text)}
.summary{font-size:1.18rem;color:var(--text-soft);line-height:1.55;margin:0 0 16px}
.byline{font-size:.95rem;color:var(--text-soft);display:flex;flex-wrap:wrap;gap:18px;align-items:center}
.byline .tag{display:inline-block;background:var(--paper-3);color:var(--ink-3);padding:3px 10px;border-radius:99px;font-size:.78rem;font-weight:600}
.article p,.article ul,.article ol{font-size:1.05rem}
.article ul,.article ol{margin:0 0 1.2em;padding-left:1.4em}
.article li{margin-bottom:.4em}
.article strong{color:var(--ink)}
.article em{color:var(--ink-3)}
.article hr{border:0;border-top:1px solid var(--line);margin:48px 0}
.article blockquote{border-left:3px solid var(--accent);padding:8px 18px;margin:24px 0;color:var(--text-soft);background:var(--paper-2);border-radius:0 6px 6px 0}
.article code{font-family:var(--mono);font-size:.92em;background:var(--code-bg);padding:2px 6px;border-radius:4px;color:var(--ink-2)}
.article pre{font-family:var(--mono);background:var(--code-bg);border:1px solid var(--line);border-radius:8px;padding:18px 20px;overflow-x:auto;font-size:.92rem;line-height:1.55;margin:24px 0}
.article pre code{background:transparent;padding:0;border-radius:0;color:var(--text)}
.article table{border-collapse:collapse;width:100%;margin:24px 0;font-size:.95rem}
.article th,.article td{border:1px solid var(--line);padding:10px 14px;text-align:left;vertical-align:top}
.article th{background:var(--paper-2);font-weight:680;color:var(--ink)}
.article tr:nth-child(even) td{background:var(--paper-2)}
footer{max-width:1080px;margin:0 auto;padding:48px 24px;border-top:1px solid var(--line);font-size:.92rem;color:var(--text-soft);display:flex;justify-content:space-between;flex-wrap:wrap;gap:18px}
footer a{color:var(--text-soft)}
.hub-list{list-style:none;padding:0;margin:0;display:grid;gap:20px}
.hub-card{display:block;padding:24px;border:1px solid var(--line);border-radius:12px;background:var(--paper);transition:border-color 144ms ease,transform 144ms ease,box-shadow 144ms ease;color:inherit;border-bottom:1px solid var(--line)}
.hub-card:hover{border-color:var(--ink-3);transform:translateY(-2px);box-shadow:0 12px 32px rgba(7,18,31,.08)}
.hub-card .num{font-size:.85rem;font-weight:600;color:var(--ink-3);letter-spacing:.05em}
.hub-card h3{margin:6px 0 10px;font-size:1.25rem}
.hub-card .summary{font-size:1rem;color:var(--text-soft);margin:0}
@media (max-width:680px){
  html{font-size:17px}
  h1{font-size:2.05rem}
  h2{font-size:1.4rem}
  main{padding:40px 18px 64px}
}
@media (prefers-reduced-motion:reduce){
  *{animation:none!important;transition:none!important;scroll-behavior:auto!important}
}
@media (prefers-contrast:high){
  body{background:#fff;color:#000}
  .article code{background:#fff;border:1px solid #000}
}
"""


NAV = '''
<nav class="nav" aria-label="Main navigation">
  <div class="nav-inner">
    <a href="/" class="brand"><img src="/assets/brand/ats-logo-icon.png" alt="" aria-hidden="true">AttestSeal</a>
    <ul>
      <li><a href="/blog/">Blog</a></li>
      <li><a href="/#how-it-works">How it works</a></li>
      <li><a href="https://github.com/AttestSeal/attestseal">GitHub</a></li>
    </ul>
  </div>
</nav>
'''.strip()


FOOTER = '''
<footer>
  <div>&copy; 2026 AttestSeal, Inc. &middot; Independent trust attestation for AI agent commerce.</div>
  <div>
    <a href="https://github.com/AttestSeal/attestseal">GitHub</a> &middot;
    <a href="https://status.attestseal.com">Status</a> &middot;
    <a href="mailto:alu@attestseal.com">Contact</a>
  </div>
</footer>
'''.strip()


def render_article_page(meta: dict, body_html: str) -> str:
    title = meta.get("title", "Untitled")
    date = meta.get("date", "")
    author = meta.get("author", "")
    summary = meta.get("summary", "")
    tags = meta.get("tags", []) or []

    tag_html = " ".join(f'<span class="tag">{html.escape(t)}</span>' for t in tags)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{html.escape(title)} -- AttestSeal</title>
<meta name="description" content="{html.escape(summary)}">
<meta property="og:title" content="{html.escape(title)}">
<meta property="og:description" content="{html.escape(summary)}">
<meta property="og:type" content="article">
<meta property="og:image" content="/assets/brand/ats-logo-full.png">
<link rel="icon" type="image/png" href="/assets/brand/ats-logo-icon.png">
<link rel="preconnect" href="https://rsms.me/">
<link rel="stylesheet" href="https://rsms.me/inter/inter.css">
<style>{CSS_BLOCK}</style>
</head>
<body>
<a class="skip-link" href="#main">Skip to content</a>
{NAV}
<main id="main">
  <article class="article">
    <header class="article-header">
      <div class="eyebrow">AttestSeal Blog</div>
      <h1>{html.escape(title)}</h1>
      <p class="summary">{html.escape(summary)}</p>
      <div class="byline">
        <span>{html.escape(author)}</span>
        <span>&middot;</span>
        <time datetime="{html.escape(date)}">{html.escape(date)}</time>
        {tag_html}
      </div>
    </header>
    {body_html}
  </article>
</main>
{FOOTER}
</body>
</html>
"""


def render_hub_page(articles: list[dict]) -> str:
    items_html = []
    for n, a in enumerate(articles, start=1):
        slug = a["slug"]
        title = a["meta"].get("title", "Untitled")
        summary = a["meta"].get("summary", "")
        # The hub itself (slug=launch-index) is rendered as the page itself,
        # not as a list item.
        if slug == "launch-index":
            continue
        items_html.append(f'''
        <li>
          <a class="hub-card" href="/blog/{html.escape(slug)}/">
            <div class="num">Article {n - 1}</div>
            <h3>{html.escape(title)}</h3>
            <p class="summary">{html.escape(summary)}</p>
          </a>
        </li>''')

    title = "AttestSeal Blog"
    summary = "A six-part series introducing AttestSeal, the trust gap in agent commerce, the x402 integration, and the policy taxonomy agents need to apply."
    items = "".join(items_html)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{html.escape(title)}</title>
<meta name="description" content="{html.escape(summary)}">
<meta property="og:title" content="{html.escape(title)}">
<meta property="og:description" content="{html.escape(summary)}">
<meta property="og:type" content="website">
<meta property="og:image" content="/assets/brand/ats-logo-full.png">
<link rel="icon" type="image/png" href="/assets/brand/ats-logo-icon.png">
<link rel="preconnect" href="https://rsms.me/">
<link rel="stylesheet" href="https://rsms.me/inter/inter.css">
<style>{CSS_BLOCK}</style>
</head>
<body>
<a class="skip-link" href="#main">Skip to content</a>
{NAV}
<main id="main">
  <header class="article-header">
    <div class="eyebrow">Editorial Series</div>
    <h1>{html.escape(title)}</h1>
    <p class="summary">{html.escape(summary)}</p>
  </header>
  <ul class="hub-list">{items}
  </ul>
</main>
{FOOTER}
</body>
</html>
"""


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    md = markdown.Markdown(extensions=["fenced_code", "tables", "smarty", "sane_lists", "toc"])

    files = sorted(SRC_DIR.glob("*.md"))
    articles: list[dict] = []
    for path in files:
        text = path.read_text(encoding="utf-8")
        meta, body = parse_frontmatter(text)
        md.reset()
        body_html = md.convert(body)
        slug = meta.get("slug") or path.stem
        articles.append({"slug": slug, "meta": meta, "body_html": body_html, "path": path})

    # Per-article pages
    for a in articles:
        slug = a["slug"]
        if slug == "launch-index":
            continue  # rendered as hub
        article_dir = OUT_DIR / slug
        article_dir.mkdir(parents=True, exist_ok=True)
        page = render_article_page(a["meta"], a["body_html"])
        (article_dir / "index.html").write_text(page, encoding="utf-8")

    # Hub page
    hub = render_hub_page(articles)
    (OUT_DIR / "index.html").write_text(hub, encoding="utf-8")

    print(f"Rendered {len(articles)} articles into {OUT_DIR.relative_to(REPO)}/")
    for a in articles:
        slug = a["slug"]
        if slug == "launch-index":
            print(f"  - /blog/                       (hub)")
        else:
            print(f"  - /blog/{slug}/")


if __name__ == "__main__":
    main()
