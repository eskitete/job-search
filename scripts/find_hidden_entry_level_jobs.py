#!/usr/bin/env python3
# scripts/find_hidden_entry_level_jobs.py

import asyncio
import argparse
import os
import pathlib
import re
import csv
import time
from urllib.parse import urljoin, urlparse
from datetime import datetime

import aiohttp
from bs4 import BeautifulSoup
import feedparser
import urllib.robotparser as robotparser


DEFAULT_ENTRY_PATTERNS = r'\b(intern(ship)?|new\s*grad|junior|apprentice|fellow(ship)?|rotation)\b'
DEFAULT_EXCLUDE_PATTERNS = r'\b(senior|staff|principal|lead|manager|sr\.?)\b'
DEFAULT_LIKELY_PATHS = ["careers", "jobs", "join-us", "join", "work-with-us", "opportunities"]

# ---------- Utilities ----------

def compile_regex(pattern: str):
    return re.compile(pattern, re.I)

def safe_company_from_domain(domain_or_url: str) -> str:
    host = urlparse(domain_or_url).netloc or urlparse("https://" + domain_or_url).netloc or domain_or_url
    parts = [p for p in host.split(".") if p and p not in ("www",)]
    if len(parts) >= 2:
        return parts[-2].capitalize()
    return host

def is_same_host(url: str, base: str) -> bool:
    return urlparse(url).netloc == urlparse(base).netloc

def now_iso() -> str:
    return datetime.utcnow().isoformat()

def normalize_roots(domains):
    roots = []
    for d in domains:
        d = d.strip()
        if not d:
            continue
        if not d.startswith("http://") and not d.startswith("https://"):
            d = "https://" + d
        # strip trailing slash for consistency
        d = d.rstrip("/")
        roots.append(d)
    return roots

# ---------- Robots ----------

def robots_allows(user_agent: str, base: str, path: str = "/") -> bool:
    try:
        rp = robotparser.RobotFileParser()
        rp.set_url(urljoin(base, "/robots.txt"))
        rp.read()
        return rp.can_fetch(user_agent, urljoin(base, path))
    except Exception:
        # if robots can't be read, stay conservative but allow
        return True

# ---------- HTTP ----------

async def fetch_text(session: aiohttp.ClientSession, url: str, timeout: int) -> str | None:
    try:
        async with session.get(url, timeout=timeout, allow_redirects=True) as r:
            ct = (r.headers.get("content-type") or "").lower()
            if r.status == 200 and ("text/html" in ct or "application/xhtml+xml" in ct or "text/plain" in ct):
                return await r.text()
    except Exception:
        return None
    return None

def extract_in_domain_links(base_url: str, html: str):
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith("#") or href.startswith("mailto:") or href.startswith("tel:"):
            continue
        full = urljoin(base_url, href)
        if is_same_host(full, base_url):
            links.add(full)
    return links

# ---------- Heuristics ----------

def looks_like_entry_title(text: str, include_re: re.Pattern, exclude_re: re.Pattern) -> bool:
    t = (text or "").strip()
    if not t:
        return False
    if not include_re.search(t):
        return False
    if exclude_re.search(t):
        return False
    # Avoid very long strings (whole paragraphs)
    words = t.split()
    return 2 <= len(words) <= 16

def jobish_link(link: str) -> bool:
    L = link.lower()
    return any(s in L for s in ("job", "career", "opening", "position", "opportunit", "intern"))

# ---------- RSS ----------

async def scan_rss(domain_root: str, session: aiohttp.ClientSession, include_re, exclude_re) -> list[dict]:
    results = []
    candidates = [
        "feed", "rss", "atom.xml", "blog/feed", "careers/feed", "jobs/feed",
        "feeds", "index.xml"
    ]
    for path in candidates:
        feed_url = urljoin(domain_root + "/", path)
        try:
            f = feedparser.parse(feed_url)
            if not getattr(f, "entries", None):
                continue
            for e in f.entries[:80]:
                title = getattr(e, "title", "") or ""
                link = getattr(e, "link", "") or feed_url
                if looks_like_entry_title(title, include_re, exclude_re):
                    results.append({
                        "company": safe_company_from_domain(domain_root),
                        "title": title.strip(),
                        "url": link,
                        "source": "rss",
                        "discovered_at": now_iso(),
                    })
        except Exception:
            continue
    return results

# ---------- HTML Crawl ----------

async def scan_domain(domain_root: str,
                      session: aiohttp.ClientSession,
                      include_re, exclude_re,
                      likely_paths: list[str],
                      max_pages: int,
                      timeout: int,
                      user_agent: str) -> list[dict]:
    seen = set()
    found = []

    seeds = {domain_root}
    for p in likely_paths:
        seeds.add(urljoin(domain_root + "/", p))
        seeds.add(urljoin(domain_root + "/", p + "/"))

    queue = list(seeds)

    while queue and len(seen) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)

        # Robots
        try:
            path = url.replace(domain_root, "") or "/"
            if not robots_allows(user_agent, domain_root, path):
                continue
        except Exception:
            pass

        html = await fetch_text(session, url, timeout)
        if not html:
            continue

        soup = BeautifulSoup(html, "html.parser")

        # Find text-y elements that often hold titles
        for tag in soup.find_all(["h1", "h2", "h3", "a", "li", "span", "div"], string=True):
            text = tag.get_text(separator=" ", strip=True)
            if looks_like_entry_title(text, include_re, exclude_re):
                link = tag.get("href")
                full = urljoin(url, link) if link else url
                found.append({
                    "company": safe_company_from_domain(domain_root),
                    "title": text,
                    "url": full,
                    "source": "html",
                    "discovered_at": now_iso(),
                })

        # Enqueue additional likely job pages
        for link in extract_in_domain_links(url, html):
            if jobish_link(link) and link not in seen and (len(seen) + len(queue) < max_pages):
                queue.append(link)

    # De-dup by (lower(title), url)
    dedup = {}
    for r in found:
        key = (r["title"].lower(), r["url"])
        dedup[key] = r
    return list(dedup.values())

# ---------- Runner ----------

async def run(domains: list[str],
              out_dir: str,
              include_keywords: str,
              exclude_keywords: str,
              likely_paths: list[str],
              max_pages: int,
              timeout: int,
              user_agent: str,
              force_empty_csv: bool) -> int:
    include_re = compile_regex(include_keywords)
    exclude_re = compile_regex(exclude_keywords)

    domains = normalize_roots(domains)
    if not domains:
        print("No domains provided. Exiting without results.")
        if force_empty_csv:
            ensure_dir(out_dir)
            out = os.path.join(out_dir, f"empty_run_{int(time.time())}.csv")
            with open(out, "w", newline="", encoding="utf-8") as f:
                f.write("no_results\n")
            print(f"Created placeholder CSV: {out}")
        return 0

    print(f"Running job scout on {len(domains)} domains -> output dir: {out_dir}")
    print(f"Include keywords: {include_keywords}")
    print(f"Exclude keywords: {exclude_keywords}")
    print(f"Max pages per domain: {max_pages}, HTTP timeout: {timeout}s")
    ensure_dir(out_dir)

    all_rows: list[dict] = []
    conn = aiohttp.TCPConnector(limit=20)
    headers = {"User-Agent": user_agent}
    async with aiohttp.ClientSession(connector=conn, headers=headers) as session:
        for d in domains:
            try:
                rss_hits = await scan_rss(d, session, include_re, exclude_re)
                html_hits = await scan_domain(
                    d, session, include_re, exclude_re,
                    likely_paths, max_pages, timeout, user_agent
                )
                print(f"[{safe_company_from_domain(d)}] rss: {len(rss_hits)} | html: {len(html_hits)}")
                all_rows.extend(rss_hits + html_hits)
            except Exception as e:
                print(f"[WARN] Failed {d}: {e}")

    # Final de-dup (across domains)
    final = {}
    for r in all_rows:
        key = (r["company"].lower(), r["title"].lower(), r["url"])
        final[key] = r
    rows = list(final.values())

    if not rows and force_empty_csv:
        out = os.path.join(out_dir, f"empty_run_{int(time.time())}.csv")
        with open(out, "w", newline="", encoding="utf-8") as f:
            f.write("no_results\n")
        print(f"No results found — created placeholder CSV: {out}")
        return 0

    if rows:
        out = os.path.join(out_dir, f"entry_level_roles_{int(time.time())}.csv")
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["company", "title", "url", "source", "discovered_at"])
            w.writeheader()
            for r in rows:
                w.writerow(r)
        print(f"Wrote {len(rows)} results to {out}")
    else:
        print("No results found and no placeholder requested.")

    return len(rows)

def ensure_dir(d: str):
    pathlib.Path(d).mkdir(parents=True, exist_ok=True)

# ---------- CLI ----------

def read_domains_file(path: str) -> list[str]:
    p = pathlib.Path(path)
    if not p.exists():
        print(f"[WARN] Domains file not found: {path}")
        return []
    lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]

def main():
    ap = argparse.ArgumentParser(description="Scan domains for entry-level or internship postings outside major job boards.")
    ap.add_argument("--domains-file", default=os.getenv("DOMAINS_FILE", "config/domains.txt"),
                    help="Path to a file with one root URL per line.")
    ap.add_argument("--out-dir", default=os.getenv("OUTPUT_DIR", "data"),
                    help="Directory to write CSV results into.")
    ap.add_argument("--include", default=os.getenv("ENTRY_KEYWORDS", DEFAULT_ENTRY_PATTERNS),
                    help="Regex for entry-level keywords to include (case-insensitive).")
    ap.add_argument("--exclude", default=os.getenv("EXCLUDE_KEYWORDS", DEFAULT_EXCLUDE_PATTERNS),
                    help="Regex for keywords to exclude (case-insensitive).")
    ap.add_argument("--likely-path", action="append", default=None,
                    help="Add a likely careers path (can be repeated). Defaults are typical careers paths.")
    ap.add_argument("--max-pages", type=int, default=int(os.getenv("MAX_PAGES", "25")),
                    help="Max in-domain pages to scan per domain.")
    ap.add_argument("--timeout", type=int, default=int(os.getenv("HTTP_TIMEOUT", "20")),
                    help="HTTP timeout (seconds).")
    ap.add_argument("--user-agent", default=os.getenv("USER_AGENT", "JobScout/1.0 (research; contact: you@example.com)"),
                    help="HTTP User-Agent string.")
    ap.add_argument("--force-empty-csv", action="store_true",
                    help="Write a tiny placeholder CSV if no results are found (useful so Actions always uploads an artifact).")

    args = ap.parse_args()

    domains = read_domains_file(args.domains_file)
    likely_paths = args.likely_path if args.likely_path else DEFAULT_LIKELY_PATHS

    exit_count = asyncio.run(
        run(domains=domains,
            out_dir=args.out_dir,
            include_keywords=args.include,
            exclude_keywords=args.exclude,
            likely_paths=likely_paths,
            max_pages=args.max_pages,
            timeout=args.timeout,
            user_agent=args.user_agent,
            force_empty_csv=args.force_empty_csv)
    )
    # Exit code 0 even with zero results; CI shouldn't fail a successful crawl.
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
