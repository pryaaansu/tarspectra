"""
crawler.py — High-precision, resilient web crawler for Tarspectra.

Features:
  - Fast connection-pooled HTTP session (keep-alive)
  - Automatic SSL resilience (works with self-signed / staging / testbed certs)
  - Content-Type verification (only crawls HTML/XHTML, skips binary assets)
  - Static asset exclusion (avoids wasting crawl budget on .png, .css, .woff, .ico)
  - Recursive path loop prevention (guards against infinite calendars/pagination)
  - Subdomain and endpoint discovery for hierarchical site mapping
"""

from __future__ import annotations

import re
import urllib3
from collections import deque
from urllib.parse import parse_qs, urlencode, urldefrag, urljoin, urlparse

import requests
from bs4 import BeautifulSoup
import tldextract

# Suppress InsecureRequestWarning when testing staging / self-signed servers
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Static asset extensions that should NOT be crawled as HTML pages
STATIC_EXTENSIONS = frozenset([
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp", ".tiff",
    ".css", ".scss", ".less",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".wav", ".avi", ".mov", ".webm",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
    ".exe", ".bin", ".iso", ".dmg",
    ".map",
])

# Marketing / tracking query parameters to strip for cleaner canonical URLs
TRACKING_PARAMS = frozenset([
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "_ga", "mc_cid", "mc_eid",
])


def _get_crawler_session() -> requests.Session:
    """Create a persistent requests session with connection pooling and sensible defaults."""
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=20,
        pool_maxsize=20,
        max_retries=1,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Tarspectra/2.5"
    })
    return session


def is_static_asset(url: str) -> bool:
    """Check if URL points to a static media, stylesheet, font, or binary asset."""
    path = urlparse(url).path.lower()
    for ext in STATIC_EXTENSIONS:
        if path.endswith(ext):
            return True
    return False


def is_recursive_path_loop(url: str) -> bool:
    """Detect repetitive directory loops (e.g. /dir/sub/dir/sub/dir/sub)."""
    parts = [p.lower() for p in urlparse(url).path.split("/") if p]
    if len(parts) >= 6:
        # Check if any segment appears 3 or more times
        counts = {}
        for p in parts:
            counts[p] = counts.get(p, 0) + 1
            if counts[p] >= 3:
                return True
    return False


def normalize_url(base: str, u: str) -> str:
    """
    Produce a canonical, clean absolute URL:
      - Strips fragment (#)
      - Lowercases scheme and netloc
      - Strips default ports (:80, :443)
      - Strips tracking query parameters
      - Preserves clean path
    """
    u = urljoin(base, u)
    u = urldefrag(u)[0]
    p = urlparse(u)

    scheme = (p.scheme or "http").lower()
    netloc = (p.netloc or "").lower()

    # Strip default ports
    if scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]

    path = p.path or "/"

    # Clean query parameters
    query_str = ""
    if p.query:
        parsed_q = parse_qs(p.query, keep_blank_values=True)
        cleaned_q = {k: v for k, v in parsed_q.items() if k.lower() not in TRACKING_PARAMS}
        if cleaned_q:
            query_str = "?" + urlencode(cleaned_q, doseq=True)

    return f"{scheme}://{netloc}{path}{query_str}"


def same_reg_domain(a: str, b: str) -> bool:
    """Check if URLs a and b belong to the same apex / registered domain."""
    ea = tldextract.extract(a)
    eb = tldextract.extract(b)
    if not ea.domain or not eb.domain:
        # Fallback for IP addresses or localhosts
        ha = urlparse(a).hostname or a
        hb = urlparse(b).hostname or b
        return ha.lower() == hb.lower()
    return (ea.domain.lower(), ea.suffix.lower()) == (eb.domain.lower(), eb.suffix.lower())


def is_http(u: str) -> bool:
    """Ensure URL is http or https."""
    p = urlparse(u)
    return p.scheme in ("http", "https")


def extract_links(base: str, html: str) -> set[str]:
    """Extract hyperlinks, forms, and endpoints from HTML content."""
    if not html or len(html) < 10:
        return set()

    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return set()

    raw_links = set()

    # <a> navigation links
    for a in soup.find_all("a", href=True):
        raw_links.add(a["href"])

    # <form> submission targets
    for form in soup.find_all("form", action=True):
        raw_links.add(form["action"])

    # <button> or <div> with formaction or data-href
    for btn in soup.find_all(["button", "input"], formaction=True):
        raw_links.add(btn["formaction"])

    # Scripts and frame sources
    for elem in soup.find_all(["iframe", "frame"], src=True):
        raw_links.add(elem["src"])

    urls = set()
    for h in raw_links:
        if not h:
            continue
        h_str = str(h).strip()
        if (
            h_str.startswith("#")
            or h_str.startswith("mailto:")
            or h_str.startswith("javascript:")
            or h_str.startswith("tel:")
            or h_str.startswith("data:")
        ):
            continue
        try:
            normalized = normalize_url(base, h_str)
            if is_http(normalized):
                urls.add(normalized)
        except Exception:
            continue

    return urls


def fetch_html(url: str, timeout: int = 10, headers: dict | None = None, session: requests.Session | None = None) -> tuple[str, str]:
    """
    Fetch URL content safely and return (html_text, content_type).
    Returns ("", "") if the resource is binary, timed out, or inaccessible.
    """
    sess = session or _get_crawler_session()
    h = headers or {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tarspectra/2.5"}

    try:
        r = sess.get(
            url,
            headers=h,
            timeout=timeout,
            allow_redirects=True,
            verify=False,
            stream=True,  # Stream first to check headers before downloading huge files
        )

        ctype = (r.headers.get("Content-Type") or "").lower()

        # Reject non-text / binary media immediately
        if (
            "text/html" not in ctype
            and "application/xhtml" not in ctype
            and "text/plain" not in ctype
            and "application/xml" not in ctype
            and "text/xml" not in ctype
        ):
            r.close()
            return "", ctype

        # Limit HTML reading to 2MB to avoid memory blowup on massive pages
        raw_bytes = r.raw.read(2_000_000, decode_content=True)
        encoding = r.encoding or "utf-8"
        try:
            text = raw_bytes.decode(encoding, errors="replace")
        except Exception:
            text = raw_bytes.decode("utf-8", errors="replace")

        return text, ctype
    except Exception:
        return "", ""


def _discover_robots_and_sitemap(start_url: str, session: requests.Session) -> set[str]:
    """Inspect robots.txt and sitemap.xml for declared paths and endpoints."""
    discovered = set()
    p = urlparse(start_url)
    origin = f"{p.scheme}://{p.netloc}"

    # 1. robots.txt
    try:
        r = session.get(f"{origin}/robots.txt", timeout=4, verify=False)
        if r.status_code == 200 and "text" in (r.headers.get("Content-Type") or ""):
            for line in r.text.splitlines():
                line = line.strip()
                if line.lower().startswith(("disallow:", "allow:")):
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        raw_path = parts[1].strip()
                        if raw_path and not any(ch in raw_path for ch in "*$"):
                            discovered.add(urljoin(origin, raw_path))
                elif line.lower().startswith("sitemap:"):
                    sm_url = line.split(":", 1)[1].strip()
                    if is_http(sm_url):
                        discovered.add(sm_url)
    except Exception:
        pass

    # 2. sitemap.xml
    try:
        r = session.get(f"{origin}/sitemap.xml", timeout=4, verify=False)
        if r.status_code == 200 and any(t in (r.headers.get("Content-Type") or "") for t in ("xml", "text")):
            locs = re.findall(r"<loc>(https?://[^<]+)</loc>", r.text, re.IGNORECASE)
            for loc in locs[:60]:
                discovered.add(loc.strip())
    except Exception:
        pass

    return discovered


def crawl_site_with_sitemap(start: str, max_pages: int = 40, max_depth: int = 2, respect_domain: bool = True) -> tuple[list[str], set[str], set[str]]:
    """
    Crawls site and collects:
      - found: list of HTML pages within page limit to inspect and audit
      - all_discovered: set of all URLs and endpoints discovered on the target registered domain
      - subdomains: set of all subdomains belonging to the registered domain
    """
    start = normalize_url(start, start)
    visited = set([start])
    q = deque([(start, 0)])
    found = [start]
    all_discovered = set([start])
    discovered_subdomains = set()

    start_host = urlparse(start).hostname or ""
    if start_host:
        discovered_subdomains.add(start_host.lower())

    session = _get_crawler_session()

    # Discover declared routes from robots.txt & sitemap.xml
    declared_routes = _discover_robots_and_sitemap(start, session)
    for r_url in declared_routes:
        r_norm = normalize_url(start, r_url)
        if same_reg_domain(start, r_norm):
            all_discovered.add(r_norm)
            r_host = urlparse(r_norm).hostname
            if r_host:
                discovered_subdomains.add(r_host.lower())
            if (
                not is_static_asset(r_norm)
                and not is_recursive_path_loop(r_norm)
                and r_norm not in visited
            ):
                visited.add(r_norm)
                if len(found) < max_pages:
                    found.append(r_norm)
                q.append((r_norm, 1))

    while q and len(found) < max_pages:
        url, depth = q.popleft()

        # Fetch page with connection pooling and SSL safety
        html, ctype = fetch_html(url, timeout=10, session=session)
        if not html:
            continue

        links = extract_links(url, html)

        for u in links:
            if not is_http(u):
                continue

            host = urlparse(u).hostname or ""
            if not host:
                continue

            is_target_domain = same_reg_domain(start, u)

            # Record subdomain & endpoint in overall sitemap inventory
            if is_target_domain:
                discovered_subdomains.add(host.lower())
                all_discovered.add(u)

            # Scope checks for active crawling
            if respect_domain and not is_target_domain:
                continue

            # Don't queue recursive directory loops
            if is_recursive_path_loop(u):
                continue

            # Don't queue static media, images, or stylesheets into HTML crawl queue
            if is_static_asset(u):
                continue

            if u in visited:
                continue
            visited.add(u)

            # Add to audit crawl list
            if len(found) < max_pages:
                found.append(u)

            # Queue for deeper crawl
            if depth < max_depth and len(found) < max_pages:
                q.append((u, depth + 1))

    return found, all_discovered, discovered_subdomains


def crawl_site(start: str, max_pages: int = 40, max_depth: int = 2, respect_domain: bool = True) -> list[str]:
    """Backward-compatible crawl returning list of URLs."""
    found, _, _ = crawl_site_with_sitemap(start, max_pages, max_depth, respect_domain)
    return found
