import requests
from urllib.parse import urljoin, urlparse, urldefrag
from bs4 import BeautifulSoup
from collections import deque
import tldextract


def normalize_url(base, u):
    u = urljoin(base, u)
    u = urldefrag(u)[0]
    p = urlparse(u)
    scheme = p.scheme if p.scheme else "http"
    netloc = p.netloc
    path = p.path or "/"
    query = ("?" + p.query) if p.query else ""
    return f"{scheme}://{netloc}{path}{query}"


def same_reg_domain(a, b):
    ea = tldextract.extract(a)
    eb = tldextract.extract(b)
    return (ea.domain, ea.suffix) == (eb.domain, eb.suffix)


def is_http(u):
    p = urlparse(u)
    return p.scheme in ("http", "https")


def extract_links(base, html):
    soup = BeautifulSoup(html, "html.parser")
    hrefs = set()
    hrefs.update([a.get("href", "") for a in soup.find_all("a", href=True)])
    hrefs.update([l.get("href") for l in soup.find_all("link", href=True)])
    hrefs.update([s.get("src") for s in soup.find_all(["script", "img", "iframe", "source"], src=True)])
    hrefs.update([f.get("action") for f in soup.find_all("form", action=True)])
    # filter None and javascript/mailto
    urls = set()
    for h in hrefs:
        if not h:
            continue
        if h.startswith("mailto:") or h.startswith("javascript:"):
            continue
        try:
            normalized = normalize_url(base, h)
            urls.add(normalized)
        except Exception:
            continue
    return urls


def fetch_html(url, timeout=10, headers=None):
    headers = headers or {"User-Agent": "ExploitFinderCrawler/0.1 (+https://example.local)"}
    try:
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=True)
        return r.text or ""
    except requests.RequestException:
        return ""


def crawl_site(start, max_pages=150, max_depth=2, respect_domain=True):
    start = normalize_url(start, start)
    visited = set([start])
    q = deque([(start, 0)])
    found = [start]
    while q:
        url, depth = q.popleft()
        html = fetch_html(url)
        if not html:
            continue
        links = extract_links(url, html)
        for u in links:
            u = normalize_url(url, u)
            if not is_http(u):
                continue
            if respect_domain and not same_reg_domain(start, u):
                continue
            if u in visited:
                continue
            visited.add(u)
            found.append(u)
            if len(found) >= max_pages:
                return found
            if depth < max_depth:
                q.append((u, depth + 1))
    return found
