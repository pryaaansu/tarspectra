"""
sitemap.py — Hierarchical Site Map & Subdomain Discovery for Tarspectra.

Groups discovered endpoints under their respective subdomains and registered domains.
Combines:
  1. Passive subdomain enumeration via ProjectDiscovery's subfinder (if installed)
  2. Subdomains and endpoints extracted during crawler execution
  3. Live status and metadata resolution (status code, content-type, parameters, forms)
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlparse, parse_qs
import tldextract


def get_registered_domain(url_or_host: str) -> str:
    """Extract apex / registered domain (e.g. dsatm.edu.in or example.com)."""
    extracted = tldextract.extract(url_or_host)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}".lower()
    return url_or_host.lower()


def get_subdomain_host(url: str) -> str:
    """Extract host string from url (e.g. portal.dsatm.edu.in)."""
    p = urlparse(url)
    return (p.hostname or p.netloc or "").lower().split(":")[0]


def run_subfinder_passive(domain: str, timeout: int = 15,
                         log_cb: Optional[Callable[[str], None]] = None) -> list[str]:
    """
    Run subfinder passively on *domain* to enumerate valid subdomains.
    Returns a sorted list of discovered hostnames.
    """
    tool = shutil.which("subfinder")
    if not tool:
        return []

    try:
        if log_cb:
            log_cb(f"[subfinder] Enumerating passive subdomains for {domain}…")

        cmd = [tool, "-d", domain, "-silent", "-timeout", str(min(timeout, 12)), "-max-time", str(timeout)]
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            errors="replace"
        )
        subdomains = []
        for line in proc.stdout.splitlines():
            host = line.strip().lower()
            if host and "." in host and not host.startswith("*"):
                subdomains.append(host)

        subdomains = sorted(set(subdomains))
        if log_cb:
            log_cb(f"[subfinder] Discovered {len(subdomains)} subdomains for {domain}")
        return subdomains
    except Exception as exc:
        if log_cb:
            log_cb(f"[subfinder] Subdomain lookup error: {exc}")
        return []


def build_hierarchical_sitemap(target_url: str,
                               collected_pages: list[dict],
                               discovered_urls: set[str],
                               passive_subdomains: Optional[list[str]] = None) -> dict:
    """
    Build a structured, hierarchical site map:
      Root Domain -> Subdomains -> Endpoints / Paths
    """
    root_domain = get_registered_domain(target_url)
    target_parsed = urlparse(target_url)
    target_scheme = target_parsed.scheme or "https"

    # Map of host -> { metadata, endpoints }
    subdomain_map = defaultdict(lambda: {
        "host": "",
        "scheme": target_scheme,
        "is_target_host": False,
        "is_alive": False,
        "status_code": 0,
        "server": "",
        "total_endpoints": 0,
        "endpoints": [],
    })

    # Index pages collected by crawler
    pages_by_url = {page.get("url", ""): page for page in collected_pages}

    # All unique URLs to organize
    all_urls = set(discovered_urls)
    all_urls.add(target_url)
    for page in collected_pages:
        if page.get("url"):
            all_urls.add(page["url"])

    target_host = get_subdomain_host(target_url)
    subdomain_map[target_host]["is_target_host"] = True
    subdomain_map[target_host]["host"] = target_host

    # Add passive subdomains found via subfinder
    for sub in (passive_subdomains or []):
        sub_host = sub.strip().lower()
        if sub_host and (sub_host == root_domain or sub_host.endswith("." + root_domain)):
            subdomain_map[sub_host]["host"] = sub_host
            subdomain_map[sub_host]["scheme"] = target_scheme

    # Group URLs under their respective subdomains
    for url in sorted(all_urls):
        host = get_subdomain_host(url)
        if not host:
            continue
        # Check if it belongs to root domain
        if host != root_domain and not host.endswith("." + root_domain):
            continue

        p = urlparse(url)
        path = p.path or "/"
        query = p.query
        params = list(parse_qs(query).keys())

        page_meta = pages_by_url.get(url, {})
        status = page_meta.get("status_code", 0)
        ctype = page_meta.get("content_type", "")
        headers = page_meta.get("headers", {}) or {}
        server = headers.get("server", headers.get("Server", ""))
        forms = page_meta.get("forms_detail", []) or []

        sub_info = subdomain_map[host]
        sub_info["host"] = host
        sub_info["scheme"] = p.scheme or target_scheme

        if status > 0:
            sub_info["is_alive"] = True
            if not sub_info["status_code"] or sub_info["status_code"] == 0:
                sub_info["status_code"] = status
            if server and not sub_info["server"]:
                sub_info["server"] = server

        # Avoid duplicate endpoint paths
        existing_paths = {ep["path_with_query"] for ep in sub_info["endpoints"]}
        path_with_query = path + (f"?{query}" if query else "")

        if path_with_query not in existing_paths:
            sub_info["endpoints"].append({
                "url": url,
                "path": path,
                "path_with_query": path_with_query,
                "query": query,
                "params": params,
                "status_code": status,
                "content_type": ctype,
                "forms_count": len(forms),
                "forms": [
                    {
                        "action": f.get("action", ""),
                        "method": (f.get("method") or "get").upper(),
                        "inputs": [inp.get("name") for inp in f.get("inputs", []) if inp.get("name")]
                    }
                    for f in forms
                ]
            })

    # Sort endpoints per subdomain (e.g. root / first, then alphabetically)
    for host, data in subdomain_map.items():
        data["endpoints"].sort(key=lambda ep: (0 if ep["path"] == "/" else 1, ep["path"]))
        data["total_endpoints"] = len(data["endpoints"])

    # Convert to clean sorted dictionary
    subdomains_sorted = dict(
        sorted(
            subdomain_map.items(),
            key=lambda item: (0 if item[1]["is_target_host"] else 1, item[0])
        )
    )

    total_endpoints_all = sum(s["total_endpoints"] for s in subdomains_sorted.values())

    return {
        "root_domain": root_domain,
        "target_url": target_url,
        "total_subdomains": len(subdomains_sorted),
        "total_endpoints": total_endpoints_all,
        "subdomains": subdomains_sorted,
    }
