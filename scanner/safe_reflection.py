"""Low-impact reflection checks for explicitly authorized scans.

Only a harmless unique marker is sent to existing GET query parameters.  No
forms are submitted, no payload lists are used, and a reflection is reported as
a lead requiring manual verification rather than an exploit confirmation.
"""

from __future__ import annotations

import secrets
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests


USER_AGENT = "Tarspectra-Reflection-Check/1.0"


def build_marker():
    return "TARSPECTRA_MARKER_" + secrets.token_hex(8)


def inject_marker(url, parameter, marker):
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[parameter] = [marker]
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


def run_safe_reflection_checks(items, max_checks=50, timeout=10):
    """Test at most ``max_checks`` existing GET parameters with a text marker."""
    findings_by_url = {}
    attempts = 0
    for item in items:
        url = item.get("url", "")
        for parameter in item.get("query_params", []) or []:
            if attempts >= max_checks:
                return findings_by_url
            marker = build_marker()
            test_url = inject_marker(url, parameter, marker)
            attempts += 1
            try:
                response = requests.get(
                    test_url,
                    headers={"User-Agent": USER_AGENT},
                    timeout=timeout,
                    allow_redirects=True,
                )
            except requests.RequestException:
                continue
            body = response.text or ""
            if marker not in body:
                continue
            location = body.find(marker)
            excerpt = body[max(0, location - 90): location + len(marker) + 90]
            findings_by_url.setdefault(url, []).append(
                {
                    "id": "reflected_marker",
                    "type": "Reflected input marker",
                    "severity": "low",
                    "confidence": "medium",
                    "source": "safe_reflection_check",
                    "parameter": parameter,
                    "evidence": excerpt,
                    "remediation": "Manually verify the HTML and JavaScript context, then apply context-aware output encoding and input validation.",
                    "note": "This is a reflection signal, not proof of script execution.",
                }
            )
    return findings_by_url
