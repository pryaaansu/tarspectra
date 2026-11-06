"""Passive, explainable web-security checks used by the CLI and web dashboard.

The checks in this module inspect responses already collected by the scanner. They
do not send exploit payloads or submit forms, so a finding is an audit signal that
should be verified manually before it is treated as a confirmed vulnerability.
"""

from urllib.parse import urlparse
import re


def _finding(key, title, severity, evidence, remediation, confidence="medium"):
    return {
        "id": key,
        "type": title,
        "severity": severity,
        "confidence": confidence,
        "evidence": evidence,
        "remediation": remediation,
        "source": "passive_check",
    }


def _headers_lower(headers):
    return {str(key).lower(): str(value) for key, value in (headers or {}).items()}


def check_security_headers(response):
    """Return missing-header and risky-header findings for a fetched response."""
    headers = _headers_lower(response.get("headers"))
    parsed_url = urlparse(response.get("url", ""))
    findings = []

    # --- Missing required headers ---
    required_headers = [
        (
            "missing_content_security_policy",
            "Missing Content Security Policy",
            "medium",
            "Content-Security-Policy header was not present.",
            "Deploy a restrictive Content-Security-Policy and allow only the sources the application needs.",
        ),
        (
            "missing_x_content_type_options",
            "Missing MIME-sniffing protection",
            "low",
            "X-Content-Type-Options header was not present.",
            "Set X-Content-Type-Options: nosniff on responses that serve user-controlled content.",
        ),
        (
            "missing_frame_protection",
            "Missing clickjacking protection",
            "medium",
            "Neither X-Frame-Options nor frame-ancestors in Content-Security-Policy was found.",
            "Use CSP frame-ancestors (preferred) or X-Frame-Options to limit where pages may be framed.",
        ),
        (
            "missing_referrer_policy",
            "Missing Referrer-Policy",
            "low",
            "Referrer-Policy header was not present.",
            "Set a policy such as strict-origin-when-cross-origin to reduce URL data leakage.",
        ),
        (
            "missing_permissions_policy",
            "Missing Permissions-Policy",
            "low",
            "Permissions-Policy header was not present.",
            "Explicitly disable browser features that this application does not require.",
        ),
    ]

    for key, title, severity, evidence, remediation in required_headers:
        if key == "missing_frame_protection":
            csp = headers.get("content-security-policy", "").lower()
            present = "x-frame-options" in headers or "frame-ancestors" in csp
        else:
            header_name = {
                "missing_content_security_policy": "content-security-policy",
                "missing_x_content_type_options": "x-content-type-options",
                "missing_referrer_policy": "referrer-policy",
                "missing_permissions_policy": "permissions-policy",
            }[key]
            present = header_name in headers
        if not present:
            findings.append(_finding(key, title, severity, evidence, remediation))

    # --- HSTS (HTTPS only) ---
    if parsed_url.scheme == "https" and "strict-transport-security" not in headers:
        findings.append(
            _finding(
                "missing_hsts",
                "Missing HTTP Strict Transport Security",
                "medium",
                "The HTTPS response did not include Strict-Transport-Security.",
                "After confirming every subdomain supports HTTPS, enable HSTS with an appropriate max-age.",
            )
        )

    # --- Unsafe CORS: wildcard + credentials ---
    cors_origin = headers.get("access-control-allow-origin", "")
    cors_creds = headers.get("access-control-allow-credentials", "").lower()
    if cors_origin == "*" and cors_creds == "true":
        findings.append(
            _finding(
                "permissive_cors_credentials",
                "Potentially unsafe CORS configuration",
                "high",
                "Access-Control-Allow-Origin: * was returned together with Access-Control-Allow-Credentials: true.",
                "Return a validated, explicit Origin value and only enable credentials where necessary.",
                "high",
            )
        )

    # --- Technology disclosure headers ---
    for header in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        val = headers.get(header, "")
        if val:
            # Only flag if there is a version number disclosed (more precise)
            has_version = bool(re.search(r'\d', val))
            severity = "medium" if has_version else "low"
            findings.append(
                _finding(
                    "technology_disclosure_" + header.replace("-", "_"),
                    "Technology disclosure header",
                    severity,
                    f"{header}: {val}",
                    "Remove unnecessary implementation and version headers at the web-server or application layer.",
                    "low",
                )
            )

    # --- Weak CSP directives ---
    csp_val = headers.get("content-security-policy", "")
    if csp_val:
        csp_lower = csp_val.lower()
        if "'unsafe-inline'" in csp_lower:
            findings.append(
                _finding(
                    "weak_csp_unsafe_inline",
                    "Weak CSP: unsafe-inline present",
                    "medium",
                    f"Content-Security-Policy contains 'unsafe-inline': {csp_val[:200]}",
                    "Remove 'unsafe-inline' from CSP; use nonces or hashes instead.",
                    "high",
                )
            )
        if "'unsafe-eval'" in csp_lower:
            findings.append(
                _finding(
                    "weak_csp_unsafe_eval",
                    "Weak CSP: unsafe-eval present",
                    "medium",
                    f"Content-Security-Policy contains 'unsafe-eval': {csp_val[:200]}",
                    "Remove 'unsafe-eval' from CSP; refactor code to avoid eval().",
                    "high",
                )
            )
        if re.search(r"(?:script-src|default-src)[^;]*\*", csp_lower):
            findings.append(
                _finding(
                    "weak_csp_wildcard",
                    "Weak CSP: wildcard source in script-src or default-src",
                    "medium",
                    f"Content-Security-Policy allows wildcard script sources: {csp_val[:200]}",
                    "Replace wildcard sources with specific, trusted origins.",
                    "medium",
                )
            )

    # --- HSTS without includeSubDomains / short max-age ---
    hsts_val = headers.get("strict-transport-security", "")
    if hsts_val:
        m = re.search(r'max-age\s*=\s*(\d+)', hsts_val, re.I)
        if m:
            max_age = int(m.group(1))
            if max_age < 15552000:  # < 180 days
                findings.append(
                    _finding(
                        "hsts_short_max_age",
                        "HSTS max-age is too short",
                        "low",
                        f"Strict-Transport-Security max-age={max_age} (< 180 days recommended).",
                        "Set max-age to at least 15552000 (180 days), ideally 31536000 (1 year).",
                    )
                )

    return findings


def check_cookies(response):
    """Inspect Set-Cookie flags for each individual cookie."""
    headers = _headers_lower(response.get("headers"))
    raw_cookies = response.get("headers", {}) or {}
    # Collect all Set-Cookie header values (some HTTP clients join them)
    cookie_headers = []
    for k, v in raw_cookies.items():
        if k.lower() == "set-cookie":
            # May be a list in some http libraries
            if isinstance(v, list):
                cookie_headers.extend(v)
            else:
                cookie_headers.append(v)

    if not cookie_headers:
        return []

    is_https = urlparse(response.get("url", "")).scheme == "https"
    findings = []

    for raw_cookie in cookie_headers:
        cookie_lower = raw_cookie.lower()
        # Extract cookie name for better evidence
        cookie_name = raw_cookie.split("=")[0].strip() if "=" in raw_cookie else "unknown"

        if is_https and "secure" not in cookie_lower:
            findings.append(
                _finding(
                    "cookie_without_secure",
                    "Cookie missing Secure attribute",
                    "medium",
                    f"Cookie '{cookie_name}' on HTTPS response lacks the Secure attribute.",
                    "Mark authentication and session cookies Secure so browsers send them only over HTTPS.",
                )
            )
        if "httponly" not in cookie_lower:
            # Skip non-session cookies (analytics, etc.) — only flag if name suggests session/auth
            is_likely_session = any(
                t in cookie_name.lower()
                for t in ("sess", "auth", "token", "user", "uid", "account", "login", "id")
            )
            severity = "medium" if is_likely_session else "low"
            findings.append(
                _finding(
                    "cookie_without_httponly",
                    "Cookie missing HttpOnly attribute",
                    severity,
                    f"Cookie '{cookie_name}' lacks the HttpOnly attribute.",
                    "Mark session cookies HttpOnly unless client-side JavaScript truly needs to read them.",
                )
            )
        if "samesite" not in cookie_lower:
            findings.append(
                _finding(
                    "cookie_without_samesite",
                    "Cookie missing SameSite attribute",
                    "low",
                    f"Cookie '{cookie_name}' lacks a SameSite attribute (cross-site request risk).",
                    "Set SameSite=Lax or SameSite=Strict where application flows permit it.",
                )
            )

    # Deduplicate by (id, cookie_name snippet)
    seen = set()
    unique = []
    for f in findings:
        key = (f["id"], f["evidence"][:60])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def check_forms(response):
    """Flag only clear form hygiene issues and label heuristic results accordingly."""
    findings = []
    for form in response.get("forms_detail", []) or []:
        method = (form.get("method") or "get").lower()
        inputs = form.get("inputs") or []
        input_types = {str(item.get("type", "text")).lower() for item in inputs}
        input_names = {str(item.get("name", "")).lower() for item in inputs}

        if method == "get" and "password" in input_types:
            findings.append(
                _finding(
                    "password_form_get",
                    "Password form uses GET",
                    "high",
                    f"Form action '{form.get('action') or response.get('url')}' contains a password field but uses GET.",
                    "Use POST over HTTPS for password submission so credentials are not placed in URLs, history, or logs.",
                    "high",
                )
            )
        if method == "post":
            has_token = any(
                any(term in name for term in ("csrf", "xsrf", "token", "nonce", "_wpnonce", "authenticity"))
                for name in input_names
            )
            if not has_token:
                findings.append(
                    _finding(
                        "post_form_missing_csrf_hint",
                        "POST form has no visible CSRF token",
                        "low",
                        f"POST form action '{form.get('action') or response.get('url')}' has no hidden input with a CSRF-like name.",
                        "Verify server-side CSRF defenses manually; token names and alternative protections can make this a false positive.",
                        "low",
                    )
                )

    return findings


def check_mixed_content(response):
    """Check if an HTTPS page loads resources over HTTP (mixed content)."""
    findings = []
    if urlparse(response.get("url", "")).scheme != "https":
        return findings

    body = response.get("body_snippet", "") or ""
    # Look for http:// in src/href attributes
    http_resources = re.findall(
        r'(?:src|href|action)\s*=\s*["\']?(http://[^\s"\'<>]+)',
        body,
        re.IGNORECASE,
    )
    for res in http_resources[:5]:  # cap at 5 examples
        findings.append(
            _finding(
                "mixed_content",
                "Mixed content: HTTP resource on HTTPS page",
                "medium",
                f"HTTP resource loaded on HTTPS page: {res[:150]}",
                "Serve all resources over HTTPS. Update hardcoded http:// URLs to https://.",
            )
        )
    return findings


def check_information_disclosure(response):
    """Detect common information-disclosure patterns in response body."""
    findings = []
    body = response.get("body_snippet", "") or ""

    patterns = [
        # Stack traces / exceptions
        (r"(?:Traceback \(most recent call last\)|at\s+[\w$\.]+\([\w\.]+:\d+\)|Exception in thread|NullPointerException|System\.Exception)",
         "Stack trace or exception leaked in response",
         "medium",
         "Application error details (stack trace / exception) are visible in the response body.",
         "Return a generic error page in production; log detailed errors server-side only.",
         "high"),
        # Database errors
        (r"(?:SQL syntax|mysql_fetch|ORA-\d{5}|pg_query|SQLSTATE|Unclosed quotation mark|syntax error.*SQL)",
         "Database error message in response",
         "high",
         "A database error message is visible in the response body — may indicate SQL injection surface.",
         "Suppress database errors in production output; use parameterized queries.",
         "high"),
        # Debug/config file paths
        (r"/etc/passwd|/etc/shadow|/proc/self|web\.config|app\.config|\.env\b",
         "Sensitive file path or config reference in response",
         "high",
         "A reference to a sensitive system file was found in the response body.",
         "Audit server file access controls; remove debug output and error details from production responses.",
         "medium"),
        # AWS / cloud keys
        (r"AKIA[0-9A-Z]{16}",
         "Possible AWS Access Key ID exposed",
         "high",
         "A string matching the pattern of an AWS Access Key ID was found in the response.",
         "Rotate the key immediately; audit IAM permissions and use secrets management (e.g. AWS Secrets Manager).",
         "high"),
        # Private key headers
        (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
         "Private key material in response",
         "high",
         "A PEM private key header was found in the response body.",
         "Remove private key material from public responses; rotate all affected keys immediately.",
         "high"),
    ]

    for pattern, title, severity, evidence_prefix, remediation, confidence in patterns:
        m = re.search(pattern, body, re.IGNORECASE | re.MULTILINE)
        if m:
            snippet = body[max(0, m.start()-40):m.end()+40].strip()
            findings.append(
                _finding(
                    "info_disclosure_" + re.sub(r'\W+', '_', title.lower())[:40],
                    title,
                    severity,
                    f"{evidence_prefix} — snippet: {snippet[:200]}",
                    remediation,
                    confidence,
                )
            )

    return findings


def run_passive_security_checks(response):
    """Run all passive checks and return a stable, deduplicated list."""
    checks = (
        check_security_headers(response)
        + check_cookies(response)
        + check_forms(response)
        + check_mixed_content(response)
        + check_information_disclosure(response)
    )
    seen = set()
    unique = []
    for finding in checks:
        key = (finding["id"], finding["evidence"][:80])
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique
