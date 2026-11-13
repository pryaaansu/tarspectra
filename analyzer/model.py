"""
analyzer/model.py — Annotate fetched responses with passive security findings.

The old keyword-pattern matching (PATTERNS / analyze_response) was the primary
source of false positives: it flagged any page whose body *mentioned* words like
"xss" or "sql" (including security blogs, WAF info pages, etc.).

This version removes that unreliable heuristic and replaces vuln_findings with
only the signals that have clear, verifiable evidence:
  - passive_findings  → header/cookie/form/mixed-content/info-disclosure checks
  - tool_findings     → set externally by tools_runner (nikto, nmap, sqlmap)

The legacy vuln_findings key is retained as an empty list so the frontend and
reporting code do not break.
"""

from __future__ import annotations

from analyzer.security_checks import run_passive_security_checks


def annotate_results(results: list[dict], check_headers: bool = True) -> list[dict]:
    """
    Accept a list of fetch_details results and return a new list where each
    item has:
      - "passive_findings": accurate header/cookie/form/disclosure checks
      - "vuln_findings": always [] (legacy key, previously unreliable)
      - "tool_findings": [] placeholder filled in by tools_runner later
    """
    annotated = []
    for r in results:
        new_r = dict(r)
        new_r["passive_findings"] = run_passive_security_checks(new_r, check_headers=check_headers)
        new_r["vuln_findings"] = []          # kept for API compatibility
        new_r.setdefault("tool_findings", [])
        annotated.append(new_r)
    return annotated
