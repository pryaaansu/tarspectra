import json
import os
import re

PATTERNS_PATH = os.path.join(os.path.dirname(__file__), "patterns.json")


def load_patterns():
    try:
        with open(PATTERNS_PATH, "r") as f:
            data = json.load(f)
        # normalize to lowercase
        return {k: [p.lower() for p in v] for k, v in data.items()}
    except Exception:
        return {}


PATTERNS = load_patterns()


def find_matches_in_text(text, keywords):
    hits = []
    if not text:
        return hits
    low = text.lower()
    for kw in keywords:
        if kw in low:
            hits.append(kw)
    return hits


def analyze_response(resp):
    """
    resp is expected to be an object like the ones produced by fetch_details:
    {
      "url": "...",
      "status_code": 200,
      "content_type": "...",
      "body_snippet": "...",
      "query_params": [...],
      "form_inputs": [...],
      "form_actions": [...],
      "headers": {...}
    }
    Returns a list of findings. Each finding: {"type": "xss", "evidence": "alert(", "location": "body", "severity": "low"}
    """
    findings = []
    body = resp.get("body_snippet", "") or ""
    headers = resp.get("headers", {}) or {}
    params = resp.get("query_params", []) or []
    forms = resp.get("form_inputs", []) or []
    form_actions = resp.get("form_actions", []) or []

    # check body and headers (text content)
    for vtype, keywords in PATTERNS.items():
        # check body
        body_hits = find_matches_in_text(body, keywords)
        for hit in body_hits:
            findings.append({
                "type": vtype,
                "evidence": hit,
                "location": "body",
                "severity_score": 1
            })

        # check headers (values)
        header_text = " ".join([f"{k}: {v}" for k, v in headers.items()])
        header_hits = find_matches_in_text(header_text, keywords)
        for hit in header_hits:
            findings.append({
                "type": vtype,
                "evidence": hit,
                "location": "headers",
                "severity_score": 1
            })

        # check query param names & values (params is a list of param names)
        for p in params:
            if any(kw in p.lower() for kw in keywords):
                findings.append({
                    "type": vtype,
                    "evidence": p,
                    "location": "query_param",
                    "severity_score": 1
                })

        # check form input names
        for fi in forms:
            if fi and any(kw in (fi or "").lower() for kw in keywords):
                findings.append({
                    "type": vtype,
                    "evidence": fi,
                    "location": "form_input",
                    "severity_score": 1
                })

        # check form actions (URL)
        for fa in form_actions:
            if fa and any(kw in (fa or "").lower() for kw in keywords):
                findings.append({
                    "type": vtype,
                    "evidence": fa,
                    "location": "form_action",
                    "severity_score": 1
                })

    # aggregate similar types and produce a severity string
    aggregated = {}
    for f in findings:
        t = f["type"]
        aggregated.setdefault(t, {"count": 0, "evidence": []})
        aggregated[t]["count"] += 1
        aggregated[t]["evidence"].append({"evidence": f["evidence"], "location": f["location"]})

    result_list = []
    for t, info in aggregated.items():
        count = info["count"]
        if count >= 4:
            sev = "high"
        elif count >= 2:
            sev = "medium"
        else:
            sev = "low"
        result_list.append({
            "type": t,
            "count": count,
            "severity": sev,
            "evidence": info["evidence"]
        })

    return result_list


def annotate_results(results):
    """
    Accepts a list of fetch_details results and returns a new list where each item
    has an extra key: "vuln_findings": [...]
    """
    annotated = []
    for r in results:
        findings = analyze_response(r)
        new_r = dict(r)
        new_r["vuln_findings"] = findings
        annotated.append(new_r)
    return annotated
