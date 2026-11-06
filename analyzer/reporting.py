# analyzer/reporting.py
"""
High-accuracy reporting and consolidation module for Tarspectra.

Provides:
  - True-positive finding consolidation (removes redundant per-page missing header spam)
  - Severity scoring and summary generation
  - Site map JSON and text tree exporters
  - CSV and HTML report generators
"""

import os
import csv
import html
import json
from datetime import datetime
from collections import defaultdict
from urllib.parse import urlparse

SEV_LEVEL = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def ensure_dir(path):
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)


def severity_to_level(s):
    if not s:
        return 0
    return SEV_LEVEL.get(str(s).lower(), 1)


# Host-level header check IDs that apply to the entire domain, not just a single page
HOST_LEVEL_CHECK_IDS = {
    "missing_content_security_policy",
    "missing_x_content_type_options",
    "missing_frame_protection",
    "missing_referrer_policy",
    "missing_permissions_policy",
    "missing_hsts",
    "permissive_cors_credentials",
    "technology_disclosure_server",
    "technology_disclosure_x_powered_by",
    "technology_disclosure_x_aspnet_version",
    "technology_disclosure_x_aspnetmvc_version",
    "weak_csp_unsafe_inline",
    "weak_csp_unsafe_eval",
    "weak_csp_wildcard",
    "hsts_short_max_age",
}


def consolidate_findings(annotated_results: list[dict], tool_findings: list[dict] = None) -> list[dict]:
    """
    Consolidate findings across pages into a true-positive, non-redundant list.

    Instead of listing 'Missing CSP' 60 times for 60 crawled pages, it consolidates
    host-wide configuration findings into a single actionable card per host, with
    sample endpoints and affected page count.
    """
    consolidated = []
    host_findings_tracker = defaultdict(lambda: {
        "finding": None,
        "affected_urls": [],
        "count": 0,
    })

    # 1. Process passive and reflection findings from crawled pages
    for item in annotated_results:
        url = item.get("url", "")
        host = urlparse(url).netloc or "target"

        # Passive findings
        for f in item.get("passive_findings", []):
            fid = f.get("id", "")
            if fid in HOST_LEVEL_CHECK_IDS:
                # Group by host and finding ID
                key = (host, fid)
                tracker = host_findings_tracker[key]
                if tracker["finding"] is None:
                    tracker["finding"] = dict(f)
                    tracker["finding"]["target_host"] = host
                    tracker["finding"]["scope"] = "Host Configuration"
                tracker["affected_urls"].append(url)
                tracker["count"] += 1
            else:
                # Page-specific finding (e.g. form hygiene, sensitive disclosure, mixed content)
                finding_copy = dict(f)
                finding_copy["url"] = url
                finding_copy["scope"] = "Page Endpoint"
                consolidated.append(finding_copy)

        # Reflection findings
        for f in item.get("reflection_findings", []):
            finding_copy = dict(f)
            finding_copy["url"] = url
            finding_copy["scope"] = "Parameter Reflection"
            consolidated.append(finding_copy)

    # Finalize consolidated host-level findings
    for (host, fid), tracker in host_findings_tracker.items():
        base_f = tracker["finding"]
        total = tracker["count"]
        samples = tracker["affected_urls"][:4]
        samples_str = ", ".join(samples)
        if total > 4:
            samples_str += f" and {total - 4} more pages"

        base_f["url"] = f"https://{host}" if not host.startswith("http") else host
        base_f["affected_count"] = total
        base_f["sample_urls"] = tracker["affected_urls"][:10]
        base_f["evidence"] = f"{base_f.get('evidence', '')} (Observed across {total} crawled pages on {host}: {samples_str})"
        consolidated.append(base_f)

    # 2. Add open-source tool findings (Nuclei, Nikto, Nmap, sqlmap)
    seen_tool_keys = set()
    for tf in (tool_findings or []):
        t_key = (tf.get("source"), tf.get("title"), tf.get("uri"))
        if t_key in seen_tool_keys:
            continue
        seen_tool_keys.add(t_key)
        tf_copy = dict(tf)
        tf_copy.setdefault("scope", "Automated Tool")
        consolidated.append(tf_copy)

    # Sort: High -> Medium -> Low
    consolidated.sort(
        key=lambda item: (
            -severity_to_level(item.get("severity", "low")),
            item.get("source", ""),
            item.get("type", item.get("title", ""))
        )
    )

    return consolidated


def generate_summary(annotated_results, tool_findings=None):
    """
    Generate accurate summary counts from consolidated findings.
    """
    findings = consolidate_findings(annotated_results, tool_findings)
    summary = {
        "total_pages": len(annotated_results),
        "total_findings": len(findings),
        "by_type": {},
        "by_severity": {"high": 0, "medium": 0, "low": 0},
        "by_source": {},
    }

    for f in findings:
        sev = str(f.get("severity", "low")).lower()
        if sev not in summary["by_severity"]:
            summary["by_severity"][sev] = 0
        summary["by_severity"][sev] += 1

        ftype = f.get("type") or f.get("title") or "finding"
        summary["by_type"][ftype] = summary["by_type"].get(ftype, 0) + 1

        src = f.get("source", "passive_check")
        summary["by_source"][src] = summary["by_source"].get(src, 0) + 1

    return summary


def filter_by_min_severity(annotated_results, min_sev):
    if not min_sev:
        return annotated_results
    min_level = severity_to_level(min_sev)
    filtered = []
    for item in annotated_results:
        findings = item.get("passive_findings", []) + item.get("tool_findings", [])
        keep = False
        for f in findings:
            if severity_to_level(f.get("severity")) >= min_level:
                keep = True
                break
        if keep:
            filtered.append(item)
    return filtered


def generate_sitemap_ascii_tree(sitemap_data: dict) -> str:
    """Generate a clean ASCII tree representation of the site map."""
    lines = []
    root = sitemap_data.get("root_domain", "Target")
    total_subs = sitemap_data.get("total_subdomains", 0)
    total_eps = sitemap_data.get("total_endpoints", 0)

    lines.append(f"🌐 Site Map: {root} ({total_subs} subdomains, {total_eps} endpoints)")
    lines.append("─" * 60)

    subdomains = sitemap_data.get("subdomains", {})
    sub_keys = list(subdomains.keys())

    for idx, (sub_host, sub_info) in enumerate(subdomains.items()):
        is_last_sub = (idx == len(sub_keys) - 1)
        sub_prefix = "└── " if is_last_sub else "├── "
        child_prefix = "    " if is_last_sub else "│   "

        status = sub_info.get("status_code", "")
        status_tag = f" [{status}]" if status else ""
        server = f" (Server: {sub_info['server']})" if sub_info.get("server") else ""
        lines.append(f"{sub_prefix}🖥️  {sub_host}{status_tag}{server}")

        endpoints = sub_info.get("endpoints", [])
        for ep_idx, ep in enumerate(endpoints):
            is_last_ep = (ep_idx == len(endpoints) - 1)
            ep_connector = "└── " if is_last_ep else "├── "
            path = ep.get("path_with_query", ep.get("path", "/"))
            ep_status = ep.get("status_code", "")
            forms_info = f" [Forms: {ep['forms_count']}]" if ep.get("forms_count") else ""
            lines.append(f"{child_prefix}{ep_connector}📄 {path} ({ep_status}){forms_info}")

    return "\n".join(lines)


def write_csv_report(annotated_results, csv_path, tool_findings=None):
    ensure_dir(csv_path)
    findings = consolidate_findings(annotated_results, tool_findings)
    headers = ["severity", "confidence", "source", "title_or_type", "url", "evidence", "remediation", "affected_count"]

    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(headers)
        for f in findings:
            writer.writerow([
                f.get("severity", "low"),
                f.get("confidence", "medium"),
                f.get("source", "passive"),
                f.get("type", f.get("title", "")),
                f.get("url", ""),
                f.get("evidence", ""),
                f.get("remediation", ""),
                f.get("affected_count", 1),
            ])


def write_html_report(annotated_results, html_path, title="Tarspectra Security Audit", tool_findings=None, sitemap_data=None):
    ensure_dir(html_path)
    summary = generate_summary(annotated_results, tool_findings)
    findings = consolidate_findings(annotated_results, tool_findings)
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    findings_html = []
    for f in findings:
        sev = html.escape(str(f.get("severity", "low")).upper())
        sev_class = "sev-" + sev.lower()
        title_text = html.escape(str(f.get("type") or f.get("title") or "Finding"))
        url_text = html.escape(str(f.get("url", "")))
        source_text = html.escape(str(f.get("source", "Check")))
        conf = html.escape(str(f.get("confidence", "Medium")))
        evidence = html.escape(str(f.get("evidence", "")))
        remediation = html.escape(str(f.get("remediation", "Apply standard defense measures.")))
        curl_cmd = f.get("curl_command", "")
        curl_block = f"<div class='curl-block'><code>{html.escape(curl_cmd)}</code></div>" if curl_cmd else ""

        findings_html.append(f"""
        <div class="card finding-card">
          <div class="topline">
            <span class="badge {sev_class}">{sev}</span>
            <span class="source">{source_text}</span>
            <span class="conf">{conf}</span>
          </div>
          <h3>{title_text}</h3>
          <p class="url">{url_text}</p>
          <p class="evidence">{evidence}</p>
          {curl_block}
          <div class="remediation"><strong>Remediation:</strong> {remediation}</div>
        </div>
        """)

    sitemap_html = ""
    if sitemap_data:
        tree_text = html.escape(generate_sitemap_ascii_tree(sitemap_data))
        sitemap_html = f"""
        <h2>Discovered Site Map & Subdomain Hierarchy</h2>
        <pre class="sitemap-tree">{tree_text}</pre>
        """

    content = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>{html.escape(title)}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #07101d; color: #edf4ff; margin: 0; padding: 24px; }}
.shell {{ max-width: 1060px; margin: auto; }}
h1 {{ color: #7bf5d5; margin-bottom: 4px; }}
.stats {{ display: flex; gap: 14px; margin: 20px 0; }}
.stat-card {{ background: #0c1a2c; padding: 14px 20px; border-radius: 8px; border: 1px solid rgba(177,205,239,0.15); }}
.stat-card strong {{ font-size: 24px; display: block; }}
.stat-card span {{ font-size: 11px; text-transform: uppercase; color: #9aabc0; }}
.card {{ background: #0c1a2c; border: 1px solid rgba(177,205,239,0.15); border-radius: 8px; padding: 16px; margin-bottom: 12px; }}
.topline {{ display: flex; gap: 10px; align-items: center; margin-bottom: 8px; font-size: 11px; font-weight: 700; }}
.badge {{ padding: 2px 8px; border-radius: 4px; font-weight: 800; }}
.sev-high {{ background: rgba(255,131,126,0.2); color: #ff837e; }}
.sev-medium {{ background: rgba(255,200,112,0.2); color: #ffc870; }}
.sev-low {{ background: rgba(130,201,255,0.2); color: #82c9ff; }}
.url {{ color: #7bf5d5; font-family: monospace; font-size: 12px; }}
.evidence {{ color: #9aabc0; font-size: 13px; white-space: pre-wrap; }}
.remediation {{ border-top: 1px solid rgba(177,205,239,0.1); padding-top: 8px; margin-top: 8px; font-size: 12px; color: #edf4ff; }}
.curl-block {{ background: #040a12; padding: 8px 12px; border-radius: 4px; margin: 8px 0; overflow-x: auto; font-family: monospace; font-size: 12px; color: #7bf5d5; }}
.sitemap-tree {{ background: #040a12; padding: 16px; border-radius: 8px; border: 1px solid rgba(177,205,239,0.15); font-family: monospace; font-size: 13px; color: #7bf5d5; overflow-x: auto; }}
</style>
</head>
<body>
<div class="shell">
  <h1>{html.escape(title)}</h1>
  <p style="color:#9aabc0;font-size:13px;">Generated: {now} | Target audit scope</p>
  <div class="stats">
    <div class="stat-card"><strong>{summary['total_pages']}</strong><span>Pages Crawled</span></div>
    <div class="stat-card"><strong>{summary['total_findings']}</strong><span>True Findings</span></div>
    <div class="stat-card"><strong style="color:#ff837e">{summary['by_severity'].get('high',0)}</strong><span>High Priority</span></div>
    <div class="stat-card"><strong style="color:#ffc870">{summary['by_severity'].get('medium',0)}</strong><span>Medium Priority</span></div>
  </div>
  {sitemap_html}
  <h2>Security Findings & Audit Signals</h2>
  {''.join(findings_html)}
</div>
</body>
</html>"""

    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(content)
