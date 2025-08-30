# analyzer/reporting.py
import os
import csv
import html
from datetime import datetime

SEV_LEVEL = {"low": 1, "medium": 2, "high": 3}


def ensure_dir(path):
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)


def severity_to_level(s):
    if not s:
        return 0
    return SEV_LEVEL.get(s.lower(), 0)


def filter_by_min_severity(annotated_results, min_sev):
    if not min_sev:
        return annotated_results
    min_level = severity_to_level(min_sev)
    filtered = []
    for item in annotated_results:
        findings = item.get("vuln_findings", [])
        keep = False
        for f in findings:
            if severity_to_level(f.get("severity")) >= min_level:
                keep = True
                break
        if keep:
            filtered.append(item)
    return filtered


def generate_summary(annotated_results):
    summary = {
        "total_pages": len(annotated_results),
        "total_findings": 0,
        "by_type": {},
        "by_severity": {}
    }
    for item in annotated_results:
        for f in item.get("vuln_findings", []):
            t = f.get("type", "unknown")
            s = f.get("severity", "low")
            count = f.get("count", 1)
            summary["total_findings"] += count
            summary["by_type"][t] = summary["by_type"].get(t, 0) + count
            summary["by_severity"][s] = summary["by_severity"].get(s, 0) + count
        for af in item.get("active_findings", []):
            for fdet in af.get("findings", []):
                t = fdet.get("type", "active")
                summary["total_findings"] += 1
                summary["by_type"][t] = summary["by_type"].get(t, 0) + 1
                summary["by_severity"]["low"] = summary["by_severity"].get("low", 0) + 1
    return summary


def write_csv_report(annotated_results, csv_path):
    ensure_dir(csv_path)
    headers = [
        "url", "status_code", "content_type", "finding_type",
        "finding_count", "severity", "evidence_snippets", "timestamp",
        "active_findings_count", "active_payloads_sample", "active_artifacts_sample"
    ]
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(headers)
        for item in annotated_results:
            url = item.get("url", "")
            status = item.get("status_code", "")
            ctype = item.get("content_type", "")
            ts = item.get("timestamp", "")
            vuln_written = False
            for f in item.get("vuln_findings", []):
                ftype = f.get("type", "")
                count = f.get("count", 0)
                sev = f.get("severity", "")
                evid = "; ".join([html.escape(str(e.get("evidence", ""))) + "@" + e.get("location", "") for e in f.get("evidence", [])])

                af_list = item.get("active_findings", []) or []
                af_count = len(af_list)
                payloads_sample = []
                artifacts_sample = []
                seenp = set()
                for af in af_list:
                    # prefer payload_variant inside findings
                    for fd in af.get("findings", []):
                        pv = fd.get("payload_variant")
                        if pv and pv not in seenp:
                            payloads_sample.append(pv)
                            seenp.add(pv)
                    # fallback to variants_tested if no payload_variant captured yet
                    if not payloads_sample:
                        for pv in af.get("variants_tested", []):
                            if pv and pv not in seenp:
                                payloads_sample.append(pv)
                                seenp.add(pv)
                    # artifacts filenames
                    for fd in af.get("findings", []):
                        if fd.get("request_file"):
                            artifacts_sample.append(os.path.basename(fd.get("request_file")))
                        if fd.get("response_file"):
                            artifacts_sample.append(os.path.basename(fd.get("response_file")))
                    if len(payloads_sample) >= 3:
                        break

                writer.writerow([url, status, ctype, ftype, count, sev, evid, ts, af_count, " | ".join(payloads_sample), " | ".join(artifacts_sample)])
                vuln_written = True

            if not vuln_written:
                af_list = item.get("active_findings", []) or []
                af_count = len(af_list)
                payloads_sample = []
                artifacts_sample = []
                seenp = set()
                for af in af_list:
                    for fd in af.get("findings", []):
                        pv = fd.get("payload_variant")
                        if pv and pv not in seenp:
                            payloads_sample.append(pv)
                            seenp.add(pv)
                    if not payloads_sample:
                        for pv in af.get("variants_tested", []):
                            if pv and pv not in seenp:
                                payloads_sample.append(pv)
                                seenp.add(pv)
                    for fd in af.get("findings", []):
                        if fd.get("request_file"):
                            artifacts_sample.append(os.path.basename(fd.get("request_file")))
                        if fd.get("response_file"):
                            artifacts_sample.append(os.path.basename(fd.get("response_file")))
                    if len(payloads_sample) >= 3:
                        break
                if af_count:
                    writer.writerow([url, status, ctype, "", 0, "", "", ts, af_count, " | ".join(payloads_sample), " | ".join(artifacts_sample)])
                else:
                    writer.writerow([url, status, ctype, "", 0, "", "", ts, 0, "", ""])


def write_html_report(annotated_results, html_path, title="Exploit Finder Report"):
    ensure_dir(html_path)
    summary = generate_summary(annotated_results)
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    css = """
    body{font-family:Inter,system-ui,Segoe UI,Arial,Helvetica,sans-serif;margin:20px}
    h1,h2{color:#111827}
    .summary{display:flex;gap:20px;flex-wrap:wrap;margin-bottom:20px}
    .card{border:1px solid #e5e7eb;padding:12px;border-radius:8px;min-width:200px}
    table{width:100%;border-collapse:collapse;margin-top:12px}
    th,td{border:1px solid #e5e7eb;padding:8px;text-align:left;font-size:13px;vertical-align:top}
    th{background:#f3f4f6}
    .sev-low{color:#065f46;font-weight:600}
    .sev-medium{color:#92400e;font-weight:700}
    .sev-high{color:#b91c1c;font-weight:800}
    .small{font-size:12px;color:#6b7280}
    .active-block{background:#f8fafc;border:1px dashed #e5e7eb;padding:8px;border-radius:6px;margin-top:6px}
    .payload{font-family:monospace;font-size:12px;background:#f3f4f6;padding:2px 6px;border-radius:4px;margin-right:6px;display:inline-block}
    .artifact{font-family:monospace;font-size:12px;background:#fff7ed;padding:2px 6px;border-radius:4px;margin-right:6px;display:inline-block}
    """

    rows_html = []
    for item in annotated_results:
        url = html.escape(item.get("url", ""))
        status = item.get("status_code", "")
        ctype = html.escape(item.get("content_type", ""))
        findings = item.get("vuln_findings", [])
        if findings:
            finds_html = "<ul>"
            for f in findings:
                sev = f.get("severity", "low")
                sev_class = "sev-" + sev
                evids = "<br>".join([html.escape(e.get("evidence", "")) + " <span class='small'>(" + e.get("location", "") + ")</span>" for e in f.get("evidence", [])])
                finds_html += f"<li><b>{html.escape(f.get('type',''))}</b> - <span class='{sev_class}'>{sev.upper()}</span> (count: {f.get('count')})<div class='small'>{evids}</div></li>"
            finds_html += "</ul>"
        else:
            finds_html = "<span class='small'>no heuristic findings</span>"

        active_list = item.get("active_findings", []) or []
        if active_list:
            active_html = "<div class='active-block'><b>Active findings:</b>"
            for af in active_list[:200]:
                param = html.escape(str(af.get("param", "")))
                payload_template = af.get("payload_template") or ""
                payload_template_esc = html.escape(payload_template)
                variants = af.get("variants_tested", []) or []
                variants_html = ""
                if variants:
                    variants_html = "<div class='small' style='margin-top:6px'>Variants tested: " + ", ".join([f"<span class='payload'>{html.escape(v)}</span>" for v in variants[:12]]) + "</div>"
                ff = af.get("findings", []) or []
                if ff:
                    ff_html = "<ul>"
                    for fd in ff:
                        ftype = html.escape(fd.get("type", ""))
                        evidence = html.escape(str(fd.get("evidence", "")))
                        payload_variant = fd.get("payload_variant") or ""
                        payload_variant_esc = html.escape(payload_variant)
                        reqf = fd.get("request_file")
                        respf = fd.get("response_file")
                        artifact_links = ""
                        if reqf:
                            artifact_links += f"<a class='artifact' href='file://{html.escape(reqf)}' target='_blank'>req</a>"
                        if respf:
                            artifact_links += f"<a class='artifact' href='file://{html.escape(respf)}' target='_blank'>resp</a>"
                        pv_display = f" <div class='small'>used variant: <span class='payload'>{payload_variant_esc}</span></div>" if payload_variant else ""
                        ff_html += f"<li><b>{ftype}</b>: {evidence} {pv_display} {artifact_links}</li>"
                    ff_html += "</ul>"
                else:
                    ff_html = "<span class='small'>no individual findings</span>"

                active_html += f"<div style='margin-top:8px'><span class='small'>param: <b>{param}</b></span><div style='margin-top:4px'>payload template: <span class='payload'>{payload_template_esc}</span></div>{variants_html}{ff_html}</div>"
            active_html += "</div>"
        else:
            active_html = ""

        rows_html.append(f"<tr><td>{url}</td><td>{status}</td><td>{ctype}</td><td>{finds_html}{active_html}</td></tr>")

    html_content = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>{html.escape(title)}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>{css}</style>
</head>
<body>
<h1>{html.escape(title)}</h1>
<p class="small">Generated: {now}</p>

<div class="summary">
  <div class="card"><h2>Total pages</h2><p>{summary['total_pages']}</p></div>
  <div class="card"><h2>Total findings</h2><p>{summary['total_findings']}</p></div>
  <div class="card"><h2>By severity</h2><p>{", ".join([f"{k}: {v}" for k,v in summary.get('by_severity',{}).items()]) or 'none'}</p></div>
  <div class="card"><h2>By type</h2><p>{", ".join([f"{k}: {v}" for k,v in summary.get('by_type',{}).items()]) or 'none'}</p></div>
</div>

<h2>Findings by URL</h2>
<table>
  <thead><tr><th>URL</th><th>Status</th><th>Content-Type</th><th>Findings</th></tr></thead>
  <tbody>
    {''.join(rows_html)}
  </tbody>
</table>

</body>
</html>"""
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html_content)

