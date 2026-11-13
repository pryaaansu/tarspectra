"""Tarspectra's local web dashboard and JSON API — v2.5

Provides:
  - Dual-View Architecture:
      1. Site Map & Subdomain Hierarchy Explorer
      2. High True-Positive Vulnerability & Security Report
  - Integrated Open-Source Tools:
      - Nuclei (ProjectDiscovery CVE & Exploit Engine)
      - Subfinder (Passive Subdomain Discovery)
      - Nikto (Tuned Server Scanner)
      - Nmap (Verified HTTP NSE Scripts)
      - sqlmap (SQL Injection Verification)
  - Real-time SSE Live Log Streaming
  - Consolidated Host-Level vs Page-Level Findings (Zero False Positive Spam)
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import threading
import uuid
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

from analyzer.model import annotate_results
from analyzer.reporting import (
    consolidate_findings,
    generate_summary,
    generate_sitemap_ascii_tree,
)
from scanner.crawler import crawl_site_with_sitemap
from scanner.fetcher import fetch_details
from scanner.safe_reflection import run_safe_reflection_checks
from scanner.sitemap import (
    build_hierarchical_sitemap,
    get_registered_domain,
    run_subfinder_passive,
)
from scanner.tools_runner import (
    get_installed_tools,
    run_nikto,
    run_nmap,
    run_nuclei,
    run_shodan,
    run_sqlmap,
    run_subfinder,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
STATIC_ROOT = Path(__file__).resolve().parent / "static"
REPORT_ROOT = PROJECT_ROOT / "reports" / "web"
MAX_HISTORY = 25
MAX_BODY = 10_000


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def clamp_int(value, default, minimum, maximum):
    try:
        return max(minimum, min(int(value), maximum))
    except (TypeError, ValueError):
        return default


def validate_target(value):
    target = str(value or "").strip()
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Enter a complete http:// or https:// URL.")
    if parsed.username or parsed.password:
        raise ValueError("URLs with embedded credentials are not accepted.")
    return target


class ScanStore:
    def __init__(self):
        self._items = {}
        self._lock = threading.Lock()
        self._log_queues: dict[str, list[str]] = {}
        self._load_existing_reports()

    def _load_existing_reports(self):
        if not REPORT_ROOT.is_dir():
            return
        for file in sorted(REPORT_ROOT.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            if file.name.endswith("_sitemap.json"):
                continue
            scan_id = file.stem
            try:
                rep = json.loads(file.read_text(encoding="utf-8"))
                sitemap_file = REPORT_ROOT / f"{scan_id}_sitemap.json"
                sitemap_data = json.loads(sitemap_file.read_text(encoding="utf-8")) if sitemap_file.is_file() else None
                findings = rep.get("consolidated_findings", [])
                total_eps = sitemap_data.get("total_endpoints", 0) if sitemap_data else len(findings)
                total_subs = sitemap_data.get("total_subdomains", 1) if sitemap_data else 1
                self._items[scan_id] = {
                    "id": scan_id,
                    "target": rep.get("target", "Target"),
                    "settings": rep.get("settings", {}),
                    "status": "completed",
                    "stage": "Complete",
                    "progress": {
                        "pages_found": total_eps,
                        "pages_scanned": total_eps,
                        "total_findings": len(findings),
                        "subdomains_found": total_subs,
                    },
                    "started_at": rep.get("generated_at", now_iso()),
                    "finished_at": rep.get("generated_at", now_iso()),
                    "summary": rep.get("summary") or {"by_severity": {}},
                    "results": [],
                    "consolidated_findings": findings,
                    "sitemap": sitemap_data,
                    "tool_results": rep.get("tool_results", {}),
                    "error": None,
                    "report_ready": True,
                }
            except Exception:
                continue

    def create(self, target, settings):
        scan_id = uuid.uuid4().hex[:12]
        scan = {
            "id": scan_id,
            "target": target,
            "settings": settings,
            "status": "queued",
            "stage": "Queued",
            "progress": {"pages_found": 0, "pages_scanned": 0, "total_findings": 0, "subdomains_found": 0},
            "started_at": now_iso(),
            "finished_at": None,
            "summary": None,
            "results": [],
            "consolidated_findings": [],
            "sitemap": None,
            "tool_results": {},
            "error": None,
            "report_ready": False,
        }
        with self._lock:
            self._items[scan_id] = scan
            self._log_queues[scan_id] = []
            self._trim_history()
        return scan_id

    def _trim_history(self):
        if len(self._items) <= MAX_HISTORY:
            return
        completed = sorted(
            (item for item in self._items.values() if item["status"] in {"completed", "failed"}),
            key=lambda item: item["started_at"],
        )
        for item in completed[: max(0, len(self._items) - MAX_HISTORY)]:
            self._items.pop(item["id"], None)
            self._log_queues.pop(item["id"], None)

    def update(self, scan_id, **changes):
        with self._lock:
            item = self._items.get(scan_id)
            if not item:
                return
            for key, value in changes.items():
                if key == "progress" and isinstance(value, dict):
                    item["progress"].update(value)
                else:
                    item[key] = value

    def append_log(self, scan_id: str, line: str):
        with self._lock:
            q = self._log_queues.get(scan_id)
            if q is not None:
                q.append(line)

    def drain_log(self, scan_id: str) -> list[str]:
        with self._lock:
            q = self._log_queues.get(scan_id, [])
            lines = list(q)
            if scan_id in self._log_queues:
                self._log_queues[scan_id] = []
        return lines

    def get(self, scan_id):
        with self._lock:
            item = self._items.get(scan_id)
            return json.loads(json.dumps(item)) if item else None

    def list(self):
        with self._lock:
            values = sorted(self._items.values(), key=lambda item: item["started_at"], reverse=True)
            return [self._compact(item) for item in values]

    @staticmethod
    def _compact(item):
        return {
            key: value
            for key, value in item.items()
            if key not in {"results"}
        }


STORE = ScanStore()


def write_reports(scan):
    REPORT_ROOT.mkdir(parents=True, exist_ok=True)
    scan_id = scan["id"]

    # 1. Main Vulnerability Report
    report = {
        "generated_at": now_iso(),
        "scanner": "Tarspectra 2.5",
        "notice": "Results contain verified true-positive findings and security audit signals.",
        "target": scan.get("target"),
        "summary": scan.get("summary"),
        "consolidated_findings": scan.get("consolidated_findings", []),
        "tool_results": scan.get("tool_results", {}),
        "settings": scan.get("settings", {}),
    }
    path = REPORT_ROOT / f"{scan_id}.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    # 2. Site Map JSON Report
    if scan.get("sitemap"):
        sitemap_path = REPORT_ROOT / f"{scan_id}_sitemap.json"
        sitemap_path.write_text(json.dumps(scan["sitemap"], indent=2), encoding="utf-8")


def execute_scan(scan_id):
    scan = STORE.get(scan_id)
    if not scan:
        return
    target = scan["target"]
    settings = scan["settings"]
    root_domain = get_registered_domain(target)

    def log(line: str):
        STORE.append_log(scan_id, line)

    try:
        # ── Phase 1: Subdomain Discovery ────────────────────────────────────
        passive_subdomains = []
        if settings.get("run_subfinder", True):
            STORE.update(scan_id, status="running", stage="Enumerating subdomains")
            log(f"[subfinder] Looking up passive subdomains for {root_domain}…")
            passive_subdomains = run_subfinder_passive(root_domain, timeout=30, log_cb=log)
            STORE.update(scan_id, progress={"subdomains_found": len(passive_subdomains)})

        # ── Phase 2: Web Crawl & Hierarchy Mapping ──────────────────────────
        STORE.update(scan_id, stage="Crawling target & mapping endpoints")
        log(f"[crawl] Crawling {target} (max_pages={settings['max_pages']}, depth={settings['max_depth']})")
        crawl_urls, all_discovered_urls, crawler_subdomains = crawl_site_with_sitemap(
            target,
            max_pages=settings["max_pages"],
            max_depth=settings["max_depth"],
            respect_domain=True,
        )
        combined_subdomains = sorted(set(passive_subdomains) | crawler_subdomains)
        STORE.update(
            scan_id,
            progress={"pages_found": len(crawl_urls), "subdomains_found": len(combined_subdomains)},
            stage="Collecting page metadata & forms"
        )
        log(f"[crawl] Discovered {len(combined_subdomains)} subdomains and {len(crawl_urls)} crawlable endpoints")

        # ── Phase 3: Fetch Details & Passive Audit ──────────────────────────
        collected = []
        for number, url in enumerate(crawl_urls, start=1):
            collected.append(fetch_details(url, timeout=12, max_body=MAX_BODY))
            STORE.update(scan_id, progress={"pages_scanned": number})

        # Build Hierarchical Site Map
        sitemap_data = build_hierarchical_sitemap(
            target,
            collected,
            all_discovered_urls,
            combined_subdomains
        )

        STORE.update(scan_id, stage="Analyzing security controls & disclosures")
        check_headers = settings.get("check_headers", True)
        if check_headers:
            log("[passive] Auditing HTML documents for security headers, cookies, forms, disclosures…")
        else:
            log("[passive] Security header audit disabled; auditing cookies, forms, disclosures, leaks…")
        annotated_results = annotate_results(collected, check_headers=check_headers)

        # ── Phase 4: Safe Reflection Checks ─────────────────────────────────
        if settings.get("safe_reflection"):
            STORE.update(scan_id, stage="Testing parameter reflections with harmless marker")
            log("[reflection] Injecting harmless unique text markers to verify reflection…")
            reflection_findings = run_safe_reflection_checks(annotated_results, max_checks=40, timeout=8)
            for r in annotated_results:
                r["reflection_findings"] = reflection_findings.get(r["url"], [])
        else:
            for r in annotated_results:
                r["reflection_findings"] = []

        # ── Phase 5: Open-Source Security Tools ─────────────────────────────
        tool_results_map: dict = {}
        all_tool_findings = []

        # 1. ProjectDiscovery Nuclei (High True Positive)
        if settings.get("run_nuclei", True):
            STORE.update(scan_id, stage="Running Nuclei vulnerability & CVE scanner…")
            log("[nuclei] Executing ProjectDiscovery Nuclei (CVEs, exposures, misconfigs)…")
            nuclei_res = run_nuclei(target, timeout=settings.get("tool_timeout", 180), log_cb=log)
            tool_results_map["nuclei"] = nuclei_res
            nf = nuclei_res.get("findings", [])
            all_tool_findings.extend(nf)
            log(f"[nuclei] Nuclei finished: {len(nf)} verified findings")

        # 2. Nikto Web Server Scanner (Tuned)
        if settings.get("run_nikto", False):
            STORE.update(scan_id, stage="Running Nikto web server scanner…")
            log("[nikto] Starting Nikto server scan…")
            nikto_res = run_nikto(target, timeout=settings.get("tool_timeout", 180), log_cb=log)
            tool_results_map["nikto"] = nikto_res
            nkf = nikto_res.get("findings", [])
            all_tool_findings.extend(nkf)
            log(f"[nikto] Nikto finished: {len(nkf)} server findings")

        # 3. Nmap HTTP NSE Scripts (Strict Positive)
        if settings.get("run_nmap", False):
            STORE.update(scan_id, stage="Running Nmap HTTP vulnerability scripts…")
            log("[nmap] Running Nmap HTTP vulnerability scripts…")
            nmap_res = run_nmap(target, timeout=settings.get("tool_timeout", 120), log_cb=log)
            tool_results_map["nmap"] = nmap_res
            nmf = nmap_res.get("findings", [])
            all_tool_findings.extend(nmf)
            log(f"[nmap] Nmap finished: {len(nmf)} confirmed findings")

        # 4. sqlmap (Safe Detection Only)
        if settings.get("run_sqlmap", False):
            STORE.update(scan_id, stage="Running sqlmap SQL injection detection…")
            log("[sqlmap] Running safe detection on target parameters (risk=1)…")
            sqlmap_res = run_sqlmap(target, timeout=settings.get("tool_timeout", 120), log_cb=log)
            tool_results_map["sqlmap"] = sqlmap_res
            sqf = sqlmap_res.get("findings", [])
            all_tool_findings.extend(sqf)
            log(f"[sqlmap] sqlmap finished: {len(sqf)} confirmed injections")

        # 5. Shodan Attack Surface & CVE Intelligence
        if settings.get("run_shodan", True):
            STORE.update(scan_id, stage="Querying Shodan intelligence & attack surface…")
            log("[shodan] Querying Shodan for public IP intelligence, open ports, and CVEs…")
            shodan_res = run_shodan(
                target,
                api_key=settings.get("shodan_api_key"),
                timeout=settings.get("tool_timeout", 25),
                log_cb=log,
            )
            tool_results_map["shodan"] = shodan_res
            shf = shodan_res.get("findings", [])
            all_tool_findings.extend(shf)
            log(f"[shodan] Shodan finished: {len(shf)} intelligence signals & vulnerabilities")

        # ── Phase 6: Consolidate & Summarize (Zero False Positive Spam) ──────
        consolidated = consolidate_findings(annotated_results, all_tool_findings)
        summary = generate_summary(annotated_results, all_tool_findings)

        log(f"[done] Assessment complete! {len(consolidated)} true-positive signals | {sitemap_data['total_subdomains']} subdomains | {sitemap_data['total_endpoints']} endpoints")

        STORE.update(
            scan_id,
            status="completed",
            stage="Complete",
            finished_at=now_iso(),
            summary=summary,
            consolidated_findings=consolidated,
            sitemap=sitemap_data,
            tool_results=tool_results_map,
            results=annotated_results,
            progress={
                "total_findings": len(consolidated),
                "pages_scanned": len(annotated_results),
                "subdomains_found": sitemap_data["total_subdomains"],
            },
            report_ready=True,
        )
        write_reports(STORE.get(scan_id))

    except Exception as exc:
        STORE.update(
            scan_id,
            status="failed",
            stage="Failed",
            finished_at=now_iso(),
            error=f"{type(exc).__name__}: {exc}",
        )


class DashboardHandler(SimpleHTTPRequestHandler):
    server_version = "Tarspectra/2.5"

    def log_message(self, format, *args):
        return

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        super().end_headers()

    def send_json(self, status, body):
        encoded = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def read_json(self):
        size = clamp_int(self.headers.get("Content-Length"), 0, 0, 32_000)
        if size <= 0:
            raise ValueError("Request body must contain JSON.")
        raw = self.rfile.read(size)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Request body must be valid JSON.") from exc
        if not isinstance(payload, dict):
            raise ValueError("Request body must be a JSON object.")
        return payload

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/api/health":
            return self.send_json(HTTPStatus.OK, {"status": "ok", "version": "2.5"})

        if path == "/api/tools":
            return self.send_json(HTTPStatus.OK, {"tools": get_installed_tools()})

        if path == "/api/scans":
            return self.send_json(HTTPStatus.OK, {"scans": STORE.list()})

        # Download Vulnerability Report
        if path.startswith("/api/scans/") and path.endswith("/download"):
            scan_id = path.split("/")[3]
            report_path = REPORT_ROOT / f"{scan_id}.json"
            if not report_path.is_file():
                return self.send_json(HTTPStatus.NOT_FOUND, {"error": "Report not ready yet."})
            data = report_path.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="tarspectra-report-{scan_id}.json"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            return self.wfile.write(data)

        # Download Site Map JSON
        if path.startswith("/api/scans/") and path.endswith("/download-sitemap"):
            scan_id = path.split("/")[3]
            sitemap_path = REPORT_ROOT / f"{scan_id}_sitemap.json"
            if not sitemap_path.is_file():
                return self.send_json(HTTPStatus.NOT_FOUND, {"error": "Site map not available."})
            data = sitemap_path.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="tarspectra-sitemap-{scan_id}.json"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            return self.wfile.write(data)

        # Site map JSON API
        if path.startswith("/api/scans/") and path.endswith("/sitemap"):
            scan_id = path.split("/")[3]
            scan = STORE.get(scan_id)
            if scan and scan.get("sitemap"):
                return self.send_json(HTTPStatus.OK, scan["sitemap"])
            return self.send_json(HTTPStatus.NOT_FOUND, {"error": "Site map not found."})

        # SSE Log Stream
        if path.startswith("/api/scans/") and path.endswith("/stream"):
            scan_id = path.split("/")[3]
            return self._handle_stream(scan_id)

        # Get Scan Details
        if path.startswith("/api/scans/"):
            scan_id = path.rsplit("/", 1)[-1]
            scan = STORE.get(scan_id)
            return self.send_json(HTTPStatus.OK, scan) if scan else self.send_json(
                HTTPStatus.NOT_FOUND, {"error": "Scan not found."}
            )

        return self.serve_static(path)

    def _handle_stream(self, scan_id: str):
        scan = STORE.get(scan_id)
        if not scan:
            return self.send_json(HTTPStatus.NOT_FOUND, {"error": "Scan not found."})

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        SimpleHTTPRequestHandler.end_headers(self)

        import time as _time
        try:
            while True:
                lines = STORE.drain_log(scan_id)
                for line in lines:
                    data = json.dumps({"log": line})
                    self.wfile.write(f"data: {data}\n\n".encode("utf-8"))
                self.wfile.flush()

                current = STORE.get(scan_id)
                if current and current.get("status") in ("completed", "failed"):
                    self.wfile.write(
                        f"event: done\ndata: {json.dumps({'status': current['status']})}\n\n".encode("utf-8")
                    )
                    self.wfile.flush()
                    break
                _time.sleep(0.35)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):
        path = urlparse(self.path).path
        if path != "/api/scans":
            return self.send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found."})
        try:
            payload = self.read_json()
            if payload.get("authorization") is not True:
                raise ValueError("Confirm authorization to test this target before starting a scan.")
            target = validate_target(payload.get("target"))
            settings = {
                "max_pages": clamp_int(payload.get("max_pages"), 20, 1, 80),
                "max_depth": clamp_int(payload.get("max_depth"), 2, 0, 4),
                "safe_reflection": payload.get("safe_reflection") is True,
                "check_headers": payload.get("check_headers") is not False,
                "run_subfinder": payload.get("run_subfinder") is not False,
                "run_nuclei": payload.get("run_nuclei") is not False,
                "run_nikto": payload.get("run_nikto") is True,
                "run_nmap": payload.get("run_nmap") is True,
                "run_sqlmap": payload.get("run_sqlmap") is True,
                "run_shodan": payload.get("run_shodan") is not False,
                "shodan_api_key": str(payload.get("shodan_api_key") or "").strip(),
                "tool_timeout": clamp_int(payload.get("tool_timeout"), 180, 30, 600),
            }
        except ValueError as exc:
            return self.send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})

        scan_id = STORE.create(target, settings)
        thread = threading.Thread(target=execute_scan, args=(scan_id,), daemon=True)
        thread.start()
        return self.send_json(HTTPStatus.ACCEPTED, STORE.get(scan_id))

    def serve_static(self, path):
        requested = "index.html" if path in {"", "/"} else unquote(path).lstrip("/")
        candidate = (STATIC_ROOT / requested).resolve()
        try:
            candidate.relative_to(STATIC_ROOT.resolve())
        except ValueError:
            return self.send_json(HTTPStatus.FORBIDDEN, {"error": "Invalid path."})
        if not candidate.is_file():
            return self.send_json(HTTPStatus.NOT_FOUND, {"error": "File not found."})
        content = candidate.read_bytes()
        content_type = mimetypes.guess_type(str(candidate))[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self.send_header(
            "Content-Type",
            content_type + ("; charset=utf-8" if content_type.startswith("text/") else ""),
        )
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


def main():
    parser = argparse.ArgumentParser(description="Tarspectra v2.5 Web Security Workbench")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", default=8000, type=int, help="Port (default: 8000)")
    args = parser.parse_args()

    tools = get_installed_tools()
    active_tools = [k for k, v in tools.items() if v]

    server = ThreadingHTTPServer((args.host, args.port), DashboardHandler)
    print(f"============================================================")
    print(f"  TARSPECTRA v2.5 — Web Security Scanner & Site Mapper")
    print(f"  http://{args.host}:{args.port}")
    print(f"  Active Engines: {', '.join(active_tools)}")
    print(f"============================================================")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nTarspectra stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
