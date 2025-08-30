import argparse
import json
import os
from scanner.crawler import crawl_site
from scanner.fetcher import fetch_all
from analyzer.model import annotate_results
from analyzer.reporting import (
    generate_summary, write_html_report, write_csv_report,
    filter_by_min_severity
)
from scanner.active_injector import run_active_tests
from utils.payloads_manager import (
    sync_default_repos, load_payload_lists_from_dir, build_active_payload_map
)


def main():
    parser = argparse.ArgumentParser(description="Exploit Finder: crawl -> fetch -> heuristics -> reports -> (optional active tests)")
    parser.add_argument("-u", "--url", required=True, help="Start URL, e.g. https://example.com")
    parser.add_argument("--max-pages", type=int, default=150, help="Max pages to crawl (default 150)")
    parser.add_argument("--max-depth", type=int, default=2, help="Max depth from start URL (default 2)")
    parser.add_argument("-o", "--output", default="reports/report.json", help="Output JSON report path (annotated)")
    parser.add_argument("--max-body", type=int, default=2000, help="Max characters to store from response body")
    parser.add_argument("--export-html", help="Also export HTML report to this path (e.g. reports/report.html)")
    parser.add_argument("--export-csv", help="Also export CSV report to this path (e.g. reports/report.csv)")
    parser.add_argument("--min-severity", choices=["low", "medium", "high"], help="Only include pages with at least this severity in additional exports")
    parser.add_argument("--no-json", action="store_true", help="Do not write annotated JSON (only exports requested outputs)")

    # Active testing flags
    parser.add_argument("--confirm-active", action="store_true", help="Run active injection tests (REQUIRES explicit consent; use only on authorized targets)")
    parser.add_argument("--active-workers", type=int, default=3, help="Threadpool workers for active testing (default 3)")
    parser.add_argument("--active-delay", type=float, default=0.6, help="Delay (seconds) between active test completions to throttle (default 0.6)")

    # Payload sync flags
    parser.add_argument("--sync-payloads", action="store_true", help="Clone/update trusted payload repos into payloads/ (requires git)")
    parser.add_argument("--payloads-dir", default="payloads", help="Directory containing payload lists (default: payloads/)")

    # mutation/encoding flags
    parser.add_argument("--encodings", default="raw,url,html", help="Comma-separated encodings to use per payload (raw,url,html,double_url,base64,hex)")
    parser.add_argument("--max-variants", type=int, default=2, help="Max number of variants to test per payload template (default 2)")

    # NEW: logging artifacts
    parser.add_argument("--log-requests-dir", default="reports/requests", help="Directory to save raw request/response artifacts for active tests (default: reports/requests)")

    args = parser.parse_args()

    # Optional payload sync step (one-shot)
    if args.sync_payloads:
        print(f"[+] Syncing payload repositories into '{args.payloads_dir}' (this may take a while)...")
        try:
            sync_res = sync_default_repos(base_dir=args.payloads_dir)
            print("[+] Sync results:", sync_res)
        except Exception as e:
            print(f"[!] Payload sync failed: {e}")
            print("[!] You can still provide a local payloads dir with --payloads-dir or clone manually.")
    else:
        print("[*] Payload sync not requested. Using payloads from", args.payloads_dir)

    print(f"[+] Crawling {args.url} (max-pages={args.max_pages}, max-depth={args.max_depth})")
    urls = crawl_site(args.url, max_pages=args.max_pages, max_depth=args.max_depth, respect_domain=True)
    print(f"[+] Found {len(urls)} URLs, collecting responses...")

    results = fetch_all(urls, output=None, timeout=12, max_body=args.max_body)
    print(f"[+] Collected {len(results)} responses. Running heuristic analysis...")

    annotated = annotate_results(results)

    # Save annotated JSON unless suppressed
    if not args.no_json:
        outdir = os.path.dirname(args.output)
        if outdir and not os.path.exists(outdir):
            os.makedirs(outdir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(annotated, f, indent=2)
        print(f"[+] Annotated JSON saved to {args.output}")

    # If user requested active testing, prepare payloads (either default or loaded)
    if args.confirm_active:
        # load payload files from payloads_dir
        try:
            payloads_map = load_payload_lists_from_dir(base_dir=args.payloads_dir)
            active_payloads = build_active_payload_map(payloads_map)
            print(f"[+] Loaded payload categories: {', '.join(sorted(payloads_map.keys()))}")
            for k in ("xss_test", "redirect_test"):
                print(f"    {k}: {len(active_payloads.get(k, []))} payloads")
        except Exception as e:
            print(f"[!] Failed to load payloads from {args.payloads_dir}: {e}")
            print("[!] Falling back to built-in minimal payloads.")
            active_payloads = None

        # LIMIT: to avoid explosion, ensure we do not use too many payloads per category
        MAX_PAYLOADS_PER_CAT = 500
        if active_payloads:
            for k, v in list(active_payloads.items()):
                if isinstance(v, list) and len(v) > MAX_PAYLOADS_PER_CAT:
                    active_payloads[k] = v[:MAX_PAYLOADS_PER_CAT]
                    print(f"[!] Truncated payloads for category {k} to {MAX_PAYLOADS_PER_CAT} entries to avoid memory issues")

        # pick pages with params/forms
        to_test = []
        for r in annotated:
            if (r.get("query_params") and len(r.get("query_params")) > 0) or (r.get("form_inputs") and len(r.get("form_inputs")) > 0):
                to_test.append(r)

        if not to_test:
            print("[+] No parameterized endpoints found for active testing.")
        else:
            enc_list = [e.strip() for e in args.encodings.split(",") if e.strip()]
            print(f"[!] ACTIVE TESTING ENABLED: You indicated consent with --confirm-active. Make sure you are authorized to test {args.url}.")
            print(f"[+] Running active injection tests on {len(to_test)} pages with {args.active_workers} workers, delay {args.active_delay}s")
            print(f"[+] Encodings: {enc_list}   max_variants per payload: {args.max_variants}")
            try:
                active_results = run_active_tests(
                    to_test,
                    payloads=active_payloads,
                    max_workers=args.active_workers,
                    delay_between=args.active_delay,
                    require_consent=True,
                    verify=True,
                    timeout=12,
                    encodings=enc_list,
                    max_variants=args.max_variants,
                    log_dir=args.log_requests_dir
                )
            except Exception as e:
                print(f"[!] Active testing failed: {e}")
                active_results = []

            # attach findings back to annotated items by url
            by_url = {r["url"]: r for r in annotated}
            for ar in active_results:
                url = ar.get("url")
                if not url:
                    continue
                parent = by_url.get(url)
                if parent is None:
                    continue
                parent.setdefault("active_findings", []).append(ar)

            # rewrite the annotated output file to include active findings
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(annotated, f, indent=2)
            print(f"[+] Active testing complete. Results merged into {args.output}")
    else:
        print("[+] Active testing not requested (use --confirm-active to enable).")

    # Apply min severity filtering for exports (if requested)
    export_set = annotated
    if args.min_severity:
        export_set = filter_by_min_severity(annotated, args.min_severity)
        print(f"[+] Filtering results to items with at least severity '{args.min_severity}': {len(export_set)} pages remain")

    # CSV export
    if args.export_csv:
        write_csv_report(export_set, args.export_csv)
        print(f"[+] CSV report written to {args.export_csv}")

    # HTML export
    if args.export_html:
        write_html_report(export_set, args.export_html, title=f"Exploit Finder Report for {args.url}")
        print(f"[+] HTML report written to {args.export_html}")

    # Print short console summary
    summary = generate_summary(annotated)
    print("[+] Heuristic summary (counts across all pages):")
    if not summary["by_type"]:
        print("    None found (no heuristic matches)")
    else:
        for k, v in sorted(summary["by_type"].items(), key=lambda x: -x[1]):
            print(f"    {k}: {v}")
    print("[+] Done.")


if __name__ == "__main__":
    main()
