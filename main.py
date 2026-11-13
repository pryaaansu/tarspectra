"""Tarspectra v2.5 — CLI Web Security Scanner & Site Mapper.

Usage:
    python main.py -u https://your-authorized-site.example [options]

Features:
  - Separate Output 1: Hierarchical Site Map of all subdomains & mapped endpoints
  - Separate Output 2: High True-Positive Vulnerability & Security Audit Report
  - Open-Source Tools: Nuclei, Subfinder, Nikto, Nmap, sqlmap
"""

import argparse
import json
import os
import sys

from scanner.crawler import crawl_site_with_sitemap
from scanner.fetcher import fetch_details
from scanner.sitemap import (
    build_hierarchical_sitemap,
    get_registered_domain,
    run_subfinder_passive,
)
from analyzer.model import annotate_results
from analyzer.reporting import (
    consolidate_findings,
    generate_summary,
    generate_sitemap_ascii_tree,
    write_html_report,
    write_csv_report,
    filter_by_min_severity,
)
from scanner.safe_reflection import run_safe_reflection_checks
from scanner.tools_runner import (
    get_installed_tools,
    run_nuclei,
    run_subfinder,
    run_nikto,
    run_nmap,
    run_sqlmap,
)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.panel import Panel
    from rich.tree import Tree
    from rich import box
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

console = Console() if HAS_RICH else None


def cprint(msg, style=""):
    if HAS_RICH:
        console.print(msg, style=style)
    else:
        print(msg)


def print_sitemap_tree(sitemap_data: dict):
    """Render a dedicated rich hierarchical tree of subdomains and endpoints."""
    root_domain = sitemap_data.get("root_domain", "Target")
    total_subs = sitemap_data.get("total_subdomains", 0)
    total_eps = sitemap_data.get("total_endpoints", 0)

    if not HAS_RICH:
        print("\n" + "=" * 60)
        print(generate_sitemap_ascii_tree(sitemap_data))
        print("=" * 60)
        return

    tree = Tree(
        f"[bold bright_green]🌐 {root_domain}[/bold bright_green] "
        f"[dim]({total_subs} subdomains, {total_eps} mapped endpoints)[/dim]",
        guide_style="bright_green dim",
    )

    subdomains = sitemap_data.get("subdomains", {})
    for sub_host, sub_info in subdomains.items():
        status = sub_info.get("status_code", "")
        status_style = "green" if status == 200 else ("yellow" if str(status).startswith("3") else "cyan")
        status_badge = f"[{status_style}][{status}][/]" if status else "[dim][probed][/]"
        is_target = " [bold cyan](Target Host)[/]" if sub_info.get("is_target_host") else ""
        server = f" [dim]({sub_info['server']})[/]" if sub_info.get("server") else ""

        sub_node = tree.add(
            f"[bold white]🖥️  {sub_host}[/] {status_badge}{is_target}{server} "
            f"[dim]— {sub_info['total_endpoints']} endpoints[/]"
        )

        endpoints = sub_info.get("endpoints", [])
        for ep in endpoints[:15]:
            path = ep.get("path_with_query", ep.get("path", "/"))
            ep_status = ep.get("status_code", "")
            forms_badge = f" [bold red]📝 [Forms: {ep['forms_count']}][/]" if ep.get("forms_count") else ""
            params_badge = f" [yellow]?[{','.join(ep['params'][:3])}][/]" if ep.get("params") else ""
            sub_node.add(f"[bright_black]├──[/] [cyan]{path}[/] [dim]({ep_status})[/]{params_badge}{forms_badge}")

        if len(endpoints) > 15:
            sub_node.add(f"[dim]... and {len(endpoints) - 15} more endpoints[/dim]")

    console.print(Panel(
        tree,
        title="[bold green]SITE MAP & SUBDOMAIN HIERARCHY[/bold green]",
        subtitle=f"[dim]Total: {total_subs} subdomains | {total_eps} endpoints[/dim]",
        border_style="green",
    ))


def print_findings_table(consolidated_findings: list[dict]):
    """Print the consolidated true-positive findings table."""
    if not consolidated_findings:
        cprint("\n[bold green]✓ No vulnerabilities detected in scope.[/bold green]")
        return

    if not HAS_RICH:
        print("\n" + "=" * 60)
        print("  TRUE POSITIVE VULNERABILITY REPORT")
        print("=" * 60)
        for f in consolidated_findings:
            sev = f.get("severity", "low").upper()
            src = f.get("source", "check")
            title = f.get("type") or f.get("title") or "Finding"
            url = f.get("url", "")
            print(f"[{sev}] ({src}) {title} — {url}")
        return

    tbl = Table(
        title="Verified Vulnerability & Security Signals",
        box=box.ROUNDED,
        show_lines=False,
        border_style="dim",
        header_style="bold bright_white",
    )
    tbl.add_column("SEV", width=9)
    tbl.add_column("Source", width=12)
    tbl.add_column("Confidence", width=11)
    tbl.add_column("Finding", min_width=32)
    tbl.add_column("Target URL / Scope", min_width=35, overflow="fold")

    SEV_STYLE = {
        "critical": "bold red on #330000",
        "high": "bold red",
        "medium": "bold yellow",
        "low": "cyan",
        "info": "dim",
    }

    for f in consolidated_findings:
        sev = str(f.get("severity", "low")).lower()
        style = SEV_STYLE.get(sev, "white")
        src = f.get("source", "passive").upper()
        conf = f.get("confidence", "Medium")
        title = f.get("type") or f.get("title") or "Finding"
        url = f.get("url", "")

        tbl.add_row(
            Text(sev.upper(), style=style),
            Text(src, style="dim cyan"),
            Text(conf, style="bold green" if conf == "VERIFIED" else "yellow"),
            title,
            url,
        )

    console.print(tbl)


def main():
    parser = argparse.ArgumentParser(
        description="Tarspectra v2.5 — Web Vulnerability Scanner & Site Mapper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL, e.g. https://example.com")
    parser.add_argument("--max-pages", type=int, default=25, help="Max pages to crawl (default 25)")
    parser.add_argument("--max-depth", type=int, default=2, help="Max depth from start URL (default 2)")
    parser.add_argument("-o", "--output", default="reports/report.json", help="Vulnerability JSON output path")
    parser.add_argument("--sitemap-output", default="reports/sitemap.json", help="Site Map JSON output path")
    parser.add_argument("--export-html", help="HTML report export path (e.g. reports/report.html)")
    parser.add_argument("--export-csv", help="CSV report export path (e.g. reports/report.csv)")
    parser.add_argument("--min-severity", choices=["low", "medium", "high", "critical"], help="Filter exports by min severity")
    parser.add_argument("--safe-reflection", action="store_true", help="Run harmless GET parameter reflection check")
    parser.add_argument("--skip-headers", action="store_true", help="Skip passive missing security headers/hardening audit (CSP, HSTS, framing)")

    # Tool switches
    tools_grp = parser.add_argument_group("Integrated Security Tools")
    tools_grp.add_argument("--all-tools", action="store_true", help="Enable all available tools (Nuclei, Subfinder, Nikto, Nmap)")
    tools_grp.add_argument("--nuclei", action="store_true", help="Run ProjectDiscovery Nuclei CVE & vulnerability scanner")
    tools_grp.add_argument("--subfinder", action="store_true", help="Run passive subdomain enumeration via Subfinder")
    tools_grp.add_argument("--nikto", action="store_true", help="Run tuned Nikto web server scanner")
    tools_grp.add_argument("--nmap", action="store_true", help="Run Nmap HTTP vulnerability NSE scripts")
    tools_grp.add_argument("--sqlmap", action="store_true", help="Run sqlmap SQL injection detection (read-only, confirmed flaws only)")
    tools_grp.add_argument("--tool-timeout", type=int, default=180, help="Per-tool timeout in seconds (default 180)")

    args = parser.parse_args()

    # If --all-tools, enable everything available
    if args.all_tools:
        args.nuclei = True
        args.subfinder = True
        args.nikto = True
        args.nmap = True
        args.sqlmap = True

    installed = get_installed_tools()
    root_domain = get_registered_domain(args.url)

    # ── Banner ──────────────────────────────────────────────────────────────
    if HAS_RICH:
        console.print(Panel.fit(
            f"[bold bright_green]TARSPECTRA v2.5[/bold bright_green] [dim]— Web Security Scanner & Site Mapper[/dim]\n"
            f"[dim]Target: {args.url} | Apex: {root_domain}[/dim]",
            border_style="bright_green",
        ))
    else:
        print("=" * 60)
        print(f"  TARSPECTRA v2.5 — Target: {args.url}")
        print("=" * 60)

    # ── Phase 1: Subdomain Discovery ────────────────────────────────────────
    passive_subdomains = []
    if args.subfinder and installed.get("subfinder"):
        cprint("\n[bold cyan]Phase 1 — Subdomain Enumeration (Subfinder)[/bold cyan]")
        passive_subdomains = run_subfinder_passive(root_domain, timeout=30, log_cb=lambda s: cprint(f"  [dim]{s}[/dim]"))

    # ── Phase 2: Web Crawling ───────────────────────────────────────────────
    cprint("\n[bold cyan]Phase 2 — Crawling & Hierarchy Discovery[/bold cyan]")
    crawl_urls, all_discovered_urls, crawler_subdomains = crawl_site_with_sitemap(
        args.url,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        respect_domain=True,
    )
    combined_subs = sorted(set(passive_subdomains) | crawler_subdomains)
    cprint(f"  → Discovered {len(combined_subs)} subdomains & {len(crawl_urls)} crawl endpoints", "green")

    # ── Phase 3: Fetching Details ───────────────────────────────────────────
    cprint("\n[bold cyan]Phase 3 — Collecting Page Metadata[/bold cyan]")
    collected = []
    if HAS_RICH:
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TaskProgressColumn(), transient=True) as prog:
            task = prog.add_task("Inspecting pages…", total=len(crawl_urls))
            for u in crawl_urls:
                collected.append(fetch_details(u, timeout=12, max_body=10000))
                prog.advance(task)
    else:
        for u in crawl_urls:
            collected.append(fetch_details(u, timeout=12, max_body=10000))

    # Build Site Map
    sitemap_data = build_hierarchical_sitemap(args.url, collected, all_discovered_urls, combined_subs)

    # Passive security audit
    if args.skip_headers:
        cprint("\n[bold cyan]Phase 4 — Passive Security Audit (Headers Skipped)[/bold cyan]")
    else:
        cprint("\n[bold cyan]Phase 4 — Passive Security Control Audit[/bold cyan]")
    annotated = annotate_results(collected, check_headers=not args.skip_headers)

    # Reflection checks
    if args.safe_reflection:
        cprint("\n[bold cyan]Phase 4b — Safe Reflection Testing[/bold cyan]")
        refl = run_safe_reflection_checks(annotated, max_checks=30, timeout=8)
        for r in annotated:
            r["reflection_findings"] = refl.get(r["url"], [])
    else:
        for r in annotated:
            r["reflection_findings"] = []

    # ── Phase 5: Open-Source Security Tools ─────────────────────────────────
    all_tool_findings = []

    def _tool_log(line):
        cprint(f"  [dim]{line}[/dim]")

    if args.nuclei and installed.get("nuclei"):
        cprint("\n[bold cyan]Phase 5a — ProjectDiscovery Nuclei (CVE & Misconfig Scan)[/bold cyan]")
        n_res = run_nuclei(args.url, timeout=args.tool_timeout, log_cb=_tool_log)
        all_tool_findings.extend(n_res.get("findings", []))

    if args.nikto and installed.get("nikto"):
        cprint("\n[bold cyan]Phase 5b — Nikto Web Server Scanner[/bold cyan]")
        nk_res = run_nikto(args.url, timeout=args.tool_timeout, log_cb=_tool_log)
        all_tool_findings.extend(nk_res.get("findings", []))

    if args.nmap and installed.get("nmap"):
        cprint("\n[bold cyan]Phase 5c — Nmap HTTP Vulnerability Scripts[/bold cyan]")
        nm_res = run_nmap(args.url, timeout=args.tool_timeout, log_cb=_tool_log)
        all_tool_findings.extend(nm_res.get("findings", []))

    if args.sqlmap and installed.get("sqlmap"):
        cprint("\n[bold cyan]Phase 5d — sqlmap SQL Injection Detection[/bold cyan]")
        sq_res = run_sqlmap(args.url, timeout=args.tool_timeout, log_cb=_tool_log)
        all_tool_findings.extend(sq_res.get("findings", []))

    # ── Phase 6: Consolidation & Output Generation ──────────────────────────
    consolidated = consolidate_findings(annotated, all_tool_findings)
    summary = generate_summary(annotated, all_tool_findings)

    # Save Site Map JSON
    os.makedirs(os.path.dirname(args.sitemap_output) or ".", exist_ok=True)
    with open(args.sitemap_output, "w", encoding="utf-8") as f:
        json.dump(sitemap_data, f, indent=2)

    # Save Vulnerability Report JSON
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    report_data = {
        "target": args.url,
        "apex_domain": root_domain,
        "summary": summary,
        "consolidated_findings": consolidated,
        "pages_analyzed": len(annotated),
    }
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    # Export CSV & HTML if requested
    if args.export_csv:
        write_csv_report(annotated, args.export_csv, tool_findings=all_tool_findings)
        cprint(f"  → CSV saved to {args.export_csv}", "green")

    if args.export_html:
        write_html_report(annotated, args.export_html, title=f"Tarspectra Audit — {args.url}",
                          tool_findings=all_tool_findings, sitemap_data=sitemap_data)
        cprint(f"  → HTML saved to {args.export_html}", "green")

    # ══════════════════════════════════════════════════════════════════════════
    # SEPARATE OUTPUT 1: SITE MAP & SUBDOMAINS HIERARCHY
    # ══════════════════════════════════════════════════════════════════════════
    cprint("\n")
    print_sitemap_tree(sitemap_data)
    cprint(f"  💾 Site Map JSON saved: [cyan]{args.sitemap_output}[/cyan]")

    # ══════════════════════════════════════════════════════════════════════════
    # SEPARATE OUTPUT 2: TRUE-POSITIVE VULNERABILITY REPORT
    # ══════════════════════════════════════════════════════════════════════════
    cprint("\n")
    print_findings_table(consolidated)
    cprint(f"  💾 Vulnerability Report saved: [cyan]{args.output}[/cyan]")

    # Summary bar
    sev = summary.get("by_severity", {})
    cprint(
        f"\n[bold]Summary:[/bold] "
        f"[bold red]{sev.get('high', 0)} High[/bold red] │ "
        f"[bold yellow]{sev.get('medium', 0)} Medium[/bold yellow] │ "
        f"[cyan]{sev.get('low', 0)} Low[/cyan] │ "
        f"[bright_green]{sitemap_data['total_subdomains']} Subdomains[/bright_green] │ "
        f"[dim]{sitemap_data['total_endpoints']} Endpoints[/dim]"
    )
    cprint("\n[bold bright_green]✓ Assessment Completed Successfully.[/bold bright_green]")


if __name__ == "__main__":
    main()
