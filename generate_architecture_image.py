"""
generate_architecture_image.py — Generates a comprehensive, publication-grade,
ultra-high-resolution system architecture diagram for TARSPECTRA v2.5.
"""

import os
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

def build_architecture_diagram():
    # Ultra-high-resolution figure: 26 x 15 inches @ 300 DPI = 7800 x 4500 pixels
    fig = plt.figure(figsize=(26, 15), facecolor='#050913')
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_facecolor('#050913')
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis('off')

    # Font configurations
    TITLE_FONT = {'family': 'sans-serif', 'weight': 'bold', 'color': '#ffffff'}
    HEADER_FONT = {'family': 'sans-serif', 'weight': 'bold', 'color': '#00ff88'}
    BODY_FONT = {'family': 'monospace', 'weight': 'normal', 'color': '#cbd5e1'}
    ACCENT_FONT = {'family': 'sans-serif', 'weight': 'bold'}

    # ─────────────────────────────────────────────────────────────────────────
    # Helper functions for drawing styled nodes & connectors
    # ─────────────────────────────────────────────────────────────────────────
    def draw_card(x, y, w, h, bg_color='#0b1326', border_color='#00ff88', lw=1.5, radius=0.012, alpha=0.95):
        rect = FancyBboxPatch(
            (x, y), w, h,
            boxstyle=f"round,pad={radius}",
            facecolor=bg_color,
            edgecolor=border_color,
            linewidth=lw,
            alpha=alpha,
            transform=ax.transAxes,
            zorder=2
        )
        ax.add_patch(rect)
        return rect

    def draw_header_badge(x, y, w, text, color='#00ff88', bg='#002b18'):
        badge = FancyBboxPatch(
            (x, y), w, 0.024,
            boxstyle="round,pad=0.004",
            facecolor=bg,
            edgecolor=color,
            linewidth=1.0,
            transform=ax.transAxes,
            zorder=3
        )
        ax.add_patch(badge)
        ax.text(x + w / 2, y + 0.012, text, ha='center', va='center',
                fontsize=9.5, fontweight='bold', color=color, fontfamily='monospace', zorder=4)

    def draw_arrow(x1, y1, x2, y2, color='#00d4ff', style='->', lw=2.0, rad=0.0):
        connectionstyle = f"arc3,rad={rad}" if rad != 0 else "arc3,rad=0"
        arrow = FancyArrowPatch(
            (x1, y1), (x2, y2),
            arrowstyle=style,
            color=color,
            linewidth=lw,
            mutation_scale=16,
            connectionstyle=connectionstyle,
            transform=ax.transAxes,
            zorder=5
        )
        ax.add_patch(arrow)

    # ─────────────────────────────────────────────────────────────────────────
    # 1. TOP BANNER: Project Brand & System Header
    # ─────────────────────────────────────────────────────────────────────────
    banner_bg = FancyBboxPatch(
        (0.015, 0.925), 0.97, 0.062,
        boxstyle="round,pad=0.008",
        facecolor='#0a1428',
        edgecolor='#00ff88',
        linewidth=2.0,
        transform=ax.transAxes,
        zorder=2
    )
    ax.add_patch(banner_bg)

    ax.text(0.03, 0.965, "TARSPECTRA v2.5", fontsize=22, fontweight='heavy', color='#00ff88', fontfamily='monospace', zorder=4)
    ax.text(0.19, 0.966, "— COMPREHENSIVE SYSTEM ARCHITECTURE & DATA FLOW", fontsize=16, fontweight='bold', color='#ffffff', fontfamily='sans-serif', zorder=4)
    ax.text(0.03, 0.938, "AI-Driven Attack Surface Reconnaissance • Resilient Web Crawler • Multi-Engine Active Auditing • False-Positive Reduction • Interactive Flowchart",
            fontsize=10.5, color='#94a3b8', fontfamily='monospace', zorder=4)

    # System Status / Tech Badges (top right)
    ax.text(0.77, 0.960, "SANDBOX: 127.0.0.1:8000", fontsize=9.5, fontweight='bold', color='#38bdf8', fontfamily='monospace', zorder=4)
    ax.text(0.77, 0.940, "ENGINES: 6 ACTIVE PLUGINS", fontsize=9.5, fontweight='bold', color='#a855f7', fontfamily='monospace', zorder=4)
    ax.text(0.91, 0.950, "STATUS: ONLINE ●", fontsize=10.5, fontweight='bold', color='#00ff88', fontfamily='monospace', zorder=4)

    # ─────────────────────────────────────────────────────────────────────────
    # 2. COLUMN 1: CLIENT & USER INTERACTION LAYER
    # ─────────────────────────────────────────────────────────────────────────
    draw_card(0.015, 0.08, 0.165, 0.825, bg_color='#06101e', border_color='#38bdf8', lw=1.8)
    draw_header_badge(0.025, 0.88, 0.145, "1. CLIENT INTERFACES", color='#38bdf8', bg='#082038')

    # 2A: Web Dashboard Card
    draw_card(0.023, 0.50, 0.149, 0.365, bg_color='#0a162d', border_color='#00d4ff', lw=1.2)
    ax.text(0.033, 0.840, "Web UI Dashboard", fontsize=13, fontweight='bold', color='#00d4ff', zorder=4)
    ax.text(0.033, 0.822, "webapp/static/ (HTML5, CSS3, ES6)", fontsize=8.5, color='#64748b', fontfamily='monospace', zorder=4)

    web_items = [
        ("• Matrix Rain Canvas", "#00ff88"),
        ("  28fps Katakana trail background", "#94a3b8"),
        ("• Target & Scope Configuration", "#f8fafc"),
        ("  Depth (1-4), Pages (15-80), Timeout", "#94a3b8"),
        ("• Security Engine Selector", "#f8fafc"),
        ("  Toggles for 6 engines + Shodan key", "#94a3b8"),
        ("• Real-Time Monitor & Metrics", "#38bdf8"),
        ("  Progress bar, endpoint/sub counters", "#94a3b8"),
        ("• SSE Terminal Log Drawer", "#00ff88"),
        ("  Live log streaming from background", "#94a3b8"),
        ("• Dual-View Mode Controller", "#f59e0b"),
        ("  Flowchart View vs Detailed List", "#94a3b8"),
        ("• Findings Inspector & Filters", "#ef4444"),
        ("  Severity, Engine, and Path query", "#94a3b8"),
    ]
    cur_y = 0.795
    for title, col in web_items:
        ax.text(0.033, cur_y, title, fontsize=8.5, color=col, fontfamily='monospace', zorder=4)
        cur_y -= 0.021

    # 2B: CLI Interface Card
    draw_card(0.023, 0.10, 0.149, 0.380, bg_color='#0a162d', border_color='#a855f7', lw=1.2)
    ax.text(0.033, 0.455, "CLI Execution Engine", fontsize=13, fontweight='bold', color='#c084fc', zorder=4)
    ax.text(0.033, 0.437, "main.py (argparse, rich)", fontsize=8.5, color='#64748b', fontfamily='monospace', zorder=4)

    cli_items = [
        ("• Target Input: -u / --url", "#f8fafc"),
        ("• Crawl Scope: --max-pages / depth", "#94a3b8"),
        ("• Engine Switches:", "#f8fafc"),
        ("  --nuclei, --subfinder, --nikto", "#cbd5e1"),
        ("  --nmap, --sqlmap, --shodan", "#cbd5e1"),
        ("  --all-tools (one-click full audit)", "#00ff88"),
        ("• Safe Reflection: --safe-reflection", "#38bdf8"),
        ("• Header Skip: --skip-headers", "#94a3b8"),
        ("• Rich Console Formatters:", "#c084fc"),
        ("  Tree visualizer for subdomains", "#94a3b8"),
        ("  Colorized vulnerability tables", "#94a3b8"),
        ("• Multi-Format Exporters:", "#f59e0b"),
        ("  --output (JSON report)", "#94a3b8"),
        ("  --sitemap-output (Site map)", "#94a3b8"),
        ("  --export-html & --export-csv", "#94a3b8"),
    ]
    cur_y = 0.412
    for title, col in web_items[:len(cli_items)]:
        item_text, item_col = cli_items[web_items.index((title, col))]
        ax.text(0.033, cur_y, item_text, fontsize=8.5, color=item_col, fontfamily='monospace', zorder=4)
        cur_y -= 0.021

    # ─────────────────────────────────────────────────────────────────────────
    # 3. COLUMN 2: API GATEWAY & SCAN CONTROLLER CORE
    # ─────────────────────────────────────────────────────────────────────────
    draw_card(0.200, 0.08, 0.170, 0.825, bg_color='#081324', border_color='#00ff88', lw=1.8)
    draw_header_badge(0.210, 0.88, 0.150, "2. BACKEND & GATEWAY", color='#00ff88', bg='#002816')

    # Gateway Web Server
    draw_card(0.208, 0.54, 0.154, 0.325, bg_color='#0c1a33', border_color='#00ff88', lw=1.2)
    ax.text(0.218, 0.840, "REST & SSE Server", fontsize=13, fontweight='bold', color='#00ff88', zorder=4)
    ax.text(0.218, 0.822, "webapp/server.py (ThreadingHTTPServer)", fontsize=8.5, color='#64748b', fontfamily='monospace', zorder=4)

    server_items = [
        ("• HTTP/1.1 Multi-Threaded Daemon", "#f8fafc"),
        ("• RESTful Endpoints:", "#38bdf8"),
        ("  POST /api/scans  (Launch scan)", "#cbd5e1"),
        ("  GET  /api/scans  (List history)", "#cbd5e1"),
        ("  GET  /api/scans/:id  (Details)", "#cbd5e1"),
        ("  GET  /api/tools  (Installed)", "#cbd5e1"),
        ("  GET  /api/health (Readiness)", "#cbd5e1"),
        ("• Server-Sent Events (SSE):", "#00ff88"),
        ("  GET  /api/scans/:id/stream", "#00ff88"),
        ("  Streams live terminal logs in real-time", "#94a3b8"),
        ("• Secure Download Handlers:", "#f59e0b"),
        ("  /api/scans/:id/download (Report)", "#cbd5e1"),
        ("  /api/scans/:id/download-sitemap", "#cbd5e1"),
        ("• Static Asset Dispatcher (index, CSS, JS)", "#64748b"),
    ]
    cur_y = 0.795
    for title, col in server_items:
        ax.text(0.218, cur_y, title, fontsize=8.5, color=col, fontfamily='monospace', zorder=4)
        cur_y -= 0.020

    # Scan State Store & Worker
    draw_card(0.208, 0.10, 0.154, 0.415, bg_color='#0c1a33', border_color='#00d4ff', lw=1.2)
    ax.text(0.218, 0.490, "ScanStore & Orchestrator", fontsize=13, fontweight='bold', color='#00d4ff', zorder=4)
    ax.text(0.218, 0.472, "Thread-Safe State & Execution Pipeline", fontsize=8.5, color='#64748b', fontfamily='monospace', zorder=4)

    store_items = [
        ("• In-Memory Thread-Safe State Store", "#f8fafc"),
        ("  Lock-guarded state transitions", "#94a3b8"),
        ("  Automatic history retention (max 25)", "#94a3b8"),
        ("• Background Thread Worker Pool", "#00d4ff"),
        ("  Daemon threads prevent UI lockup", "#94a3b8"),
        ("• Per-Scan Log Queue Manager", "#00ff88"),
        ("  append_log() & drain_log() buffer", "#94a3b8"),
        ("• Progress Telemetry Engine", "#f59e0b"),
        ("  Pages found / scanned, subs, findings", "#94a3b8"),
        ("• Pipeline Stage Dispatcher:", "#a855f7"),
        ("  1. Subfinder OSINT enumeration", "#cbd5e1"),
        ("  2. Resilient BFS web crawling", "#cbd5e1"),
        ("  3. Page metadata & headers audit", "#cbd5e1"),
        ("  4. Safe reflection PoC test", "#cbd5e1"),
        ("  5. Active tool engine execution", "#cbd5e1"),
        ("  6. De-duplication & report write", "#00ff88"),
    ]
    cur_y = 0.446
    for title, col in store_items:
        ax.text(0.218, cur_y, title, fontsize=8.2, color=col, fontfamily='monospace', zorder=4)
        cur_y -= 0.021

    # ─────────────────────────────────────────────────────────────────────────
    # 4. COLUMN 3: RECONNAISSANCE, CRAWLER & SECURITY ENGINES
    # ─────────────────────────────────────────────────────────────────────────
    draw_card(0.390, 0.08, 0.270, 0.825, bg_color='#07111f', border_color='#f59e0b', lw=1.8)
    draw_header_badge(0.400, 0.88, 0.250, "3. MULTI-ENGINE RECON & AUDIT LAYER", color='#f59e0b', bg='#2b1a00')

    # Sub-box 3A: Resilient Web Crawler
    draw_card(0.398, 0.58, 0.122, 0.285, bg_color='#0a172e', border_color='#00ff88', lw=1.2)
    ax.text(0.406, 0.840, "Resilient BFS Crawler", fontsize=11.5, fontweight='bold', color='#00ff88', zorder=4)
    ax.text(0.406, 0.824, "scanner/crawler.py", fontsize=8.0, color='#64748b', fontfamily='monospace', zorder=4)
    crawler_items = [
        ("• Connection-Pooled Session", "#f8fafc"),
        ("  requests.Session keep-alive (10x fast)", "#94a3b8"),
        ("• Route Auto-Discovery", "#00ff88"),
        ("  Pulls /robots.txt & /sitemap.xml", "#94a3b8"),
        ("• Static Asset Filter", "#38bdf8"),
        ("  Excludes .png/.css/.woff/media", "#94a3b8"),
        ("• Recursive Loop Detector", "#f59e0b"),
        ("  Guards against infinite calendars", "#94a3b8"),
        ("• SSL/TLS Resilience", "#cbd5e1"),
        ("  Auto verify=False for local/staging", "#94a3b8"),
        ("• Content-Type Guard (HTML only)", "#64748b"),
    ]
    cur_y = 0.800
    for title, col in crawler_items:
        ax.text(0.406, cur_y, title, fontsize=7.8, color=col, fontfamily='monospace', zorder=4)
        cur_y -= 0.020

    # Sub-box 3B: OSINT & Passive Recon
    draw_card(0.528, 0.58, 0.122, 0.285, bg_color='#0a172e', border_color='#38bdf8', lw=1.2)
    ax.text(0.536, 0.840, "OSINT & Surface Recon", fontsize=11.5, fontweight='bold', color='#38bdf8', zorder=4)
    ax.text(0.536, 0.824, "scanner/sitemap.py & tools_runner.py", fontsize=7.5, color='#64748b', fontfamily='monospace', zorder=4)
    osint_items = [
        ("• Subfinder Passive Engine", "#38bdf8"),
        ("  DNS & Certificate Transparency logs", "#94a3b8"),
        ("  Subdomain enumeration without alert", "#94a3b8"),
        ("• Shodan OSINT Engine", "#00ff88"),
        ("  Free automated Shodan InternetDB", "#00ff88"),
        ("  Public IP & ASN mapping", "#94a3b8"),
        ("  Listening ports & banner metadata", "#94a3b8"),
        ("  Exposed database alerts (Redis/Mongo)", "#ef4444"),
        ("  Verified CVE vulnerability lookup", "#f59e0b"),
        ("• Apex Topology Mapper", "#cbd5e1"),
        ("  Extracts root domain via tldextract", "#94a3b8"),
    ]
    cur_y = 0.800
    for title, col in osint_items:
        ax.text(0.536, cur_y, title, fontsize=7.8, color=col, fontfamily='monospace', zorder=4)
        cur_y -= 0.020

    # Sub-box 3C: Hierarchical Site Map Builder
    draw_card(0.398, 0.44, 0.252, 0.125, bg_color='#0b1933', border_color='#f59e0b', lw=1.2)
    ax.text(0.406, 0.542, "Site Map Topology Builder (scanner/sitemap.py)", fontsize=11.5, fontweight='bold', color='#f59e0b', zorder=4)
    sitemap_items = [
        "• Combines passive subdomains (Subfinder, Shodan) with actively discovered crawler paths",
        "• Structures tree: Apex Registered Domain ──► Subdomains ──► Endpoints & Parameters",
        "• Inspects HTTP status codes, server technologies (nginx, Apache, cloudflare), and forms count",
        "• Feeds structured topology JSON to Interactive Flowchart and export endpoints",
    ]
    cur_y = 0.520
    for it in sitemap_items:
        ax.text(0.406, cur_y, it, fontsize=8.0, color='#cbd5e1', fontfamily='monospace', zorder=4)
        cur_y -= 0.018

    # Bottom Half: Active Scanning Engines Grid (Nuclei, Nikto, Nmap, sqlmap, Reflection)
    draw_card(0.398, 0.10, 0.252, 0.320, bg_color='#091428', border_color='#ef4444', lw=1.2)
    ax.text(0.406, 0.398, "Active Security & Vulnerability Engines (scanner/tools_runner.py)", fontsize=11.5, fontweight='bold', color='#ef4444', zorder=4)

    # 4 Tool sub-boxes inside
    tool_boxes = [
        (0.406, 0.250, 0.115, 0.130, "Nuclei CVE Engine", "#00ff88", [
            "• ProjectDiscovery templates",
            "• Confirmed CVEs & exposures",
            "• 99%+ True Positive rate",
            "• Extracts reproduction cURL"
        ]),
        (0.527, 0.250, 0.115, 0.130, "Nikto Web Scanner", "#f59e0b", [
            "• Tuned server audit (-T 1..9)",
            "• Noise filter rejects info msgs",
            "• Dangerous files, .git, .env",
            "• Outdated package detection"
        ]),
        (0.406, 0.112, 0.115, 0.125, "Nmap HTTP Scripts", "#38bdf8", [
            "• NSE scripts: methods, xss, sqli",
            "• Strict positive XML parsing",
            "• Rejects 'could not find' noise",
            "• Insecure HTTP methods alert"
        ]),
        (0.527, 0.112, 0.115, 0.125, "sqlmap & Reflection", "#a855f7", [
            "• Safe SQLi detection (risk=1)",
            "• Zero DB write tampering",
            "• Canary reflection marker",
            "• Proves injection reflection"
        ]),
    ]
    for bx, by, bw, bh, btitle, bcol, bitems in tool_boxes:
        draw_card(bx, by, bw, bh, bg_color='#0e1d38', border_color=bcol, lw=1.0)
        ax.text(bx + 0.006, by + bh - 0.018, btitle, fontsize=9.5, fontweight='bold', color=bcol, zorder=4)
        cy = by + bh - 0.038
        for bit in bitems:
            ax.text(bx + 0.006, cy, bit, fontsize=7.2, color='#cbd5e1', fontfamily='monospace', zorder=4)
            cy -= 0.018

    # ─────────────────────────────────────────────────────────────────────────
    # 5. COLUMN 4: ANALYSIS, DE-DUPLICATION & AI/ML CLASSIFIER
    # ─────────────────────────────────────────────────────────────────────────
    draw_card(0.680, 0.08, 0.145, 0.825, bg_color='#081324', border_color='#a855f7', lw=1.8)
    draw_header_badge(0.690, 0.88, 0.125, "4. ANALYSIS & ML CORE", color='#c084fc', bg='#260c38')

    # Passive Security Analyzer
    draw_card(0.688, 0.54, 0.129, 0.325, bg_color='#0f1c3a', border_color='#38bdf8', lw=1.2)
    ax.text(0.696, 0.840, "Passive Rule Engine", fontsize=12, fontweight='bold', color='#38bdf8', zorder=4)
    ax.text(0.696, 0.822, "analyzer/security_checks.py", fontsize=8.0, color='#64748b', fontfamily='monospace', zorder=4)
    passive_items = [
        ("• Security Headers Audit:", "#f8fafc"),
        ("  CSP (Content-Security-Policy)", "#cbd5e1"),
        ("  HSTS (Strict-Transport)", "#cbd5e1"),
        ("  X-Frame-Options (Clickjack)", "#cbd5e1"),
        ("  X-Content-Type-Options", "#cbd5e1"),
        ("  Referrer-Policy & Permissions", "#cbd5e1"),
        ("• Meta Tag CSP Parser", "#00ff88"),
        ("  Detects <meta> CSP in HTML", "#94a3b8"),
        ("• Cookie Hardening Checks", "#f59e0b"),
        ("  Secure, HttpOnly, SameSite", "#cbd5e1"),
        ("• Information Leak Regexes", "#ef4444"),
        ("  API keys, tokens, emails, stack", "#cbd5e1"),
        ("• Static Asset Disqualification", "#38bdf8"),
        ("  Zero header warnings on images", "#94a3b8"),
    ]
    cur_y = 0.795
    for title, col in passive_items:
        ax.text(0.696, cur_y, title, fontsize=7.8, color=col, fontfamily='monospace', zorder=4)
        cur_y -= 0.020

    # ML Classifier & De-Duplication
    draw_card(0.688, 0.10, 0.129, 0.415, bg_color='#0f1c3a', border_color='#a855f7', lw=1.2)
    ax.text(0.696, 0.490, "De-Duplication & ML", fontsize=12, fontweight='bold', color='#c084fc', zorder=4)
    ax.text(0.696, 0.472, "analyzer/reporting.py & model.py", fontsize=8.0, color='#64748b', fontfamily='monospace', zorder=4)
    ml_items = [
        ("• False-Positive Reducer", "#00ff88"),
        ("  consolidate_findings()", "#00ff88"),
        ("  83.6% relative FP reduction", "#00ff88"),
        ("  30 duplicate page CSP warnings", "#94a3b8"),
        ("  ──► 1 host-level finding", "#00ff88"),
        ("• Feature Vector Extractor ($x_i$):", "#f8fafc"),
        ("  Status, method, forms, headers,", "#cbd5e1"),
        ("  content-type, response entropy", "#cbd5e1"),
        ("• ML Classifier (RF / LogReg):", "#c084fc"),
        ("  Computes probability $P(y_i|x_i)$", "#cbd5e1"),
        ("  Decision threshold $\\tau = 0.65$", "#cbd5e1"),
        ("• Risk Prioritization Model:", "#f59e0b"),
        ("  $R_i = w_s S_i + w_e E_i + w_c C_i + w_p I_i$", "#f59e0b"),
        ("  Critical ($R_i \\geq 0.85$): SLA 24h", "#ef4444"),
        ("  High ($0.65 \\leq R_i < 0.85$): SLA 7d", "#f97316"),
        ("  Medium ($0.40 \\leq R_i < 0.65$): 30d", "#f59e0b"),
        ("  Low ($R_i < 0.40$): SLA 90d", "#38bdf8"),
    ]
    cur_y = 0.446
    for title, col in ml_items:
        ax.text(0.696, cur_y, title, fontsize=7.6, color=col, fontfamily='monospace', zorder=4)
        cur_y -= 0.020

    # ─────────────────────────────────────────────────────────────────────────
    # 6. COLUMN 5: PRESENTATION, FLOWCHART & PERSISTENCE
    # ─────────────────────────────────────────────────────────────────────────
    draw_card(0.845, 0.08, 0.140, 0.825, bg_color='#06101e', border_color='#00ff88', lw=1.8)
    draw_header_badge(0.855, 0.88, 0.120, "5. VISUAL & STORAGE", color='#00ff88', bg='#002816')

    # Flowchart Visualizer Box
    draw_card(0.853, 0.54, 0.124, 0.325, bg_color='#0a172e', border_color='#00ff88', lw=1.2)
    ax.text(0.861, 0.840, "Flowchart Architecture", fontsize=11.5, fontweight='bold', color='#00ff88', zorder=4)
    ax.text(0.861, 0.822, "Interactive Attack Surface Tree", fontsize=8.0, color='#64748b', fontfamily='monospace', zorder=4)
    fc_items = [
        ("• Visual Node Graph Hierarchy:", "#00ff88"),
        ("  Apex Root ──► Subdomains ──►", "#00ff88"),
        ("  Endpoints with Methods & Params", "#00ff88"),
        ("• Status & Technology Badges", "#38bdf8"),
        ("  200 OK, 301 Redirect, 403 Forbidden", "#94a3b8"),
        ("• Dynamic Method Pills", "#f59e0b"),
        ("  [GET] cyan / [POST] orange", "#cbd5e1"),
        ("• Form & Parameter Indicators", "#ef4444"),
        ("  Forms count & ?param badges", "#cbd5e1"),
        ("• Quick Attack Surface Filters:", "#a855f7"),
        ("  [All] / [Forms Only] / [Params]", "#a855f7"),
        ("• Expand / Collapse Branches", "#94a3b8"),
        ("• One-Click cURL & URL Copy", "#00ff88"),
    ]
    cur_y = 0.795
    for title, col in fc_items:
        ax.text(0.861, cur_y, title, fontsize=7.6, color=col, fontfamily='monospace', zorder=4)
        cur_y -= 0.020

    # Persistence & Reporting Box
    draw_card(0.853, 0.10, 0.124, 0.415, bg_color='#0a172e', border_color='#f59e0b', lw=1.2)
    ax.text(0.861, 0.490, "Reports & Data Store", fontsize=11.5, fontweight='bold', color='#f59e0b', zorder=4)
    ax.text(0.861, 0.472, "Persistent File Archive (reports/)", fontsize=8.0, color='#64748b', fontfamily='monospace', zorder=4)
    report_items = [
        ("• Vulnerability Reports (JSON)", "#f8fafc"),
        ("  reports/web/{scan_id}.json", "#cbd5e1"),
        ("  Target, findings, severity summary", "#94a3b8"),
        ("  Active tool outputs & remediation", "#94a3b8"),
        ("• Site Map Export (JSON)", "#38bdf8"),
        ("  reports/web/{scan_id}_sitemap.json", "#cbd5e1"),
        ("  Topology, subdomains, endpoints", "#94a3b8"),
        ("• Request/Response Store", "#00ff88"),
        ("  reports/requests/*.txt", "#cbd5e1"),
        ("  Raw forensic audit proof & headers", "#94a3b8"),
        ("• Publication Artifacts:", "#a855f7"),
        ("  CSV & Standalone HTML Reports", "#cbd5e1"),
        ("  300 DPI Figures in output/paper_figures/", "#cbd5e1"),
        ("• GitHub Synchronization", "#f59e0b"),
        ("  Automated commit & push integration", "#94a3b8"),
    ]
    cur_y = 0.446
    for title, col in report_items:
        ax.text(0.861, cur_y, title, fontsize=7.6, color=col, fontfamily='monospace', zorder=4)
        cur_y -= 0.020

    # ─────────────────────────────────────────────────────────────────────────
    # 7. INTER-LAYER DATA FLOW CONNECTORS & PIPELINES (Arrows)
    # ─────────────────────────────────────────────────────────────────────────
    # Arrow 1: Client -> Gateway
    draw_arrow(0.180, 0.68, 0.208, 0.68, color='#38bdf8', lw=2.5)
    ax.text(0.183, 0.700, "HTTP REST", fontsize=7.5, fontweight='bold', color='#38bdf8', fontfamily='monospace', zorder=6)

    draw_arrow(0.208, 0.64, 0.180, 0.64, color='#00ff88', lw=2.0)
    ax.text(0.183, 0.620, "SSE Logs", fontsize=7.5, fontweight='bold', color='#00ff88', fontfamily='monospace', zorder=6)

    draw_arrow(0.180, 0.26, 0.208, 0.26, color='#c084fc', lw=2.0)
    ax.text(0.183, 0.280, "CLI Call", fontsize=7.5, fontweight='bold', color='#c084fc', fontfamily='monospace', zorder=6)

    # Arrow 2: Gateway Store -> Multi-Engine Pipeline
    draw_arrow(0.362, 0.72, 0.398, 0.72, color='#00ff88', lw=2.5)
    ax.text(0.367, 0.738, "Phase 1 & 2", fontsize=7.5, fontweight='bold', color='#00ff88', fontfamily='monospace', zorder=6)

    draw_arrow(0.362, 0.26, 0.398, 0.26, color='#ef4444', lw=2.5)
    ax.text(0.367, 0.278, "Phase 3..5", fontsize=7.5, fontweight='bold', color='#ef4444', fontfamily='monospace', zorder=6)

    # Arrow 3: Crawler & OSINT -> Sitemap Builder
    draw_arrow(0.459, 0.58, 0.459, 0.565, color='#00ff88', lw=1.8)
    draw_arrow(0.589, 0.58, 0.589, 0.565, color='#38bdf8', lw=1.8)

    # Arrow 4: Multi-Engine Results -> Analysis Core
    draw_arrow(0.650, 0.70, 0.688, 0.70, color='#38bdf8', lw=2.2)
    ax.text(0.654, 0.718, "Pages & Headers", fontsize=7.0, fontweight='bold', color='#38bdf8', fontfamily='monospace', zorder=6)

    draw_arrow(0.650, 0.26, 0.688, 0.26, color='#ef4444', lw=2.2)
    ax.text(0.654, 0.278, "Active Findings", fontsize=7.0, fontweight='bold', color='#ef4444', fontfamily='monospace', zorder=6)

    # Arrow 5: Analysis Core -> Flowchart & Reports
    draw_arrow(0.817, 0.70, 0.853, 0.70, color='#00ff88', lw=2.5)
    ax.text(0.822, 0.718, "Site Topology", fontsize=7.0, fontweight='bold', color='#00ff88', fontfamily='monospace', zorder=6)

    draw_arrow(0.817, 0.26, 0.853, 0.26, color='#f59e0b', lw=2.5)
    ax.text(0.822, 0.278, "Consolidated JSON", fontsize=7.0, fontweight='bold', color='#f59e0b', fontfamily='monospace', zorder=6)

    # ─────────────────────────────────────────────────────────────────────────
    # 8. BOTTOM FOOTER & ARCHITECTURAL METRICS
    # ─────────────────────────────────────────────────────────────────────────
    footer_bg = FancyBboxPatch(
        (0.015, 0.012), 0.97, 0.052,
        boxstyle="round,pad=0.006",
        facecolor='#091428',
        edgecolor='#334155',
        linewidth=1.2,
        transform=ax.transAxes,
        zorder=2
    )
    ax.add_patch(footer_bg)

    highlights = [
        "KEY ARCHITECTURAL HIGHLIGHTS:",
        "1. True-Positive Consolidation (83.6% Noise Reduction)",
        "2. Multi-Engine Corroboration (Nuclei + Nikto + Nmap + sqlmap + Shodan)",
        "3. Resilient BFS Crawling (Keep-Alive Pool + Route Discovery)",
        "4. Interactive Flowchart Topology Explorer",
    ]
    ax.text(0.028, 0.038, highlights[0], fontsize=9.0, fontweight='bold', color='#00ff88', fontfamily='monospace', zorder=4)
    ax.text(0.240, 0.038, highlights[1], fontsize=8.5, fontweight='bold', color='#38bdf8', fontfamily='monospace', zorder=4)
    ax.text(0.530, 0.038, highlights[2], fontsize=8.5, fontweight='bold', color='#f59e0b', fontfamily='monospace', zorder=4)
    ax.text(0.028, 0.020, highlights[3], fontsize=8.5, fontweight='bold', color='#c084fc', fontfamily='monospace', zorder=4)
    ax.text(0.360, 0.020, "5. Strict Positive Verification for NSE & Nikto", fontsize=8.5, fontweight='bold', color='#ef4444', fontfamily='monospace', zorder=4)
    ax.text(0.680, 0.020, "6. Shodan InternetDB Zero-Key + API Key Dual Mode", fontsize=8.5, fontweight='bold', color='#00ff88', fontfamily='monospace', zorder=4)

    # ─────────────────────────────────────────────────────────────────────────
    # Save Image to disk
    # ─────────────────────────────────────────────────────────────────────────
    out_dir = "/Users/priyanshu/Documents/tarspectra web/output"
    os.makedirs(out_dir, exist_ok=True)
    out_path_png = os.path.join(out_dir, "tarspectra_system_architecture.png")
    out_path_root_png = "/Users/priyanshu/Documents/tarspectra web/system_architecture.png"
    out_path_svg = os.path.join(out_dir, "tarspectra_system_architecture.svg")

    plt.savefig(out_path_png, dpi=300, facecolor='#050913', edgecolor='none')
    plt.savefig(out_path_root_png, dpi=300, facecolor='#050913', edgecolor='none')
    plt.savefig(out_path_svg, dpi=300, facecolor='#050913', edgecolor='none')
    plt.close()

    print(f"✓ Generated high-resolution architecture PNG: {out_path_png}")
    print(f"✓ Copied to project root: {out_path_root_png}")
    print(f"✓ Generated vector SVG: {out_path_svg}")

if __name__ == '__main__':
    build_architecture_diagram()
