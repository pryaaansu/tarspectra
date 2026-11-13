"""
generate_architecture_image.py — Generates a clean, professional, publication-grade
System Architecture diagram for TARSPECTRA v2.5 with a white background, black text,
and 16:9 aspect ratio optimized for PowerPoint presentations and research slides.
"""

import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

def build_architecture_diagram():
    # 16:9 PowerPoint Widescreen: 14.0 x 7.875 inches @ 200 DPI = 2800 x 1575 px
    # Perfectly proportioned for inserting into standard PowerPoint slides (16:9)
    fig = plt.figure(figsize=(14.0, 7.875), facecolor='#FFFFFF', dpi=200)
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_facecolor('#FFFFFF')
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis('off')

    # Color Palette: Clean black text, white background, minimalist neutral borders
    BG_WHITE = '#FFFFFF'
    BG_STAGE = '#F8FAFC'       # Subtle off-white container fill
    BG_HEADER = '#0F172A'      # Deep solid black/slate header
    BG_CARD = '#FFFFFF'        # Crisp white card fill
    BORDER_MAIN = '#0F172A'    # Black / Slate-900 border
    BORDER_LIGHT = '#CBD5E1'   # Slate-300 clean border
    TEXT_BLACK = '#000000'     # Black text
    TEXT_MAIN = '#0F172A'      # Deep Charcoal / Slate-900 text
    TEXT_MUTED = '#475569'     # Slate-600 neutral text
    TEXT_CODE = '#334155'      # Code / tech labels
    ARROW_COLOR = '#0F172A'    # Black arrows

    def draw_box(x, y, w, h, bg=BG_CARD, border=BORDER_MAIN, lw=1.2, radius=0.008, zorder=2):
        rect = FancyBboxPatch(
            (x, y), w, h,
            boxstyle=f"round,pad={radius}",
            facecolor=bg,
            edgecolor=border,
            linewidth=lw,
            transform=ax.transAxes,
            zorder=zorder
        )
        ax.add_patch(rect)
        return rect

    def draw_arrow(x1, y1, x2, y2, label=None, label_above=True, lw=1.6):
        arrow = FancyArrowPatch(
            (x1, y1), (x2, y2),
            arrowstyle='->',
            color=ARROW_COLOR,
            linewidth=lw,
            mutation_scale=12,
            transform=ax.transAxes,
            zorder=6
        )
        ax.add_patch(arrow)
        if label:
            ly = y1 + 0.016 if label_above else y1 - 0.020
            ax.text((x1 + x2) / 2, ly, label,
                    fontsize=6.8, fontweight='bold', color=TEXT_MAIN,
                    ha='center', va='center', family='sans-serif', zorder=7)

    # 1. Slide Title Header (Clean PPT Slide Header)
    ax.text(0.025, 0.958, "TARSPECTRA v2.5 — SYSTEM ARCHITECTURE & DATA FLOW",
            fontsize=15.5, fontweight='bold', color=TEXT_BLACK, family='sans-serif', zorder=4)
    ax.text(0.025, 0.928, "Modular Web Vulnerability Scanner • Multi-Engine Active Auditing • 83.6% False-Positive Reduction • Attack Surface Flowchart",
            fontsize=9.2, color=TEXT_MUTED, family='sans-serif', zorder=4)

    # Status Pill (top right)
    draw_box(0.79, 0.922, 0.185, 0.046, bg='#F1F5F9', border=BORDER_LIGHT, lw=1.0, radius=0.006)
    ax.text(0.882, 0.945, "LOCAL SANDBOX: 127.0.0.1:8000", fontsize=8.2, fontweight='bold', color=TEXT_MAIN, ha='center', va='center', family='monospace', zorder=4)

    # Top divider rule
    ax.plot([0.025, 0.975], [0.905, 0.905], color=BORDER_LIGHT, linewidth=1.2, transform=ax.transAxes, zorder=3)

    # 2. Stage Columns Geometry
    col_w = 0.164
    gap = 0.035
    start_x = 0.025
    col_y = 0.108
    col_h = 0.772

    stages = [
        {
            "num": "1",
            "title": "CLIENT INTERFACES",
            "sub": "Input & Dashboard",
            "card_top": {
                "title": "Web UI Dashboard",
                "tag": "webapp/static/",
                "bullets": [
                    "• Matrix Rain HUD UI",
                    "• Target URL & Scan Depth",
                    "• 6 Engine Toggle Switches",
                    "• Real-Time SSE Log Viewer",
                    "• Attack Surface Visualizer"
                ]
            },
            "card_bot": {
                "title": "Command-Line (CLI)",
                "tag": "main.py (Rich Console)",
                "bullets": [
                    "• Rich Formatted Terminal",
                    "• Live Spinners & Counters",
                    "• Arguments (--tools, -d)",
                    "• Automated Batch Auditing",
                    "• Report Format Exporters"
                ]
            }
        },
        {
            "num": "2",
            "title": "SCAN CONTROLLER",
            "sub": "API & Task Pool",
            "card_top": {
                "title": "API Gateway & SSE",
                "tag": "webapp/server.py",
                "bullets": [
                    "• ThreadingHTTPServer Core",
                    "• REST Endpoints (/api/scans)",
                    "• Server-Sent Events (SSE)",
                    "• URL Syntax Normalization",
                    "• Scope Boundary Filter"
                ]
            },
            "card_bot": {
                "title": "ScanStore & Queue",
                "tag": "State Engine",
                "bullets": [
                    "• Async Thread Worker Pool",
                    "• Memory State Machine",
                    "• Real-Time Progress State",
                    "• Disk Report Auto-Reload",
                    "• Safe Scan Cancellation"
                ]
            }
        },
        {
            "num": "3",
            "title": "RECON & ENGINES",
            "sub": "Discovery & Active Audit",
            "card_top": {
                "title": "Crawler & OSINT",
                "tag": "scanner/crawler.py",
                "bullets": [
                    "• Resilient BFS Web Crawler",
                    "• HTTP Keep-Alive Pooling",
                    "• /robots.txt & /sitemap.xml",
                    "• Static Asset Filter (.css/.png)",
                    "• Subfinder & Shodan Intel"
                ]
            },
            "card_bot": {
                "title": "Active Tool Plugins",
                "tag": "scanner/tools_runner.py",
                "bullets": [
                    "• Nuclei: CVEs & Misconfigs",
                    "• Nikto: Web Hardening Scan",
                    "• Nmap: Port & NSE Scripts",
                    "• sqlmap: Safe Risk=1 SQLi",
                    "• Safe Canary Token PoC"
                ]
            }
        },
        {
            "num": "4",
            "title": "ANALYSIS & ML CORE",
            "sub": "Validation & Scoring",
            "card_top": {
                "title": "Passive Rule Engine",
                "tag": "analyzer/security_checks.py",
                "bullets": [
                    "• Headers (CSP, HSTS, XFO)",
                    "• HTML <meta> CSP Parser",
                    "• Cookie Flags (HttpOnly/Sec)",
                    "• Sensitive Secret Regexes",
                    "• Zero Static Asset Noise"
                ]
            },
            "card_bot": {
                "title": "Deduplication & Risk",
                "tag": "analyzer/reporting.py",
                "bullets": [
                    "• 83.6% False-Positive Cut",
                    "• Host-Level Header Rollup",
                    "• Multi-Engine Corroboration",
                    "• Risk Score: Ri >= 0.85 (Crit)",
                    "• Strict Positive Verification"
                ]
            }
        },
        {
            "num": "5",
            "title": "VISUAL & OUTPUT",
            "sub": "Hierarchy & Archive",
            "card_top": {
                "title": "Attack Flowchart",
                "tag": "Flowchart Visualizer",
                "bullets": [
                    "• Interactive Site Topology",
                    "• Apex -> Subdomain -> Endpt",
                    "• Method Pills [GET] / [POST]",
                    "• Form & Parameter Badges",
                    "• One-Click cURL Generator"
                ]
            },
            "card_bot": {
                "title": "Report Store",
                "tag": "reports/web/ Archive",
                "bullets": [
                    "• Machine-Readable JSON",
                    "• Attack Surface Sitemap",
                    "• Raw HTTP Evidence Log",
                    "• Formats: JSON, HTML, CSV",
                    "• Direct Git Sync Support"
                ]
            }
        }
    ]

    card_h = 0.332
    top_card_y = col_y + 0.370
    bot_card_y = col_y + 0.015

    for idx, st in enumerate(stages):
        cx = start_x + idx * (col_w + gap)

        # Stage background container
        draw_box(cx, col_y, col_w, col_h, bg=BG_STAGE, border=BORDER_MAIN, lw=1.4, radius=0.008, zorder=2)

        # Stage header banner
        draw_box(cx, col_y + col_h - 0.054, col_w, 0.054, bg=BG_HEADER, border=BORDER_MAIN, lw=1.2, radius=0.006, zorder=3)
        ax.text(cx + col_w / 2, col_y + col_h - 0.021, f"{st['num']}. {st['title']}",
                fontsize=9.2, fontweight='bold', color='#FFFFFF', ha='center', va='center', family='sans-serif', zorder=4)
        ax.text(cx + col_w / 2, col_y + col_h - 0.040, st['sub'],
                fontsize=7.2, color='#94A3B8', ha='center', va='center', family='sans-serif', zorder=4)

        # TOP CARD (Recon / UI Pipeline)
        c_top = st['card_top']
        draw_box(cx + 0.006, top_card_y, col_w - 0.012, card_h, bg=BG_CARD, border=BORDER_LIGHT, lw=1.0, radius=0.006, zorder=3)
        ax.text(cx + 0.012, top_card_y + card_h - 0.022, c_top['title'], fontsize=8.8, fontweight='bold', color=TEXT_BLACK, family='sans-serif', zorder=4)
        ax.text(cx + 0.012, top_card_y + card_h - 0.039, c_top['tag'], fontsize=7.0, color=TEXT_CODE, family='monospace', zorder=4)

        # Divider line inside card
        ax.plot([cx + 0.012, cx + col_w - 0.012], [top_card_y + card_h - 0.048, top_card_y + card_h - 0.048],
                color='#E2E8F0', linewidth=0.8, transform=ax.transAxes, zorder=3)

        by = top_card_y + card_h - 0.070
        for b in c_top['bullets']:
            ax.text(cx + 0.012, by, b, fontsize=7.4, color=TEXT_MAIN, family='sans-serif', zorder=4)
            by -= 0.052

        # BOTTOM CARD (Active / Analysis Pipeline)
        c_bot = st['card_bot']
        draw_box(cx + 0.006, bot_card_y, col_w - 0.012, card_h, bg=BG_CARD, border=BORDER_LIGHT, lw=1.0, radius=0.006, zorder=3)
        ax.text(cx + 0.012, bot_card_y + card_h - 0.022, c_bot['title'], fontsize=8.8, fontweight='bold', color=TEXT_BLACK, family='sans-serif', zorder=4)
        ax.text(cx + 0.012, bot_card_y + card_h - 0.039, c_bot['tag'], fontsize=7.0, color=TEXT_CODE, family='monospace', zorder=4)

        # Divider line inside card
        ax.plot([cx + 0.012, cx + col_w - 0.012], [bot_card_y + card_h - 0.048, bot_card_y + card_h - 0.048],
                color='#E2E8F0', linewidth=0.8, transform=ax.transAxes, zorder=3)

        by = bot_card_y + card_h - 0.070
        for b in c_bot['bullets']:
            ax.text(cx + 0.012, by, b, fontsize=7.4, color=TEXT_MAIN, family='sans-serif', zorder=4)
            by -= 0.052

    # 3. Connecting Pipeline Arrows (Top and Bottom Rows)
    top_arrow_y = top_card_y + card_h / 2
    bot_arrow_y = bot_card_y + card_h / 2

    # Top Row: Reconnaissance & Surface Mapping Pipeline
    top_labels = ["HTTP / SSE", "Start Crawl", "Endpoints", "Site Tree"]
    for i in range(4):
        x1 = start_x + (i + 1) * col_w + i * gap
        x2 = x1 + gap
        draw_arrow(x1, top_arrow_y, x2, top_arrow_y, label=top_labels[i], label_above=True)

    # Bottom Row: Active Vulnerability & Verification Pipeline
    bot_labels = ["CLI Flags", "Dispatch", "Findings", "Final JSON"]
    for i in range(4):
        x1 = start_x + (i + 1) * col_w + i * gap
        x2 = x1 + gap
        draw_arrow(x1, bot_arrow_y, x2, bot_arrow_y, label=bot_labels[i], label_above=False)

    # 4. Bottom Capabilities & Summary Bar
    draw_box(0.025, 0.022, 0.950, 0.065, bg='#F1F5F9', border=BORDER_MAIN, lw=1.2, radius=0.006, zorder=2)
    ax.text(0.040, 0.060, "KEY ARCHITECTURAL HIGHLIGHTS:", fontsize=8.5, fontweight='bold', color=TEXT_BLACK, family='sans-serif', zorder=4)
    ax.text(0.245, 0.060, "1. 83.6% Noise Reduction via Host-Level Rollup", fontsize=8.0, color=TEXT_MAIN, family='sans-serif', zorder=4)
    ax.text(0.575, 0.060, "2. 6 Security Engines (Nuclei, Nikto, Nmap, sqlmap, Subfinder, Shodan)", fontsize=8.0, color=TEXT_MAIN, family='sans-serif', zorder=4)
    
    ax.text(0.040, 0.038, "3. Resilient BFS Crawling with Keep-Alive Pool", fontsize=8.0, color=TEXT_MAIN, family='sans-serif', zorder=4)
    ax.text(0.335, 0.038, "4. Safe Reflection PoC (Zero DB Tampering)", fontsize=8.0, color=TEXT_MAIN, family='sans-serif', zorder=4)
    ax.text(0.615, 0.038, "5. Interactive Subdomain Attack Surface Flowchart", fontsize=8.0, color=TEXT_MAIN, family='sans-serif', zorder=4)

    # Save outputs
    out_dir = "/Users/priyanshu/Documents/tarspectra web/output"
    os.makedirs(out_dir, exist_ok=True)
    out_png = os.path.join(out_dir, "tarspectra_system_architecture.png")
    out_root = "/Users/priyanshu/Documents/tarspectra web/system_architecture.png"
    out_svg = os.path.join(out_dir, "tarspectra_system_architecture.svg")
    out_ppt_png = os.path.join(out_dir, "tarspectra_architecture_ppt.png")

    plt.savefig(out_png, dpi=200, facecolor='#FFFFFF', edgecolor='none')
    plt.savefig(out_root, dpi=200, facecolor='#FFFFFF', edgecolor='none')
    plt.savefig(out_svg, dpi=200, facecolor='#FFFFFF', edgecolor='none')
    plt.savefig(out_ppt_png, dpi=200, facecolor='#FFFFFF', edgecolor='none')
    plt.close()

    print(f"✓ Generated clean PPT architecture PNG (Output): {out_png}")
    print(f"✓ Generated clean PPT architecture PNG (Root): {out_root}")
    print(f"✓ Generated clean PPT architecture PNG (PPT alias): {out_ppt_png}")
    print(f"✓ Generated clean vector SVG: {out_svg}")

if __name__ == '__main__':
    build_architecture_diagram()
