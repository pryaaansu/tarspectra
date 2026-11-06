"""
generate_paper_charts.py
Generates high-resolution, publication-quality figures for the research paper:
'AI-Driven Web Vulnerability Assessment and Automated Security Scanning Frameworks'
"""

import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
import numpy as np
import os

# Set publication-quality style
plt.rcParams.update({
    'font.family': 'sans-serif',
    'font.sans-serif': ['Helvetica', 'Arial', 'DejaVu Sans'],
    'font.size': 11,
    'axes.labelsize': 12,
    'axes.titlesize': 13,
    'xtick.labelsize': 11,
    'ytick.labelsize': 11,
    'legend.fontsize': 10,
    'figure.titlesize': 14,
    'figure.dpi': 300,
    'savefig.dpi': 300,
    'axes.grid': True,
    'grid.alpha': 0.35,
    'grid.linestyle': '--',
})

OUT_DIR = "/Users/priyanshu/Documents/tarspectra web/output/paper_figures"
os.makedirs(OUT_DIR, exist_ok=True)

# ==============================================================================
# Figure 3: Comparative Performance of Vulnerability Detection Methods
# (Replaces bogus smart-contract graph)
# ==============================================================================
def generate_figure_3():
    methods = ['SAST-only', 'DAST-only', 'Combined\nSAST–DAST', 'Proposed\n(Tarspectra)']
    metrics = {
        'Precision': [58.4, 65.2, 62.4, 92.6],
        'Recall':    [76.8, 71.4, 84.6, 89.8],
        'F1-score':  [66.3, 68.2, 71.8, 91.2],
        'FPR':       [38.5, 31.8, 34.2, 5.6],
    }

    x = np.arange(len(methods))
    width = 0.18

    fig, ax = plt.subplots(figsize=(8.5, 4.8))

    colors = ['#2b5c8f', '#3caea3', '#f6d55c', '#ed553b']

    for i, (metric, vals) in enumerate(metrics.items()):
        offset = (i - 1.5) * width
        rects = ax.bar(x + offset, vals, width, label=metric, color=colors[i], edgecolor='black', linewidth=0.6)
        # Value labels above bars
        for rect in rects:
            h = rect.get_height()
            ax.annotate(f'{h:.1f}%',
                        xy=(rect.get_x() + rect.get_width() / 2, h),
                        xytext=(0, 3),  # 3 points vertical offset
                        textcoords="offset points",
                        ha='center', va='bottom', fontsize=8, fontweight='bold')

    ax.set_ylabel('Performance Value (%)', fontweight='bold')
    ax.set_title('Fig. 3. Comparative Performance of Web Vulnerability Detection Approaches', fontweight='bold', pad=14)
    ax.set_xticks(x)
    ax.set_xticklabels(methods, fontweight='bold')
    ax.set_ylim(0, 108)
    ax.legend(loc='upper left', framealpha=0.95, ncol=4)
    plt.tight_layout()

    fig.savefig(f"{OUT_DIR}/Fig3_comparative_performance.png")
    fig.savefig(f"{OUT_DIR}/Fig3_comparative_performance.svg")
    plt.close()
    print("✓ Generated Fig 3: Comparative Performance")


# ==============================================================================
# Figure 4: False-Positive Rate (FPR) and Relative Reduction Analysis
# ==============================================================================
def generate_figure_4():
    configs = [
        'SAST Baseline',
        'DAST Baseline',
        'Combined\nSAST–DAST',
        'Scanning + ML\n(Random Forest)',
        'Proposed Framework\n(ML + Verification)'
    ]
    fpr_values = [38.5, 31.8, 34.2, 15.6, 5.6]
    reduction_vs_baseline = [0.0, 7.0, 0.0, 54.4, 83.6]  # vs Combined SAST-DAST (34.2%)

    fig, ax1 = plt.subplots(figsize=(8.8, 5.0))

    x = np.arange(len(configs))
    bar_width = 0.45

    bars = ax1.bar(x, fpr_values, bar_width, color='#e74c3c', alpha=0.85, edgecolor='black', linewidth=0.8, label='False-Positive Rate (FPR %)')
    ax1.set_ylabel('False-Positive Rate (%) [Lower is Better]', color='#c0392b', fontweight='bold')
    ax1.tick_params(axis='y', labelcolor='#c0392b')
    ax1.set_ylim(0, 48)

    for bar in bars:
        h = bar.get_height()
        ax1.annotate(f'{h:.1f}%',
                     xy=(bar.get_x() + bar.get_width() / 2, h),
                     xytext=(0, 3),
                     textcoords="offset points",
                     ha='center', va='bottom', fontsize=9, fontweight='bold', color='#c0392b')

    # Line chart on secondary axis for Relative Reduction RFP (%)
    ax2 = ax1.twinx()
    line = ax2.plot(x, reduction_vs_baseline, color='#27ae60', marker='o', linewidth=2.5, markersize=8, label='Relative FP Reduction ($R_{FP}$ %)')
    ax2.set_ylabel('Relative False-Positive Reduction (%) [Higher is Better]', color='#27ae60', fontweight='bold')
    ax2.tick_params(axis='y', labelcolor='#27ae60')
    ax2.set_ylim(-5, 105)

    for i, txt in enumerate(reduction_vs_baseline):
        if i >= 2:
            ax2.annotate(f'{txt:.1f}%', (x[i], txt), textcoords="offset points", xytext=(0, 9), ha='center', fontsize=9, fontweight='bold', color='#1e8449')

    ax1.set_xticks(x)
    ax1.set_xticklabels(configs, fontweight='bold', fontsize=9.5)
    ax1.set_title('Fig. 4. False-Positive Rate (FPR) and Relative Reduction ($R_{FP}$) Across Configurations', fontweight='bold', pad=14)

    # Combined legend
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper right', framealpha=0.95)

    plt.tight_layout()
    fig.savefig(f"{OUT_DIR}/Fig4_false_positive_reduction.png")
    fig.savefig(f"{OUT_DIR}/Fig4_false_positive_reduction.svg")
    plt.close()
    print("✓ Generated Fig 4: False-Positive Reduction Analysis")


# ==============================================================================
# Figure 5: Category-Wise Evaluation Across Web Vulnerability Categories
# ==============================================================================
def generate_figure_5():
    categories = [
        'SQL Injection\n(SQLi)',
        'Cross-Site\nScripting (XSS)',
        'Broken Access\nControl',
        'Security\nMisconfiguration',
        'Overall\nFramework'
    ]

    precision = [94.2, 91.8, 86.5, 96.1, 92.6]
    recall    = [91.5, 88.4, 82.1, 95.0, 89.8]
    f1        = [92.8, 90.1, 84.2, 95.5, 91.2]
    fpr       = [4.8,  6.2,  9.4,  3.1,  5.6]

    x = np.arange(len(categories))
    width = 0.2

    fig, ax = plt.subplots(figsize=(9.2, 5.0))

    r1 = ax.bar(x - 1.5*width, precision, width, label='Precision (%)', color='#1f77b4', edgecolor='black', linewidth=0.6)
    r2 = ax.bar(x - 0.5*width, recall,    width, label='Recall (%)',    color='#2ca02c', edgecolor='black', linewidth=0.6)
    r3 = ax.bar(x + 0.5*width, f1,        width, label='F1-Score (%)',  color='#ff7f0e', edgecolor='black', linewidth=0.6)
    r4 = ax.bar(x + 1.5*width, fpr,       width, label='FPR (%)',       color='#d62728', edgecolor='black', linewidth=0.6)

    ax.set_ylabel('Metric Score (%)', fontweight='bold')
    ax.set_title('Fig. 5. Category-Wise Performance Evaluation Across OWASP Web Vulnerabilities', fontweight='bold', pad=14)
    ax.set_xticks(x)
    ax.set_xticklabels(categories, fontweight='bold')
    ax.set_ylim(0, 115)
    ax.legend(loc='upper right', ncol=4, framealpha=0.95)

    # Annotate bars
    for group in [r1, r2, r3]:
        for bar in group:
            h = bar.get_height()
            ax.annotate(f'{h:.1f}', xy=(bar.get_x() + bar.get_width()/2, h), xytext=(0, 2), textcoords="offset points", ha='center', va='bottom', fontsize=7.5)

    for bar in r4:
        h = bar.get_height()
        ax.annotate(f'{h:.1f}%', xy=(bar.get_x() + bar.get_width()/2, h), xytext=(0, 2), textcoords="offset points", ha='center', va='bottom', fontsize=7.5, color='#b01212', fontweight='bold')

    plt.tight_layout()
    fig.savefig(f"{OUT_DIR}/Fig5_category_evaluation.png")
    fig.savefig(f"{OUT_DIR}/Fig5_category_evaluation.svg")
    plt.close()
    print("✓ Generated Fig 5: Category-Wise Evaluation")


# ==============================================================================
# Figure 6: AI-Assisted Architecture Workflow (Replaces Russian/Smart-contract diagrams)
# ==============================================================================
def generate_figure_architecture():
    fig, ax = plt.subplots(figsize=(10.5, 4.5))
    ax.axis('off')

    # Draw boxes for pipeline steps
    boxes = [
        {"x": 0.03, "y": 0.35, "w": 0.15, "h": 0.40, "title": "1. Input Environment", "items": ["• Target Web URL", "• HTML / Endpoints", "• Config & Headers", "• Scope Constraints"], "color": "#e8f4f8", "border": "#2b5c8f"},
        {"x": 0.22, "y": 0.35, "w": 0.16, "h": 0.40, "title": "2. Discovery & Scan", "items": ["• BFS Web Crawler", "• Subfinder OSINT", "• Baseline DAST/SAST", "• Feature Extractor $x_i$"], "color": "#e8f8f5", "border": "#16a085"},
        {"x": 0.42, "y": 0.35, "w": 0.17, "h": 0.40, "title": "3. ML Classification", "items": ["• Random Forest / LR", "• Probability $P(y_i|x_i)$", "• Decision Thresh $\\tau$", "• Benign vs Vuln Filter"], "color": "#fef9e7", "border": "#f39c12"},
        {"x": 0.63, "y": 0.35, "w": 0.17, "h": 0.40, "title": "4. Evidence Verification", "items": ["• Safe Reflection PoC", "• Header Consolidation", "• False-Positive Red.", "• Nuclei/Nikto Corrobor."], "color": "#fbf2ea", "border": "#d35400"},
        {"x": 0.84, "y": 0.35, "w": 0.14, "h": 0.40, "title": "5. Prioritized Report", "items": ["• Risk Score $R_i$", "• Subdomain Hierarchy", "• True Findings Report", "• Remediation Guide"], "color": "#f4ecf7", "border": "#8e44ad"},
    ]

    for b in boxes:
        rect = FancyBboxPatch((b['x'], b['y']), b['w'], b['h'], boxstyle="round,pad=0.015", facecolor=b['color'], edgecolor=b['border'], linewidth=2.0, linestyle='-', transform=ax.transAxes, zorder=2)
        ax.add_patch(rect)
        ax.text(b['x'] + b['w']/2, b['y'] + b['h'] - 0.06, b['title'], ha='center', va='center', transform=ax.transAxes, fontsize=10, fontweight='bold', color=b['border'], zorder=3)
        body_text = "\n".join(b['items'])
        ax.text(b['x'] + 0.015, b['y'] + 0.17, body_text, ha='left', va='center', transform=ax.transAxes, fontsize=8.5, color='#2c3e50', zorder=3)

    # Draw arrows connecting boxes
    for i in range(len(boxes) - 1):
        x_start = boxes[i]['x'] + boxes[i]['w'] + 0.005
        x_end = boxes[i+1]['x'] - 0.005
        y = boxes[i]['y'] + boxes[i]['h'] / 2
        ax.annotate('', xy=(x_end, y), xytext=(x_start, y),
                    xycoords='axes fraction', textcoords='axes fraction',
                    arrowprops=dict(arrowstyle="->", lw=2.2, color="#34495e"))

    ax.set_title('Fig. 1. End-to-End Modular Architecture of the Proposed AI-Driven Security Scanning Framework', fontweight='bold', pad=15)
    plt.tight_layout()
    fig.savefig(f"{OUT_DIR}/Fig1_framework_architecture.png")
    fig.savefig(f"{OUT_DIR}/Fig1_framework_architecture.svg")
    plt.close()
    print("✓ Generated Fig 1: Modular Framework Architecture")


# ==============================================================================
# Figure 6: Risk Prioritization Distribution and Threshold Policy (Table II visual)
# ==============================================================================
def generate_figure_risk():
    levels = ['Critical\n($0.85 \\leq R_i \\leq 1.00$)', 'High\n($0.65 \\leq R_i < 0.85$)', 'Medium\n($0.40 \\leq R_i < 0.65$)', 'Low\n($0.00 \\leq R_i < 0.40$)']
    findings_pct = [8.5, 24.2, 42.1, 25.2]
    sla_hours = [24, 168, 720, 2160] # 24h, 7d, 30d, 90d
    colors = ['#c0392b', '#e67e22', '#f1c40f', '#3498db']

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(9.5, 4.2))

    # Pie/Donut Chart of findings distribution
    wedges, texts, autotexts = ax1.pie(findings_pct, labels=levels, autopct='%1.1f%%', startangle=140, colors=colors, wedgeprops=dict(width=0.45, edgecolor='black', linewidth=0.8))
    for t in texts:
        t.set_fontsize(8.5)
        t.set_fontweight('bold')
    for at in autotexts:
        at.set_fontsize(9)
        at.set_fontweight('bold')
    ax1.set_title('(a) Finding Distribution by Risk Tier', fontweight='bold', fontsize=11)

    # SLA remediation horizon bar chart
    y_pos = np.arange(len(levels))
    bars = ax2.barh(y_pos, [24, 168, 720, 2160], color=colors, edgecolor='black', linewidth=0.8)
    ax2.set_yticks(y_pos)
    ax2.set_yticklabels(['Critical (24h)', 'High (7d)', 'Medium (30d)', 'Low (90d)'], fontweight='bold', fontsize=9.5)
    ax2.invert_yaxis()  # Critical at top
    ax2.set_xlabel('Remediation SLA Target (Hours)', fontweight='bold')
    ax2.set_xscale('log')
    ax2.set_title('(b) Recommended Remediation Response SLA', fontweight='bold', fontsize=11)

    for bar, val in zip(bars, [24, 168, 720, 2160]):
        text = f"{val}h (24h)" if val==24 else (f"{val}h (7 days)" if val==168 else (f"{val}h (30 days)" if val==720 else f"{val}h (90 days)"))
        ax2.text(bar.get_width() * 1.15, bar.get_y() + bar.get_height()/2, text, va='center', ha='left', fontsize=8.5, fontweight='bold')

    ax2.set_xlim(1, 10000)
    fig.suptitle('Fig. 2. Risk-Based Prioritization Model ($R_i = w_sS_i + w_eE_i + w_cC_i + w_pI_i$) Allocation & Remediation Policy', fontweight='bold', fontsize=12)
    plt.tight_layout()
    fig.savefig(f"{OUT_DIR}/Fig2_risk_prioritization.png")
    fig.savefig(f"{OUT_DIR}/Fig2_risk_prioritization.svg")
    plt.close()
    print("✓ Generated Fig 2: Risk-Based Prioritization Model")


if __name__ == '__main__':
    generate_figure_3()
    generate_figure_4()
    generate_figure_5()
    generate_figure_architecture()
    generate_figure_risk()
    print("\nAll figures generated successfully in:", OUT_DIR)
