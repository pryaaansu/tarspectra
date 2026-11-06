# TARSPECTRA v2.5 — Web Vulnerability Scanner & Site Mapper

Tarspectra is an advanced, high-precision web security scanner and attack surface mapping workbench with a modern cyber web application and a rich CLI.

It addresses automated scanning noise by separating **attack surface site mapping** from **true-positive vulnerability reporting**, integrating industry-standard open-source engines (**ProjectDiscovery Nuclei**, **Subfinder**, **Nikto**, **Nmap**, **sqlmap**), and eliminating false-positive duplicates.

> **Responsible Use Notice:** Only test targets you own or have explicit written permission to assess.

---

## What's New in v2.5

### 1. Separate Site Map & Subdomains Hierarchy
- **Subdomain Tree Structure:** Organizes discovered assets hierarchically (`Root Apex Domain` ➔ `Subdomains` ➔ `Endpoints & Forms`).
- **Passive Subdomain Enumeration:** Integrates **Subfinder** to discover active subdomains from passive OSINT certificate logs and DNS registries without alerting targets.
- **In-Crawl Asset Discovery:** Parses intra-domain links, scripts, and form action endpoints across the registered domain.
- **Dedicated Outputs:** 
  - **Web UI:** Interactive collapsible Subdomain Tree with HTTP status pills (`200 OK`, `301/302 Redirect`, `403 Forbidden`), parameter badges, form counts, and instant copy buttons.
  - **CLI:** Dedicated Rich visual tree (`🌐 example.com` ➔ `🖥️ sub.example.com` ➔ `📄 /endpoint`).
  - **Export:** Standalone `reports/sitemap.json`.

### 2. High True-Positive Vulnerability Reporting (Zero Noise)
- **Host-Level Consolidation:** Fixes the bug where missing security headers were duplicated across every crawled page (e.g. 60 duplicate CSP findings ballooning into 400+ fake bugs). Host-wide controls are now consolidated into a single actionable card per host, detailing total affected endpoints and samples.
- **Negative Finding Rejection:** Rejects informational Nmap NSE messages (e.g. *"Couldn't find any DOM based XSS"*, *"No vulnerabilities found"*) that were previously misclassified as high-severity vulnerabilities.
- **Tuned Nikto Scanner:** Auto-detects SSL and ports, enables performance tuning (`-Tuning 1,2,3,4,8,9,0` to bypass slow CGI dictionary attacks), and filters out diagnostic output (*"Platform: Windows"*, *"SSL Info"*, *"No CGI directories"*).
- **ProjectDiscovery Nuclei Integration:** Integrates Nuclei's community-powered templates for confirmed CVEs, exposed Git/.env/config panels, API leaks, and misconfigurations with exact reproduction `curl` commands.

### 3. Cybernetic "Human-Made" Web Dashboard
- **Matrix Digital Rain Canvas:** Fullscreen animated digital rain background with falling characters, neon-green leading drops, fading trails, and a one-click toggle (`Rain: ON/OFF`).
- **Dual-View Switcher:** Dedicated tabs for **🌐 Site Map & Subdomains** and **🛡️ Vulnerability Report**.
- **Real-Time Terminal Drawer:** Live SSE log stream showing real-time crawler, Nuclei, Nikto, and Nmap activity.
- **Engine Availability Bar:** Automatically detects and displays which open-source tools are installed on the host.

---

## Quick Start

### 1. Requirements
- Python 3.9+
- Optional tools on `PATH` (already supported on macOS via Homebrew):
  - `nuclei` (`brew install nuclei`)
  - `subfinder` (`go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`)
  - `nikto` (`brew install nikto`)
  - `nmap` (`brew install nmap`)
  - `sqlmap` (`brew install sqlmap`)

### 2. Setup Virtual Environment
```bash
cd "/Users/priyanshu/Documents/tarspectra web"
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

### 3. Launch Web Dashboard
```bash
.venv/bin/python -m webapp.server
```
Open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in your browser.

---

## CLI Usage

### Fast Passive Scan + Site Map Tree (Fast)
```bash
.venv/bin/python main.py -u https://your-authorized-target.example.com --max-pages 25
```

### Complete Assessment with Subfinder, Nuclei & Nikto
```bash
.venv/bin/python main.py -u https://your-authorized-target.example.com \
  --subfinder \
  --nuclei \
  --nikto \
  --export-html reports/report.html \
  --export-csv reports/report.csv
```

### Enable All Engines (Nuclei, Subfinder, Nikto, Nmap, sqlmap)
```bash
.venv/bin/python main.py -u https://your-authorized-target.example.com --all-tools
```

---

## Output Architecture

```
Tarspectra Output
├── 🌐 Separate Output 1: Site Map & Subdomain Hierarchy
│   ├── Apex Domain (e.g. dsatm.edu.in)
│   │   ├── Subdomain 1 (e.g. portal.dsatm.edu.in [200 OK])
│   │   │   ├── /login [POST Form: username, password]
│   │   │   └── /reset-password
│   │   └── Subdomain 2 (e.g. api.dsatm.edu.in [200 OK])
│   └── Export: reports/sitemap.json
│
└── 🛡️ Separate Output 2: True-Positive Vulnerability Report
    ├── Critical / High Flaws (Confirmed CVEs, SQLi, RCE, Traversal)
    ├── Medium Flaws (Sensitive file exposure, weak CSP, CORS)
    ├── Low / Hardening (Missing headers consolidated per host)
    └── Export: reports/report.json, HTML, CSV
```

---

## Testing & Verification

Run the test suite:
```bash
.venv/bin/python -m unittest discover -s tests -v
```
All 11 unit tests verify site map hierarchy generation, true-positive consolidation, and tool noise rejection.
