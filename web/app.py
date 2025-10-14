from flask import Flask, render_template, request
import os
import sys

# Ensure project root is on sys.path when running this file directly
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scanner.crawler import crawl_site
from scanner.fetcher import fetch_all
from analyzer.model import annotate_results
from analyzer.reporting import generate_summary
from main import run_active_injection


app = Flask(__name__)


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/crawl")
def crawl():
    start_url = request.form.get("url", "").strip()
    if not start_url:
        return render_template("index.html", error="Please provide a URL to crawl.")

    try:
        max_pages = int(request.form.get("max_pages", 50))
    except ValueError:
        max_pages = 50

    try:
        max_depth = int(request.form.get("max_depth", 2))
    except ValueError:
        max_depth = 2

    urls = crawl_site(start_url, max_pages=max_pages, max_depth=max_depth, respect_domain=True)
    details = fetch_all(urls, output=None, timeout=12, max_body=1000)

    # Heuristic annotate
    annotated = annotate_results(details)

    active_findings = []
    ran_active = False
    if request.form.get("confirm_active") == "1":
        ran_active = True
        workers = int(request.form.get("active_workers", 3))
        delay = float(request.form.get("active_delay", 0.6))
        max_variants = int(request.form.get("max_variants", 2))
        encodings = (request.form.get("encodings") or "raw,url,html")

        annotated, active_findings, err = run_active_injection(
            annotated,
            target_url=start_url,
            payloads_dir="payloads",
            workers=workers,
            delay_between=delay,
            encodings=encodings,
            max_variants=max_variants,
            log_dir="reports/requests",
        )
        if err:
            return render_template(
                "results.html",
                start_url=start_url,
                urls=urls,
                details=annotated,
                summary=generate_summary(annotated),
                active_enabled=True,
                active_error=str(err),
                active_findings_count=len(active_findings),
            )

    return render_template(
        "results.html",
        start_url=start_url,
        urls=urls,
        details=annotated,
        summary=generate_summary(annotated),
        active_enabled=ran_active,
        active_findings_count=len(active_findings),
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)


