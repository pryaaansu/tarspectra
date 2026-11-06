import requests
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
import time
import json


def fetch_details(url, timeout=12, max_body=2000):
    headers = {"User-Agent": "ExploitFinder/0.2 (+https://example.local)"}
    try:
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=True)
        content_type = r.headers.get("Content-Type", "")
        text = r.text or ""
        snippet = text[:max_body]
        parsed = urlparse(url)
        params = list(parse_qs(parsed.query).keys())
        soup = BeautifulSoup(text, "html.parser")
        inputs = [i.get("name") for i in soup.find_all("input", attrs={"name": True})]
        forms = [f.get("action") or "" for f in soup.find_all("form")]
        forms_detail = []
        for form in soup.find_all("form"):
            form_inputs = []
            for element in form.find_all(["input", "textarea", "select"]):
                name = element.get("name")
                if name:
                    form_inputs.append({"name": name, "type": element.get("type", "text")})
            forms_detail.append({
                "action": form.get("action") or "",
                "method": (form.get("method") or "get").lower(),
                "inputs": form_inputs,
            })
        return {
            "url": url,
            "status_code": r.status_code,
            "content_type": content_type,
            "body_snippet": snippet,
            "query_params": params,
            "form_inputs": inputs,
            "form_actions": forms,
            "forms_detail": forms_detail,
            "headers": dict(r.headers),
            "timestamp": int(time.time())
        }
    except requests.RequestException as e:
        return {
            "url": url,
            "status_code": 0,
            "content_type": "",
            "body_snippet": "",
            "query_params": [],
            "form_inputs": [],
            "form_actions": [],
            "forms_detail": [],
            "headers": {},
            "error": str(e),
            "timestamp": int(time.time())
        }


def fetch_all(urls, output=None, timeout=12, max_body=2000):
    results = []
    for u in urls:
        results.append(fetch_details(u, timeout=timeout, max_body=max_body))
    if output:
        with open(output, "w") as f:
            json.dump(results, f, indent=2)
    return results
