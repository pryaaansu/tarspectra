import requests
import time
import html as html_mod
import base64
import hashlib
import json
import os
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote_plus
from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy

DEFAULT_USER_AGENT = "ExploitFinder-Active/0.3 (+https://example.local)"

# small fallback
DEFAULT_PAYLOADS = {
    "marker": ["INJECT-MARKER-PRYANSU-@@ID@@"],
    "xss_test": ["<INJECT-MARKER-PRYANSU-@@ID@@>"],
    "redirect_test": ["https://attacker.example/INJECT-MARKER-@@ID@@"]
}

# default max body saved per request/response (bytes)
DEFAULT_MAX_SAVE_BODY = 50000


def ensure_headers(headers):
    h = {"User-Agent": DEFAULT_USER_AGENT}
    if headers:
        h.update(headers)
    return h


def build_injected_url(original_url, param, payload):
    p = urlparse(original_url)
    q = parse_qs(p.query, keep_blank_values=True)
    q[param] = [payload]
    new_q = urlencode({k: v[0] for k, v in q.items()}, doseq=False)
    new_parts = (p.scheme, p.netloc, p.path, p.params, new_q, p.fragment)
    return urlunparse(new_parts)


def baseline_fetch(url, timeout=12, headers=None, verify=True):
    try:
        r = requests.get(url, headers=ensure_headers(headers), timeout=timeout, allow_redirects=True, verify=verify)
        return {
            "status_code": r.status_code,
            "text": r.text or "",
            "headers": dict(r.headers),
            "elapsed": r.elapsed.total_seconds(),
            "url": r.url
        }
    except requests.RequestException as e:
        return {"status_code": 0, "text": "", "headers": {}, "error": str(e), "elapsed": 0, "url": url}


def injected_fetch(method, url, param, payload, headers=None, timeout=12, data=None, verify=True):
    try:
        h = ensure_headers(headers)
        if method.upper() == "POST":
            post_data = deepcopy(data) if data else {}
            post_data[param] = payload
            r = requests.post(url, headers=h, data=post_data, timeout=timeout, allow_redirects=True, verify=verify)
            req_info = {"method": "POST", "url": url, "data": post_data, "headers": dict(r.request.headers)}
        else:
            injected_url = build_injected_url(url, param, payload)
            r = requests.get(injected_url, headers=h, timeout=timeout, allow_redirects=True, verify=verify)
            # requests.Request object for GET has no body
            req_info = {"method": "GET", "url": injected_url, "data": None, "headers": dict(r.request.headers)}
        return {
            "status_code": r.status_code,
            "text": r.text or "",
            "headers": dict(r.headers),
            "elapsed": r.elapsed.total_seconds(),
            "final_url": r.url,
            "request_info": req_info
        }
    except requests.RequestException as e:
        return {"status_code": 0, "text": "", "headers": {}, "error": str(e), "elapsed": 0, "final_url": url, "request_info": {"method": method, "url": url, "data": data, "headers": {}}}


def detect_reflection(baseline_text, injected_text, payload_marker):
    if not payload_marker:
        return False, ""
    if payload_marker in injected_text and payload_marker not in baseline_text:
        idx = injected_text.find(payload_marker)
        start = max(0, idx - 80)
        end = min(len(injected_text), idx + len(payload_marker) + 80)
        return True, injected_text[start:end]
    return False, ""


def detect_redirect_change(baseline_headers, injected_headers, payload_marker):
    base_loc = baseline_headers.get("Location", "")
    inj_loc = injected_headers.get("Location", "")
    if payload_marker and payload_marker in (inj_loc or "") and payload_marker not in (base_loc or ""):
        return True, inj_loc
    return False, ""


def detect_length_change(baseline_text, injected_text, threshold=80):
    return abs(len(injected_text) - len(baseline_text)) >= threshold


def _ensure_log_dir(log_dir):
    if not log_dir:
        return
    os.makedirs(log_dir, exist_ok=True)


def _write_text_file(path, content, max_bytes=DEFAULT_MAX_SAVE_BODY):
    try:
        # Trim content to max_bytes safely (keep start + end if large)
        if isinstance(content, str):
            b = content.encode("utf-8", errors="replace")
        else:
            b = str(content).encode("utf-8", errors="replace")
        if len(b) <= max_bytes:
            with open(path, "wb") as fh:
                fh.write(b)
            return
        # keep head and tail for context
        head = b[: max_bytes // 2]
        tail = b[- (max_bytes // 2) :]
        with open(path, "wb") as fh:
            fh.write(head + b"\n\n---TRUNCATED---\n\n" + tail)
    except Exception:
        # ignore write errors to avoid breaking tests
        pass


def _make_unique_id(*parts):
    h = hashlib.sha256()
    for p in parts:
        if p is None:
            continue
        if isinstance(p, str):
            h.update(p.encode("utf-8", errors="ignore"))
        else:
            try:
                h.update(json.dumps(p, sort_keys=True).encode("utf-8"))
            except Exception:
                h.update(str(p).encode("utf-8", errors="ignore"))
    h.update(str(time.time()).encode("utf-8"))
    return h.hexdigest()[:28]


def save_evidence(log_dir, prefix, info, max_body=DEFAULT_MAX_SAVE_BODY):
    """
    Saves a request/response pair (info) into files under log_dir.
    prefix will be used as part of filename.
    info is a dict e.g.
      {"request": {"method":"GET","url":...,"headers":...,"data":...},
       "response": {"status":..., "headers":..., "body": "..."}}
    Returns tuple (req_path, resp_path) (absolute paths)
    """
    if not log_dir:
        return None, None
    _ensure_log_dir(log_dir)
    uid = _make_unique_id(prefix, info.get("request", {}).get("url", ""), info.get("response", {}).get("status", ""))
    base = os.path.join(log_dir, uid)
    req_path = base + "_req.txt"
    resp_path = base + "_resp.txt"
    # write readable request
    try:
        req_lines = []
        r = info.get("request", {})
        method = r.get("method", "GET")
        req_lines.append(f"{method} {r.get('url','')}")
        req_lines.append("")
        req_lines.append("Headers:")
        for k, v in (r.get("headers") or {}).items():
            req_lines.append(f"{k}: {v}")
        req_lines.append("")
        req_lines.append("Body/data:")
        req_lines.append(json.dumps(r.get("data", {}), ensure_ascii=False, indent=2))
        _write_text_file(req_path, "\n".join(req_lines), max_bytes=max_body)
    except Exception:
        req_path = None
    # write response
    try:
        resp_lines = []
        s = info.get("response", {})
        resp_lines.append(f"Status: {s.get('status')}")
        resp_lines.append("")
        resp_lines.append("Headers:")
        for k, v in (s.get("headers") or {}).items():
            resp_lines.append(f"{k}: {v}")
        resp_lines.append("")
        resp_lines.append("Body (trimmed):")
        resp_lines.append(s.get("body", "")[: max_body])
        _write_text_file(resp_path, "\n".join(resp_lines), max_bytes=max_body)
    except Exception:
        resp_path = None

    # return absolute paths where possible
    return (os.path.abspath(req_path) if req_path else None, os.path.abspath(resp_path) if resp_path else None)


def generate_variants(raw_payload, encodings, max_variants=2):
    variants = []
    seen = set()

    def add_variant(v):
        if v in seen:
            return
        seen.add(v)
        variants.append(v)

    for enc in encodings:
        if enc == "raw":
            add_variant(raw_payload)
        elif enc == "url":
            add_variant(quote_plus(raw_payload))
        elif enc == "html":
            add_variant(html_mod.escape(raw_payload))
        elif enc == "double_url":
            add_variant(quote_plus(quote_plus(raw_payload)))
        elif enc == "base64":
            try:
                add_variant(base64.b64encode(raw_payload.encode()).decode())
            except Exception:
                pass
        elif enc == "hex":
            try:
                add_variant(raw_payload.encode().hex())
            except Exception:
                pass
        if len(variants) >= max_variants:
            break

    if not variants:
        variants = [raw_payload]

    return variants[:max_variants]


def test_param_reflection_task(item, param, payload_template, method="GET", form_data=None, headers=None,
                               verify=True, timeout=12, encodings=None, max_variants=2, log_dir=None, max_save_body=DEFAULT_MAX_SAVE_BODY):
    url = item.get("url")
    unique_id = str(int(time.time() * 1000))[-6:]
    raw_payload = payload_template.replace("@@ID@@", unique_id)
    encodings = encodings or ["raw", "url", "html"]
    variants = generate_variants(raw_payload, encodings, max_variants=max_variants)

    base = baseline_fetch(url, timeout=timeout, headers=headers, verify=verify)
    all_findings = []
    variants_tested = []

    for variant in variants:
        inj = injected_fetch(method, url, param, variant, headers=headers, timeout=timeout, data=form_data, verify=verify)

        # prepare evidence info
        base_info = {
            "request": {"method": "GET", "url": base.get("url"), "headers": {} , "data": None},
            "response": {"status": base.get("status_code"), "headers": base.get("headers"), "body": base.get("text", "")}
        }
        inj_req = inj.get("request_info") or {"method": "GET", "url": inj.get("final_url") or url, "headers": {}, "data": None}
        inj_info = {
            "request": {"method": inj_req.get("method"), "url": inj_req.get("url"), "headers": inj_req.get("headers"), "data": inj_req.get("data")},
            "response": {"status": inj.get("status_code"), "headers": inj.get("headers"), "body": inj.get("text", "")}
        }

        findings = []
        reflected, snippet = detect_reflection(base.get("text", ""), inj.get("text", ""), variant)
        if reflected:
            findings.append({
                "type": "reflection",
                "evidence": snippet,
                "payload_variant": variant,
                "method": method,
                "param": param,
                "final_url": inj.get("final_url")
            })

        redir, redir_loc = detect_redirect_change(base.get("headers", {}), inj.get("headers", {}), variant)
        if redir:
            findings.append({
                "type": "redirect",
                "evidence": redir_loc,
                "payload_variant": variant,
                "method": method,
                "param": param
            })

        if detect_length_change(base.get("text", ""), inj.get("text", ""), threshold=80):
            findings.append({
                "type": "length_change",
                "evidence": {"base_len": len(base.get("text", "")), "inj_len": len(inj.get("text", ""))},
                "payload_variant": variant,
                "method": method,
                "param": param
            })

        if base.get("status_code") != inj.get("status_code"):
            findings.append({
                "type": "status_change",
                "evidence": {"base_status": base.get("status_code"), "inj_status": inj.get("status_code")},
                "payload_variant": variant,
                "method": method,
                "param": param
            })

        variants_tested.append(variant)
        # if we have findings for this variant, save evidence files and attach paths
        if findings and log_dir:
            prefix = f"{param}-{unique_id}-{variant[:40]}"
            req_path, resp_path = save_evidence(log_dir, prefix, {"request": inj_info["request"], "response": inj_info["response"]}, max_body=max_save_body)
            # also save baseline for context
            base_req_path, base_resp_path = save_evidence(log_dir, f"baseline-{param}-{unique_id}", {"request": base_info["request"], "response": base_info["response"]}, max_body=max_save_body)
            # attach file paths to each finding
            for f in findings:
                f["request_file"] = req_path
                f["response_file"] = resp_path
                f["baseline_request_file"] = base_req_path
                f["baseline_response_file"] = base_resp_path

        if findings:
            all_findings.extend(findings)

    return {
        "url": url,
        "param": param,
        "payload_template": payload_template,
        "variants_tested": variants_tested,
        "findings": all_findings,
        "base": {"status": base.get("status_code"), "elapsed": base.get("elapsed")}
    }


def run_active_tests(items, payloads=None, max_workers=3, delay_between=0.6,
                     require_consent=False, verify=True, timeout=12,
                     encodings=None, max_variants=2, log_dir=None, max_save_body=DEFAULT_MAX_SAVE_BODY):
    if require_consent is False:
        raise RuntimeError("Active testing requires explicit consent. Set require_consent=True to confirm you have authorization.")

    payloads = payloads or DEFAULT_PAYLOADS
    encodings = encodings or ["raw", "url", "html"]
    results = []
    tasks = []

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for item in items:
            params = item.get("query_params", []) or []
            forms = item.get("form_inputs", []) or []
            for p in params:
                for ptype in ("marker", "xss_test", "redirect_test"):
                    for tmpl in payloads.get(ptype, []):
                        tasks.append(ex.submit(
                            test_param_reflection_task,
                            item, p, tmpl, "GET", None, None, True, timeout,
                            encodings, max_variants, log_dir, max_save_body
                        ))
            for fi in forms:
                for tmpl in payloads.get("marker", []):
                    tasks.append(ex.submit(
                        test_param_reflection_task,
                        item, fi, tmpl, "POST", {}, None, True, timeout,
                        encodings, max_variants, log_dir, max_save_body
                    ))

        for future in as_completed(tasks):
            try:
                r = future.result()
            except Exception as e:
                r = {"error": str(e)}
            results.append(r)
            time.sleep(delay_between)

    return results
