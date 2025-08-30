import os
import subprocess
import time
import shutil
import requests

# Trusted repositories to clone (shallow)
REPOS = {
    "SecLists": "https://github.com/danielmiessler/SecLists.git",
    "PayloadsAllTheThings": "https://github.com/swisskyrepo/PayloadsAllTheThings.git"
}

DEFAULT_BASE_DIR = "payloads"  # changeable via CLI


def ensure_dir(path):
    if not path:
        return
    os.makedirs(path, exist_ok=True)


def has_git():
    try:
        subprocess.check_call(["git", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False


def shallow_clone(repo_url, dest):
    """
    Clone repo_url into dest with --depth 1. If dest exists, skip.
    """
    ensure_dir(os.path.dirname(dest))
    if os.path.exists(dest) and os.path.isdir(dest):
        # already cloned
        return dest
    if not has_git():
        raise RuntimeError("git is not available on PATH. Install git (apt install git) to use --sync-payloads.")
    try:
        subprocess.check_call(["git", "clone", "--depth", "1", repo_url, dest])
        return dest
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"git clone failed for {repo_url}: {e}")


def sync_default_repos(base_dir=DEFAULT_BASE_DIR):
    """
    Clone SecLists and PayloadsAllTheThings (shallow) into base_dir/<reponame>.
    Returns dict of repo_name -> path
    """
    ensure_dir(base_dir)
    out = {}
    for name, url in REPOS.items():
        dest = os.path.join(base_dir, name)
        try:
            shallow_clone(url, dest)
            out[name] = dest
        except Exception as e:
            # continue but surface error
            out[name] = {"error": str(e)}
    # write simple timestamp for caching awareness
    try:
        with open(os.path.join(base_dir, ".last_sync"), "w") as fh:
            fh.write(str(int(time.time())))
    except Exception:
        pass
    return out


def fetch_raw_to(path_url, dest_path, timeout=30):
    """
    Download a single raw URL to dest_path (fallback if git missing).
    """
    ensure_dir(os.path.dirname(dest_path))
    r = requests.get(path_url, timeout=timeout)
    r.raise_for_status()
    with open(dest_path, "wb") as fh:
        fh.write(r.content)
    return dest_path


def list_payload_files(base_dir=DEFAULT_BASE_DIR, ext_list=(".txt", ".list", ".payload", ".csv")):
    """
    Walk base_dir and return list of file paths with provided extensions.
    """
    out = []
    if not os.path.exists(base_dir):
        return out
    for root, _, files in os.walk(base_dir):
        for f in files:
            if f.lower().endswith(ext_list):
                out.append(os.path.join(root, f))
    return out


def categorize_filename(filename):
    """
    Heuristic categorization by filename substring.
    Returns a short category like 'xss','sqli','lfi','ssrf','redirect','generic'
    """
    n = filename.lower()
    if "xss" in n or "cross" in n:
        return "xss"
    if "sqli" in n or "sql" in n or "sql-injection" in n:
        return "sqli"
    if "lfi" in n or "traversal" in n or "directory" in n:
        return "lfi"
    if "ssrf" in n or "169.254.169.254" in n:
        return "ssrf"
    if "redirect" in n or "openredirect" in n or "redirects" in n:
        return "redirect"
    if "payload" in n or "fuzz" in n or "wordlist" in n:
        return "generic"
    return "generic"


def load_payload_lists_from_dir(base_dir=DEFAULT_BASE_DIR, extensions=(".txt", ".list", ".payload", ".csv")):
    """
    Return a dict mapping categories to lists of payload strings.
    Example output: { "xss": [...], "sqli": [...], "redirect": [...], "generic": [...] }
    """
    payloads = {}
    files = list_payload_files(base_dir, ext_list=extensions)
    for path in files:
        fname = os.path.basename(path)
        cat = categorize_filename(fname)
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                lines = [line.strip() for line in fh if line.strip() and not line.strip().startswith("#")]
            if not lines:
                continue
            payloads.setdefault(cat, []).extend(lines)
        except Exception:
            continue

    # normalize: deduplicate and lowercase where appropriate (but keep original for URL payloads)
    for k, v in payloads.items():
        # keep unique order-preserving
        seen = set()
        uniq = []
        for p in v:
            if p in seen:
                continue
            seen.add(p)
            uniq.append(p)
        payloads[k] = uniq
    return payloads


def build_active_payload_map(payloads_map, base_marker=None):
    """
    Convert categorized payloads_map into the shape expected by active_injector:
    { "marker": [...], "xss_test": [...], "redirect_test": [...] }
    base_marker: optional custom marker fallback
    """
    out = {}
    # marker(s) - unique sentinel(s)
    if base_marker:
        out["marker"] = [base_marker]
    else:
        out["marker"] = ["INJECT-MARKER-PRYANSU-@@ID@@"]

    # xss_test: pick from 'xss' and 'generic'
    xss_list = payloads_map.get("xss", []) + payloads_map.get("generic", [])
    out["xss_test"] = xss_list[:200] if len(xss_list) > 200 else xss_list

    # redirect_test: prefer payloads in redirect category or full-URL-looking items
    redirect_candidates = payloads_map.get("redirect", [])[:200] if payloads_map.get("redirect") else []
    # also try to pick items that look like URLs from generic
    for g in payloads_map.get("generic", []):
        if g.startswith("http://") or g.startswith("https://"):
            redirect_candidates.append(g)
    out["redirect_test"] = redirect_candidates[:200]

    # sqli/lfi/ssrf can be present in payloads_map too
    out["sqli"] = payloads_map.get("sqli", [])[:200] if payloads_map.get("sqli") else []
    out["lfi"] = payloads_map.get("lfi", [])[:200] if payloads_map.get("lfi") else []
    out["ssrf"] = payloads_map.get("ssrf", [])[:200] if payloads_map.get("ssrf") else []

    return out
