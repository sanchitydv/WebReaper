import requests
from urllib.parse import urljoin
import os
from concurrent.futures import ThreadPoolExecutor, as_completed


WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "..", "wordlists", "sensitive_paths.txt")

SENSITIVE_KEYWORDS = [
    "password", "secret", "api_key", "apikey", "token", "private",
    "database", "db_pass", "mysql", "mongodb", "aws_access", "aws_secret",
    "-----BEGIN", "config", "credential",
]


def load_paths():
    try:
        with open(WORDLIST_PATH) as f:
            return [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        return [".env", ".git/config", "phpinfo.php", "admin/"]


def check_path(base_url, path, session):
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    try:
        resp = session.get(url, timeout=6, allow_redirects=False, verify=False)
        if resp.status_code == 200:
            severity = "HIGH"
            detail = f"HTTP 200 — file accessible"
            content_lower = resp.text.lower()
            if any(kw.lower() in content_lower for kw in SENSITIVE_KEYWORDS):
                severity = "CRITICAL"
                detail = f"HTTP 200 — contains sensitive data (credentials/keys detected)"
            return {
                "name": "Sensitive File Exposed",
                "severity": severity,
                "url": url,
                "evidence": detail,
                "parameter": path,
                "description": f"The file '{path}' is publicly accessible and may expose sensitive information.",
                "module": "Sensitive Files",
            }
        if resp.status_code == 403:
            return {
                "name": "Restricted File Found (403)",
                "severity": "LOW",
                "url": url,
                "evidence": "HTTP 403 — file exists but access is restricted",
                "parameter": path,
                "description": f"The file '{path}' exists but returns 403. Access controls may be bypassable.",
                "module": "Sensitive Files",
            }
    except Exception:
        pass
    return None


def scan_sensitive_files(base_url, session, callback=None):
    findings = []
    paths = load_paths()

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_path, base_url, path, session): path for path in paths}
        for future in as_completed(futures):
            result = future.result()
            if result:
                findings.append(result)
                if callback:
                    callback("finding", result)

    return findings
