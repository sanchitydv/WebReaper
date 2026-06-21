import requests
from urllib.parse import urljoin
import os
import json
from concurrent.futures import ThreadPoolExecutor, as_completed


WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "..", "wordlists", "api_paths.txt")


def load_paths():
    try:
        with open(WORDLIST_PATH) as f:
            return [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        return ["api/v1/users", "graphql", "swagger-ui", "api-docs"]


def check_api_path(base_url, path, session):
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    try:
        resp = session.get(url, timeout=6, verify=False)
        if resp.status_code in (200, 201):
            content_type = resp.headers.get("Content-Type", "")
            is_json = "json" in content_type or resp.text.strip().startswith(("{", "["))

            if is_json:
                try:
                    data = json.loads(resp.text)
                    has_data = bool(data)
                except Exception:
                    has_data = len(resp.text) > 50

                severity = "HIGH" if has_data else "MEDIUM"
                return {
                    "name": "Exposed API Endpoint",
                    "severity": severity,
                    "url": url,
                    "evidence": f"Endpoint returns {resp.status_code} with JSON data ({len(resp.text)} bytes)",
                    "parameter": path,
                    "description": f"The API endpoint '{path}' is publicly accessible without authentication and returns data.",
                    "module": "API Discovery",
                }

            if any(kw in resp.text.lower() for kw in ["swagger", "openapi", "graphql", "api"]):
                return {
                    "name": "API Documentation Exposed",
                    "severity": "MEDIUM",
                    "url": url,
                    "evidence": f"API documentation page found at {url}",
                    "parameter": path,
                    "description": "Publicly accessible API documentation reveals endpoint structure, parameters, and authentication details.",
                    "module": "API Discovery",
                }
    except Exception:
        pass
    return None


def scan_api(base_url, session, callback=None):
    findings = []
    paths = load_paths()

    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(check_api_path, base_url, path, session): path for path in paths}
        for future in as_completed(futures):
            result = future.result()
            if result:
                findings.append(result)
                if callback:
                    callback("finding", result)

    return findings
