import requests
from urllib.parse import urlencode, urlparse, parse_qs, urljoin
import os
import html


PAYLOADS_PATH = os.path.join(os.path.dirname(__file__), "..", "wordlists", "xss_payloads.txt")
MARKER = "WEBREAPER_XSS_TEST"


def load_payloads():
    try:
        with open(PAYLOADS_PATH) as f:
            return [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        return ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]


def is_reflected(payload, response_text):
    decoded = html.unescape(response_text)
    return payload in response_text or payload in decoded


def scan_xss(crawl_data, session, callback=None):
    findings = []
    payloads = load_payloads()
    tested = set()

    def test_form(form, payload):
        data = {}
        for field in form["fields"]:
            if field["type"] in ("submit", "hidden", "button"):
                data[field["name"]] = field["value"] or "test"
            else:
                data[field["name"]] = payload
        key = (form["url"], form["method"], payload[:20])
        if key in tested:
            return
        tested.add(key)
        try:
            if form["method"] == "post":
                resp = session.post(form["url"], data=data, timeout=8, verify=False)
            else:
                resp = session.get(form["url"], params=data, timeout=8, verify=False)
            for field in form["fields"]:
                if field["type"] not in ("submit", "hidden", "button"):
                    if is_reflected(payload, resp.text):
                        return {
                            "name": "Cross-Site Scripting (XSS)",
                            "severity": "HIGH",
                            "url": form["url"],
                            "evidence": f"Payload reflected in response via parameter '{field['name']}'",
                            "parameter": field["name"],
                            "description": "User input is reflected in the page without sanitization, allowing script injection.",
                            "module": "XSS Scanner",
                        }
        except Exception:
            pass
        return None

    def test_url_param(url_data, payload):
        parsed = urlparse(url_data["url"])
        for param in url_data["params"]:
            new_params = dict(url_data["params"])
            new_params[param] = payload
            key = (url_data["url"], param, payload[:20])
            if key in tested:
                continue
            tested.add(key)
            try:
                resp = session.get(parsed.scheme + "://" + parsed.netloc + parsed.path, params=new_params, timeout=8, verify=False)
                if is_reflected(payload, resp.text):
                    return {
                        "name": "Cross-Site Scripting (XSS)",
                        "severity": "HIGH",
                        "url": url_data["url"],
                        "evidence": f"Payload reflected via URL parameter '{param}'",
                        "parameter": param,
                        "description": "URL parameter is reflected in the page without sanitization.",
                        "module": "XSS Scanner",
                    }
            except Exception:
                pass
        return None

    for payload in payloads:
        for form in crawl_data.get("forms", []):
            result = test_form(form, payload)
            if result:
                findings.append(result)
                if callback:
                    callback("finding", result)

        for url_data in crawl_data.get("url_params", []):
            result = test_url_param(url_data, payload)
            if result:
                findings.append(result)
                if callback:
                    callback("finding", result)

    return findings
