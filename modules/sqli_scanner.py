import requests
from urllib.parse import urlparse
import os
import time
import re


PAYLOADS_PATH = os.path.join(os.path.dirname(__file__), "..", "wordlists", "sqli_payloads.txt")

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query",
    "supplied argument is not a valid mysql",
    "ora-01756",
    "ora-00933",
    "microsoft ole db provider for sql server",
    "odbc microsoft access driver",
    "sqlite_master",
    "syntax error",
    "unexpected end of sql command",
    "invalid query",
    "sql command not properly ended",
    "division by zero",
    "invalid column name",
    "column count doesn't match",
]


def load_payloads():
    try:
        with open(PAYLOADS_PATH) as f:
            return [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        return ["'", "\" OR 1=1--", "' OR '1'='1"]


def has_sql_error(text):
    lower = text.lower()
    return any(err in lower for err in SQL_ERRORS)


def scan_sqli(crawl_data, session, callback=None):
    findings = []
    payloads = load_payloads()
    tested = set()

    def test_input(url, method, params, param_name, payload):
        key = (url, param_name, payload[:15])
        if key in tested:
            return None
        tested.add(key)
        test_params = dict(params)
        test_params[param_name] = payload
        try:
            start = time.time()
            if method == "post":
                resp = session.post(url, data=test_params, timeout=12, verify=False)
            else:
                resp = session.get(url, params=test_params, timeout=12, verify=False)
            elapsed = time.time() - start

            if has_sql_error(resp.text):
                return {
                    "name": "SQL Injection",
                    "severity": "CRITICAL",
                    "url": url,
                    "evidence": f"SQL error detected in response for parameter '{param_name}' with payload: {payload}",
                    "parameter": param_name,
                    "description": "The application returns SQL error messages, indicating unsanitized input is passed to a database query.",
                    "module": "SQLi Scanner",
                }
            if "SLEEP" in payload.upper() and elapsed >= 4:
                return {
                    "name": "Blind SQL Injection (Time-Based)",
                    "severity": "CRITICAL",
                    "url": url,
                    "evidence": f"Response delayed {elapsed:.1f}s for parameter '{param_name}' with sleep payload",
                    "parameter": param_name,
                    "description": "Application responded with a delay matching the injected SLEEP payload, indicating blind SQL injection.",
                    "module": "SQLi Scanner",
                }
        except Exception:
            pass
        return None

    for payload in payloads:
        for form in crawl_data.get("forms", []):
            params = {f["name"]: f["value"] or "test" for f in form["fields"]}
            for field in form["fields"]:
                if field["type"] not in ("submit", "hidden", "button"):
                    result = test_input(form["url"], form["method"], params, field["name"], payload)
                    if result:
                        findings.append(result)
                        if callback:
                            callback("finding", result)

        for url_data in crawl_data.get("url_params", []):
            parsed = urlparse(url_data["url"])
            base = parsed.scheme + "://" + parsed.netloc + parsed.path
            for param in url_data["params"]:
                result = test_input(base, "get", url_data["params"], param, payload)
                if result:
                    findings.append(result)
                    if callback:
                        callback("finding", result)

    return findings
