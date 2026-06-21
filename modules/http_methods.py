import requests
from urllib.parse import urlparse


DANGEROUS_METHODS = ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"]


def test_methods(url, session):
    results = {}
    try:
        resp = session.options(url, timeout=6, verify=False)
        allow_header = resp.headers.get("Allow", "")
        if allow_header:
            results["allow_header"] = allow_header
            results["allowed_methods"] = [m.strip() for m in allow_header.split(",")]
    except Exception:
        pass

    try:
        resp = session.request("TRACE", url, timeout=6, verify=False)
        if resp.status_code in (200, 405):
            results["trace"] = resp.status_code
            results["trace_body"] = resp.text[:200]
    except Exception:
        pass

    return results


def scan_http_methods(crawl_data, session, base_url, callback=None):
    findings = []
    checked = set()
    pages = crawl_data.get("pages", [])

    urls_to_test = [base_url]
    for page in pages[:10]:
        if page["url"] not in checked:
            urls_to_test.append(page["url"])

    for url in urls_to_test[:10]:
        if url in checked:
            continue
        checked.add(url)

        results = test_methods(url, session)
        allowed = results.get("allowed_methods", [])

        for method in DANGEROUS_METHODS:
            if method in allowed:
                severity = "CRITICAL" if method in ("DELETE", "PUT") else "MEDIUM"
                finding = {
                    "name": f"Dangerous HTTP Method Allowed: {method}",
                    "severity": severity,
                    "url": url,
                    "evidence": f"OPTIONS response Allow header includes: {method} (full: {results.get('allow_header', 'N/A')})",
                    "parameter": method,
                    "description": f"The {method} method is allowed on this endpoint. {method} could allow data modification or deletion by attackers.",
                    "module": "HTTP Methods",
                }
                findings.append(finding)
                if callback:
                    callback("finding", finding)

        trace_status = results.get("trace")
        if trace_status == 200:
            finding = {
                "name": "HTTP TRACE Method Enabled",
                "severity": "MEDIUM",
                "url": url,
                "evidence": f"TRACE request returned 200. Response snippet: {results.get('trace_body', '')[:100]}",
                "parameter": "TRACE",
                "description": "TRACE allows Cross-Site Tracing (XST) attacks that can steal cookies even with HttpOnly set.",
                "module": "HTTP Methods",
            }
            findings.append(finding)
            if callback:
                callback("finding", finding)

    return findings
