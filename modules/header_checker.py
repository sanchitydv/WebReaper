import requests
import re
import urllib3
urllib3.disable_warnings()


SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "Forces HTTPS connections. Without it, users can be downgraded to HTTP.",
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "Prevents XSS and data injection. Without it, injected scripts run freely.",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "Prevents clickjacking by blocking page from being embedded in iframes.",
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "description": "Prevents MIME-type sniffing which can lead to drive-by downloads.",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "Controls how much referrer info is sent with requests.",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "description": "Controls browser features (camera, mic, geolocation) accessible to the page.",
    },
    "X-XSS-Protection": {
        "severity": "LOW",
        "description": "Legacy XSS filter for older browsers.",
    },
}

CSP_UNSAFE = ["'unsafe-inline'", "'unsafe-eval'", "data:", "*"]


def scan_headers(base_url, session, callback=None):
    findings = []
    try:
        resp = session.get(base_url, timeout=8, verify=False, allow_redirects=True)
        headers = resp.headers

        for header, meta in SECURITY_HEADERS.items():
            if header not in headers:
                finding = {
                    "name": f"Missing Security Header: {header}",
                    "severity": meta["severity"],
                    "url": base_url,
                    "evidence": f"Header '{header}' is not present in the HTTP response",
                    "parameter": header,
                    "description": meta["description"],
                    "module": "Security Headers",
                }
                findings.append(finding)
                if callback:
                    callback("finding", finding)

        csp = headers.get("Content-Security-Policy", "")
        if csp:
            for unsafe in CSP_UNSAFE:
                if unsafe in csp:
                    finding = {
                        "name": "Weak Content-Security-Policy",
                        "severity": "MEDIUM",
                        "url": base_url,
                        "evidence": f"CSP contains unsafe directive: {unsafe}",
                        "parameter": "Content-Security-Policy",
                        "description": f"The CSP policy includes '{unsafe}' which weakens XSS protections.",
                        "module": "Security Headers",
                    }
                    findings.append(finding)
                    if callback:
                        callback("finding", finding)
                    break

        server = headers.get("Server", "")
        if server and any(char.isdigit() for char in server):
            finding = {
                "name": "Server Version Disclosure",
                "severity": "LOW",
                "url": base_url,
                "evidence": f"Server header reveals version: '{server}'",
                "parameter": "Server",
                "description": "Exposing the server version helps attackers identify applicable CVEs.",
                "module": "Security Headers",
            }
            findings.append(finding)
            if callback:
                callback("finding", finding)

        x_powered = headers.get("X-Powered-By", "")
        if x_powered:
            finding = {
                "name": "Technology Disclosure via X-Powered-By",
                "severity": "LOW",
                "url": base_url,
                "evidence": f"X-Powered-By header reveals: '{x_powered}'",
                "parameter": "X-Powered-By",
                "description": "Revealing the technology stack helps attackers target known vulnerabilities.",
                "module": "Security Headers",
            }
            findings.append(finding)
            if callback:
                callback("finding", finding)

    except Exception as e:
        findings.append({
            "name": "Header Check Error",
            "severity": "INFO",
            "url": base_url,
            "evidence": str(e),
            "parameter": "N/A",
            "description": "Could not retrieve headers.",
            "module": "Security Headers",
        })

    return findings
