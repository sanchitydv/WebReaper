import requests
from urllib.parse import urlparse


BYPASS_HEADERS = [
    {"X-Original-URL": "/{path}"},
    {"X-Rewrite-URL": "/{path}"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "localhost"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Host": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
]

PATH_BYPASSES = [
    "/{path}/",
    "/{path}//",
    "//{path}",
    "/./{path}",
    "/{path}/.",
    "/{path}%20",
    "/{path}%09",
    "/{path}?",
    "/{path}?anythingatall",
    "/{path}#",
    "/{Path}",
    "/%2f{path}",
]


def get_path(url):
    return urlparse(url).path.lstrip("/")


def scan_access_control(crawl_data, session, base_url, callback=None):
    findings = []
    parsed_base = urlparse(base_url)
    origin = parsed_base.scheme + "://" + parsed_base.netloc

    forbidden_pages = [p["url"] for p in crawl_data.get("pages", []) if p.get("status") == 403]

    for url in forbidden_pages[:10]:
        path = get_path(url)
        if not path:
            continue

        for header_dict in BYPASS_HEADERS:
            headers = {}
            for k, v in header_dict.items():
                headers[k] = v.replace("{path}", "/" + path)
            try:
                resp = session.get(url, headers=headers, timeout=6, verify=False)
                if resp.status_code == 200:
                    finding = {
                        "name": "Broken Access Control — Header Bypass",
                        "severity": "CRITICAL",
                        "url": url,
                        "evidence": f"403 bypassed using header: {headers}",
                        "parameter": str(headers),
                        "description": "A 403 Forbidden page was bypassed by manipulating HTTP headers, indicating improper access control.",
                        "module": "Access Control",
                    }
                    findings.append(finding)
                    if callback:
                        callback("finding", finding)
                    break
            except Exception:
                pass

        for pattern in PATH_BYPASSES:
            bypass_path = pattern.replace("{path}", path).replace("{Path}", path.capitalize())
            bypass_url = origin + bypass_path
            try:
                resp = session.get(bypass_url, timeout=6, verify=False)
                if resp.status_code == 200:
                    finding = {
                        "name": "Broken Access Control — Path Bypass",
                        "severity": "CRITICAL",
                        "url": url,
                        "evidence": f"403 bypassed using path manipulation: {bypass_url}",
                        "parameter": bypass_url,
                        "description": "A restricted URL was accessed using path manipulation techniques.",
                        "module": "Access Control",
                    }
                    findings.append(finding)
                    if callback:
                        callback("finding", finding)
                    break
            except Exception:
                pass

    return findings
