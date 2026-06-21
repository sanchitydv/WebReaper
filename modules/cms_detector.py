import requests
from urllib.parse import urljoin
import re
import urllib3
urllib3.disable_warnings()


CMS_SIGNATURES = {
    "WordPress": {
        "paths": ["/wp-login.php", "/wp-admin/", "/wp-content/", "/wp-json/"],
        "headers": {"X-Pingback": None},
        "meta": [r'<meta name="generator" content="WordPress ([^"]+)"'],
        "body": ["wp-content", "wp-includes", "wordpress"],
    },
    "Drupal": {
        "paths": ["/user/login", "/CHANGELOG.txt", "/core/CHANGELOG.txt"],
        "headers": {"X-Generator": "Drupal", "X-Drupal-Cache": None},
        "meta": [r'<meta name="Generator" content="Drupal ([^"]+)"'],
        "body": ["drupal", "Drupal.settings", "/sites/default/files"],
    },
    "Joomla": {
        "paths": ["/administrator/", "/components/", "/modules/"],
        "headers": {},
        "meta": [r'<meta name="generator" content="Joomla! ([^"]+)"'],
        "body": ["joomla", "/components/com_", "Joomla!"],
    },
    "Magento": {
        "paths": ["/admin/", "/downloader/", "/skin/frontend/"],
        "headers": {},
        "meta": [],
        "body": ["Mage.Cookies", "mage/cookies", "magento"],
    },
    "Shopify": {
        "paths": [],
        "headers": {"X-ShopId": None, "X-ShopifyRequestId": None},
        "meta": [],
        "body": ["cdn.shopify.com", "Shopify.theme"],
    },
    "Laravel": {
        "paths": ["/laravel_session"],
        "headers": {},
        "meta": [],
        "body": ["laravel_session", "XSRF-TOKEN", "laravel"],
    },
}


def detect_version(cms_name, resp_text, session, base_url):
    version = None
    if cms_name == "WordPress":
        m = re.search(r'<meta name="generator" content="WordPress ([^"]+)"', resp_text, re.I)
        if m:
            version = m.group(1)
        else:
            try:
                r = session.get(urljoin(base_url, "/wp-json/"), timeout=5, verify=False)
                m2 = re.search(r'"version":"([^"]+)"', r.text)
                if m2:
                    version = m2.group(1)
            except Exception:
                pass
    elif cms_name == "Drupal":
        try:
            r = session.get(urljoin(base_url, "/CHANGELOG.txt"), timeout=5, verify=False)
            m = re.search(r"Drupal ([0-9.]+)", r.text)
            if m:
                version = m.group(1)
        except Exception:
            pass
    elif cms_name == "Joomla":
        m = re.search(r'<meta name="generator" content="Joomla! ([^"]+)"', resp_text, re.I)
        if m:
            version = m.group(1)
    return version


def scan_cms(base_url, session, callback=None):
    findings = []
    try:
        resp = session.get(base_url, timeout=8, verify=False)
        body = resp.text
        headers = resp.headers
    except Exception:
        return findings

    detected = []
    for cms_name, sigs in CMS_SIGNATURES.items():
        score = 0

        for kw in sigs["body"]:
            if kw.lower() in body.lower():
                score += 1

        for hdr, val in sigs["headers"].items():
            if hdr in headers:
                if val is None or val.lower() in headers[hdr].lower():
                    score += 2

        for pattern in sigs["meta"]:
            if re.search(pattern, body, re.I):
                score += 2

        if score >= 2:
            detected.append((cms_name, score))

    for cms_name, _ in detected:
        version = detect_version(cms_name, body, session, base_url)
        finding = {
            "name": f"CMS Detected: {cms_name}",
            "severity": "INFO",
            "url": base_url,
            "evidence": f"{cms_name} detected" + (f" version {version}" if version else " (version unknown)"),
            "parameter": "CMS",
            "description": f"The site runs {cms_name}. Version info can be used to find applicable CVEs.",
            "module": "CMS Detector",
            "cms_name": cms_name,
            "cms_version": version,
        }
        findings.append(finding)
        if callback:
            callback("finding", finding)

    return findings
