import requests
import re
from concurrent.futures import ThreadPoolExecutor, as_completed


SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']([a-zA-Z0-9\-_]{16,})["\']', "API Key"),
    (r'(?i)(secret[_-]?key|secret)\s*[=:]\s*["\']([a-zA-Z0-9\-_]{16,})["\']', "Secret Key"),
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']', "Hardcoded Password"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
    (r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']([^"\']{20,})["\']', "AWS Secret Key"),
    (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key"),
    (r'(?i)firebase[_-]?api[_-]?key\s*[=:]\s*["\']([^"\']+)["\']', "Firebase API Key"),
    (r'sk_live_[0-9a-zA-Z]{24,}', "Stripe Live Secret Key"),
    (r'pk_live_[0-9a-zA-Z]{24,}', "Stripe Live Publishable Key"),
    (r'AC[a-z0-9]{32}', "Twilio Account SID"),
    (r'(?i)twilio.*["\']([a-z0-9]{32})["\']', "Twilio Auth Token"),
    (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----', "Private Key"),
    (r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+', "JWT Token"),
    (r'(?i)(bearer\s+)([a-zA-Z0-9\-_.~+/]+=*)', "Bearer Token"),
    (r'(?i)(auth[_-]?token|authorization[_-]?token)\s*[=:]\s*["\']([^"\']{16,})["\']', "Auth Token"),
    (r'(?i)mongodb(\+srv)?://[^\s"\']+', "MongoDB Connection String"),
    (r'(?i)mysql://[^\s"\']+', "MySQL Connection String"),
    (r'(?i)postgres(ql)?://[^\s"\']+', "PostgreSQL Connection String"),
    (r'(?i)(internal|localhost|127\.0\.0\.1|192\.168\.[0-9]+\.[0-9]+|10\.[0-9]+\.[0-9]+\.[0-9]+)[^\s"\']{0,50}', "Internal URL/IP"),
]


def analyze_js_file(url, session):
    secrets = []
    try:
        resp = session.get(url, timeout=8, verify=False)
        if resp.status_code != 200:
            return secrets

        content = resp.text
        for pattern, label in SECRET_PATTERNS:
            matches = re.findall(pattern, content)
            for match in matches:
                value = match if isinstance(match, str) else (match[-1] if match else "")
                if len(value) > 4:
                    secrets.append({
                        "url": url,
                        "type": label,
                        "value": value[:60] + "..." if len(value) > 60 else value,
                    })
    except Exception:
        pass
    return secrets


def scan_js(crawl_data, session, callback=None):
    findings = []
    js_files = crawl_data.get("js_files", [])

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(analyze_js_file, url, session): url for url in js_files}
        for future in as_completed(futures):
            secrets = future.result()
            for secret in secrets:
                finding = {
                    "name": f"Secret Found in JS: {secret['type']}",
                    "severity": "CRITICAL",
                    "url": secret["url"],
                    "evidence": f"{secret['type']} found: {secret['value']}",
                    "parameter": "JavaScript file",
                    "description": f"A {secret['type']} was found hardcoded in a public JavaScript file. This allows anyone to access the associated service.",
                    "module": "JS Analyzer",
                }
                findings.append(finding)
                if callback:
                    callback("finding", finding)

    return findings
