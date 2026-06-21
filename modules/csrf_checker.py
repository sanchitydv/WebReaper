import re


CSRF_TOKEN_NAMES = [
    "csrf", "csrftoken", "_token", "authenticity_token", "csrf_token",
    "__requestverificationtoken", "nonce", "_csrf", "xsrf",
    "csrfmiddlewaretoken", "anti_csrf", "anticsrf", "verify_token",
]


def has_csrf_token(form):
    for field in form.get("fields", []):
        name = field.get("name", "").lower()
        if any(token in name for token in CSRF_TOKEN_NAMES):
            return True
        if field.get("type") == "hidden" and field.get("value", ""):
            value = field["value"]
            if len(value) >= 16 and re.match(r"^[a-zA-Z0-9+/=_\-]+$", value):
                return True
    return False


def scan_csrf(crawl_data, callback=None):
    findings = []
    checked = set()

    for form in crawl_data.get("forms", []):
        if form.get("method", "get").lower() != "post":
            continue

        key = form["url"]
        if key in checked:
            continue
        checked.add(key)

        if not has_csrf_token(form):
            finding = {
                "name": "Missing CSRF Token",
                "severity": "HIGH",
                "url": form["url"],
                "evidence": f"POST form at '{form['url']}' has no CSRF token in fields: {[f['name'] for f in form['fields']]}",
                "parameter": "form",
                "description": "The form does not include a CSRF token, allowing attackers to forge requests on behalf of authenticated users.",
                "module": "CSRF Checker",
            }
            findings.append(finding)
            if callback:
                callback("finding", finding)

    return findings
