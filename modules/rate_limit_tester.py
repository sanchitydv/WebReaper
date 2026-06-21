import requests
import time
from urllib.parse import urljoin


LOGIN_KEYWORDS = ["login", "signin", "sign-in", "auth", "authenticate", "session"]


def find_login_forms(crawl_data):
    login_forms = []
    for form in crawl_data.get("forms", []):
        url_lower = form["url"].lower()
        has_password = any(f.get("type") == "password" for f in form["fields"])
        is_login_url = any(kw in url_lower for kw in LOGIN_KEYWORDS)
        if has_password or is_login_url:
            login_forms.append(form)
    return login_forms


def test_rate_limit(url, method, data, session, attempts=20):
    blocked_at = None
    for i in range(attempts):
        try:
            if method == "post":
                resp = session.post(url, data=data, timeout=6, verify=False, allow_redirects=False)
            else:
                resp = session.get(url, params=data, timeout=6, verify=False, allow_redirects=False)

            if resp.status_code == 429:
                blocked_at = i + 1
                break
            if resp.status_code in (423, 403):
                blocked_at = i + 1
                break
            body_lower = resp.text.lower()
            if any(kw in body_lower for kw in ["too many", "rate limit", "blocked", "locked", "captcha", "slow down"]):
                blocked_at = i + 1
                break
        except Exception:
            break

    return blocked_at


def scan_rate_limit(crawl_data, session, base_url, callback=None):
    findings = []
    login_forms = find_login_forms(crawl_data)

    if not login_forms:
        login_url = urljoin(base_url, "/login")
        try:
            resp = session.get(login_url, timeout=5, verify=False)
            if resp.status_code == 200:
                login_forms.append({
                    "url": login_url,
                    "method": "post",
                    "fields": [
                        {"name": "username", "type": "text", "value": ""},
                        {"name": "password", "type": "password", "value": ""},
                    ],
                })
        except Exception:
            pass

    tested = set()
    for form in login_forms[:3]:
        if form["url"] in tested:
            continue
        tested.add(form["url"])

        data = {}
        for field in form["fields"]:
            if field["type"] == "password":
                data[field["name"]] = "wrongpassword123"
            else:
                data[field["name"]] = "testuser@test.com"

        blocked_at = test_rate_limit(form["url"], form["method"], data, session)

        if blocked_at is None:
            finding = {
                "name": "No Rate Limiting on Login",
                "severity": "HIGH",
                "url": form["url"],
                "evidence": f"Sent 20 rapid login requests with no rate limiting or lockout detected",
                "parameter": "login form",
                "description": "The login endpoint does not implement rate limiting, allowing brute-force password attacks.",
                "module": "Rate Limit Tester",
            }
            findings.append(finding)
            if callback:
                callback("finding", finding)
        else:
            findings.append({
                "name": "Rate Limiting Detected",
                "severity": "INFO",
                "url": form["url"],
                "evidence": f"Rate limiting triggered after {blocked_at} attempts",
                "parameter": "login form",
                "description": "Rate limiting is in place.",
                "module": "Rate Limit Tester",
            })

    return findings
