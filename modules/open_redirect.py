from urllib.parse import urlparse, parse_qs, urlencode, urljoin
import requests


REDIRECT_PARAMS = [
    "next", "url", "redirect", "redirect_url", "redirect_uri",
    "return", "return_url", "returnUrl", "returnto", "return_to",
    "dest", "destination", "to", "goto", "go", "forward",
    "continue", "target", "rurl", "redir", "ref", "out",
    "view", "loginto", "image_url", "callback",
]

EVIL_URL = "https://evil-redirect-test.com"


def scan_open_redirect(crawl_data, session, callback=None):
    findings = []
    tested = set()

    def test_url(url, param, value):
        key = (url, param)
        if key in tested:
            return None
        tested.add(key)
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [EVIL_URL]
        test_url = parsed.scheme + "://" + parsed.netloc + parsed.path + "?" + urlencode(params, doseq=True)
        try:
            resp = session.get(test_url, timeout=8, allow_redirects=False, verify=False)
            location = resp.headers.get("Location", "")
            if location and ("evil-redirect-test" in location or location.startswith("https://evil")):
                return {
                    "name": "Open Redirect",
                    "severity": "MEDIUM",
                    "url": url,
                    "evidence": f"Parameter '{param}' redirects to external URL: {location}",
                    "parameter": param,
                    "description": "The application redirects users to attacker-controlled URLs, enabling phishing attacks.",
                    "module": "Open Redirect",
                }
        except Exception:
            pass
        return None

    for url_data in crawl_data.get("url_params", []):
        for param in url_data["params"]:
            if param.lower() in REDIRECT_PARAMS:
                result = test_url(url_data["url"], param, url_data["params"][param])
                if result:
                    findings.append(result)
                    if callback:
                        callback("finding", result)

    for form in crawl_data.get("forms", []):
        for field in form["fields"]:
            if field["name"].lower() in REDIRECT_PARAMS:
                key = (form["url"], field["name"])
                if key not in tested:
                    tested.add(key)
                    data = {f["name"]: f["value"] or "test" for f in form["fields"]}
                    data[field["name"]] = EVIL_URL
                    try:
                        if form["method"] == "post":
                            resp = session.post(form["url"], data=data, timeout=8, allow_redirects=False, verify=False)
                        else:
                            resp = session.get(form["url"], params=data, timeout=8, allow_redirects=False, verify=False)
                        location = resp.headers.get("Location", "")
                        if location and "evil-redirect-test" in location:
                            finding = {
                                "name": "Open Redirect",
                                "severity": "MEDIUM",
                                "url": form["url"],
                                "evidence": f"Form field '{field['name']}' redirects to: {location}",
                                "parameter": field["name"],
                                "description": "Form submission redirects users to attacker-controlled URLs.",
                                "module": "Open Redirect",
                            }
                            findings.append(finding)
                            if callback:
                                callback("finding", finding)
                    except Exception:
                        pass

    return findings
