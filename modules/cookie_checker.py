def scan_cookies(crawl_data, callback=None):
    findings = []

    for cookie in crawl_data.get("cookies", []):
        name = cookie.get("name", "unknown")

        if not cookie.get("http_only"):
            finding = {
                "name": "Cookie Missing HttpOnly Flag",
                "severity": "MEDIUM",
                "url": f"Cookie: {name}",
                "evidence": f"Cookie '{name}' does not have the HttpOnly flag set",
                "parameter": name,
                "description": "Without HttpOnly, the cookie can be accessed via JavaScript, enabling session theft via XSS.",
                "module": "Cookie Security",
            }
            findings.append(finding)
            if callback:
                callback("finding", finding)

        if not cookie.get("secure"):
            finding = {
                "name": "Cookie Missing Secure Flag",
                "severity": "MEDIUM",
                "url": f"Cookie: {name}",
                "evidence": f"Cookie '{name}' does not have the Secure flag set",
                "parameter": name,
                "description": "Without the Secure flag, the cookie can be transmitted over HTTP, exposing it to interception.",
                "module": "Cookie Security",
            }
            findings.append(finding)
            if callback:
                callback("finding", finding)

        same_site = cookie.get("same_site")
        if not same_site or same_site.lower() == "none":
            finding = {
                "name": "Cookie Missing SameSite Attribute",
                "severity": "LOW",
                "url": f"Cookie: {name}",
                "evidence": f"Cookie '{name}' has no SameSite attribute (or SameSite=None)",
                "parameter": name,
                "description": "Without SameSite, the cookie is sent with cross-site requests, enabling CSRF attacks.",
                "module": "Cookie Security",
            }
            findings.append(finding)
            if callback:
                callback("finding", finding)

    if not crawl_data.get("cookies"):
        findings.append({
            "name": "No Cookies Detected",
            "severity": "INFO",
            "url": "N/A",
            "evidence": "No cookies were set during the crawl",
            "parameter": "N/A",
            "description": "The application does not appear to use cookies for session management.",
            "module": "Cookie Security",
        })

    return findings
