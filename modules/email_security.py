import dns.resolver
from urllib.parse import urlparse


DKIM_SELECTORS = ["default", "google", "mail", "dkim", "k1", "s1", "s2", "selector1", "selector2"]


def query_txt(domain):
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 4
        resolver.lifetime = 4
        answers = resolver.resolve(domain, "TXT")
        return [str(r).strip('"') for r in answers]
    except Exception:
        return []


def scan_email_security(base_url, callback=None):
    findings = []
    domain = urlparse(base_url).netloc.lstrip("www.")

    # SPF check
    txt_records = query_txt(domain)
    spf = [r for r in txt_records if r.startswith("v=spf1")]

    if not spf:
        finding = {
            "name": "Missing SPF Record",
            "severity": "HIGH",
            "url": f"DNS: {domain}",
            "evidence": f"No SPF TXT record found for {domain}",
            "parameter": "SPF",
            "description": "Without an SPF record, anyone can send emails claiming to be from your domain, enabling phishing attacks.",
            "module": "Email Security",
        }
        findings.append(finding)
        if callback:
            callback("finding", finding)
    else:
        spf_value = spf[0]
        if "+all" in spf_value or "?all" in spf_value:
            finding = {
                "name": "Weak SPF Record",
                "severity": "HIGH",
                "url": f"DNS: {domain}",
                "evidence": f"SPF record uses permissive policy: {spf_value}",
                "parameter": "SPF",
                "description": "The SPF record allows any server to send mail on behalf of your domain (+all or ?all).",
                "module": "Email Security",
            }
            findings.append(finding)
            if callback:
                callback("finding", finding)

    # DMARC check
    dmarc_records = query_txt(f"_dmarc.{domain}")
    dmarc = [r for r in dmarc_records if r.startswith("v=DMARC1")]

    if not dmarc:
        finding = {
            "name": "Missing DMARC Record",
            "severity": "HIGH",
            "url": f"DNS: _dmarc.{domain}",
            "evidence": f"No DMARC TXT record found for _dmarc.{domain}",
            "parameter": "DMARC",
            "description": "Without DMARC, phishing emails using your domain cannot be automatically rejected by mail servers.",
            "module": "Email Security",
        }
        findings.append(finding)
        if callback:
            callback("finding", finding)
    else:
        dmarc_value = dmarc[0]
        if "p=none" in dmarc_value:
            finding = {
                "name": "Weak DMARC Policy",
                "severity": "MEDIUM",
                "url": f"DNS: _dmarc.{domain}",
                "evidence": f"DMARC policy is set to 'none' (monitoring only): {dmarc_value}",
                "parameter": "DMARC",
                "description": "DMARC p=none only monitors — it does not reject or quarantine spoofed emails.",
                "module": "Email Security",
            }
            findings.append(finding)
            if callback:
                callback("finding", finding)

    # DKIM check
    dkim_found = False
    for selector in DKIM_SELECTORS:
        records = query_txt(f"{selector}._domainkey.{domain}")
        if records:
            dkim_found = True
            break

    if not dkim_found:
        finding = {
            "name": "DKIM Not Detected",
            "severity": "MEDIUM",
            "url": f"DNS: {domain}",
            "evidence": f"No DKIM record found for common selectors on {domain}",
            "parameter": "DKIM",
            "description": "DKIM could not be detected. Without it, email integrity cannot be verified and spoofing is easier.",
            "module": "Email Security",
        }
        findings.append(finding)
        if callback:
            callback("finding", finding)

    return findings
