import dns.resolver
import requests
from urllib.parse import urlparse


TAKEOVER_SIGNATURES = {
    "github.io": ["There isn't a GitHub Pages site here", "404 - File or directory not found"],
    "herokuapp.com": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
    "azurewebsites.net": ["404 Web Site not found", "Microsoft Azure"],
    "s3.amazonaws.com": ["NoSuchBucket", "The specified bucket does not exist"],
    "cloudfront.net": ["ERROR: The request could not be satisfied"],
    "ghost.io": ["The thing you were looking for is no longer here"],
    "myshopify.com": ["Sorry, this shop is currently unavailable"],
    "zendesk.com": ["Help Center Closed"],
    "tumblr.com": ["There's nothing here"],
    "readme.io": ["Project doesnt exist", "project-not-found"],
    "surge.sh": ["project not found"],
    "bitbucket.io": ["Repository not found"],
    "unbounce.com": ["The requested URL was not found on this server"],
    "strikingly.com": ["page not found"],
    "wordpress.com": ["Do you want to register"],
}


def check_subdomain(subdomain, domain):
    fqdn = f"{subdomain}.{domain}"
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        answers = resolver.resolve(fqdn, "CNAME")
        cname_target = str(answers[0].target).rstrip(".")
        for service_domain, signatures in TAKEOVER_SIGNATURES.items():
            if service_domain in cname_target:
                try:
                    resp = requests.get(f"https://{fqdn}", timeout=6, verify=False)
                    for sig in signatures:
                        if sig.lower() in resp.text.lower():
                            return {
                                "subdomain": fqdn,
                                "cname": cname_target,
                                "service": service_domain,
                                "vulnerable": True,
                            }
                except Exception:
                    pass
    except Exception:
        pass
    return None


COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "blog", "shop", "app", "cdn", "static", "assets", "media", "beta",
    "old", "new", "portal", "vpn", "remote", "git", "support",
]


def scan_subdomain_takeover(base_url, callback=None):
    findings = []
    domain = urlparse(base_url).netloc

    for sub in COMMON_SUBDOMAINS:
        result = check_subdomain(sub, domain)
        if result and result["vulnerable"]:
            finding = {
                "name": "Subdomain Takeover Vulnerability",
                "severity": "CRITICAL",
                "url": f"https://{result['subdomain']}",
                "evidence": f"{result['subdomain']} CNAME points to unclaimed {result['service']} service",
                "parameter": result["subdomain"],
                "description": f"The subdomain {result['subdomain']} points to a {result['service']} resource that is no longer claimed. An attacker can register this service and serve malicious content.",
                "module": "Subdomain Takeover",
            }
            findings.append(finding)
            if callback:
                callback("finding", finding)

    return findings
