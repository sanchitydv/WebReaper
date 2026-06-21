import requests
import re


OSV_API = "https://api.osv.dev/v1/query"

ECOSYSTEM_MAP = {
    "WordPress": "npm",
    "Drupal": "Packagist",
    "Joomla": "Packagist",
    "Laravel": "Packagist",
    "Django": "PyPI",
    "Rails": "RubyGems",
}

SERVER_PACKAGE_MAP = {
    "apache": ("Apache HTTP Server", "OSS-Fuzz"),
    "nginx": ("nginx", "OSS-Fuzz"),
    "iis": ("IIS", "OSS-Fuzz"),
    "php": ("php", "OSS-Fuzz"),
}


def query_osv(package_name, version, ecosystem="npm"):
    try:
        payload = {
            "version": version,
            "package": {"name": package_name, "ecosystem": ecosystem},
        }
        resp = requests.post(OSV_API, json=payload, timeout=8)
        if resp.status_code == 200:
            return resp.json().get("vulns", [])
    except Exception:
        pass
    return []


def scan_cve(cms_findings, server_header="", callback=None):
    findings = []

    for cms_finding in cms_findings:
        cms_name = cms_finding.get("cms_name")
        cms_version = cms_finding.get("cms_version")
        if not cms_name or not cms_version:
            continue

        ecosystem = ECOSYSTEM_MAP.get(cms_name, "npm")
        vulns = query_osv(cms_name, cms_version, ecosystem)

        for vuln in vulns[:5]:
            vuln_id = vuln.get("id", "Unknown")
            summary = vuln.get("summary", "No summary available")
            severity = "HIGH"
            for s in vuln.get("severity", []):
                if "CRITICAL" in str(s.get("score", "")):
                    severity = "CRITICAL"
                    break

            finding = {
                "name": f"Known CVE: {vuln_id}",
                "severity": severity,
                "url": cms_finding["url"],
                "evidence": f"{cms_name} {cms_version} is affected by {vuln_id}: {summary}",
                "parameter": cms_name,
                "description": f"The detected version of {cms_name} has a known vulnerability: {summary}",
                "module": "CVE Lookup",
            }
            findings.append(finding)
            if callback:
                callback("finding", finding)

    return findings
