import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse


WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
WEAK_CIPHERS = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"]


def scan_ssl(base_url, callback=None):
    findings = []
    parsed = urlparse(base_url)

    if parsed.scheme != "https":
        finding = {
            "name": "Site Not Using HTTPS",
            "severity": "CRITICAL",
            "url": base_url,
            "evidence": "The target URL uses HTTP instead of HTTPS",
            "parameter": "protocol",
            "description": "All traffic is transmitted in plaintext. Credentials, cookies, and data are exposed to interception.",
            "module": "SSL/TLS Analyzer",
        }
        findings.append(finding)
        if callback:
            callback("finding", finding)
        return findings

    hostname = parsed.hostname
    port = parsed.port or 443

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol = ssock.version()

        # Check expiry
        expire_str = cert.get("notAfter", "")
        if expire_str:
            expire_date = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (expire_date - datetime.utcnow()).days
            if days_left < 0:
                findings.append({
                    "name": "SSL Certificate Expired",
                    "severity": "CRITICAL",
                    "url": base_url,
                    "evidence": f"Certificate expired on {expire_date.strftime('%Y-%m-%d')}",
                    "parameter": "certificate",
                    "description": "The SSL certificate has expired. Browsers will show security warnings to all visitors.",
                    "module": "SSL/TLS Analyzer",
                })
            elif days_left < 30:
                findings.append({
                    "name": "SSL Certificate Expiring Soon",
                    "severity": "MEDIUM",
                    "url": base_url,
                    "evidence": f"Certificate expires in {days_left} days ({expire_date.strftime('%Y-%m-%d')})",
                    "parameter": "certificate",
                    "description": "The SSL certificate will expire soon. Renew it to prevent browser warnings.",
                    "module": "SSL/TLS Analyzer",
                })

        # Check protocol version
        if protocol and any(weak in protocol for weak in WEAK_PROTOCOLS):
            findings.append({
                "name": "Weak TLS Protocol Version",
                "severity": "HIGH",
                "url": base_url,
                "evidence": f"Server is using {protocol}",
                "parameter": "protocol",
                "description": f"{protocol} is deprecated and vulnerable to known attacks (POODLE, BEAST, etc.).",
                "module": "SSL/TLS Analyzer",
            })

        # Check cipher suite
        if cipher:
            cipher_name = cipher[0]
            if any(weak in cipher_name.upper() for weak in WEAK_CIPHERS):
                findings.append({
                    "name": "Weak Cipher Suite",
                    "severity": "HIGH",
                    "url": base_url,
                    "evidence": f"Cipher suite in use: {cipher_name}",
                    "parameter": "cipher",
                    "description": f"The cipher suite '{cipher_name}' is weak and can be broken by attackers.",
                    "module": "SSL/TLS Analyzer",
                })

        if not findings:
            findings.append({
                "name": "SSL/TLS Configuration OK",
                "severity": "INFO",
                "url": base_url,
                "evidence": f"Protocol: {protocol}, Cipher: {cipher[0] if cipher else 'N/A'}",
                "parameter": "N/A",
                "description": "SSL/TLS configuration appears secure.",
                "module": "SSL/TLS Analyzer",
            })

    except ssl.SSLCertVerificationError as e:
        findings.append({
            "name": "SSL Certificate Verification Failed",
            "severity": "HIGH",
            "url": base_url,
            "evidence": str(e),
            "parameter": "certificate",
            "description": "The SSL certificate could not be verified (self-signed, wrong hostname, or untrusted CA).",
            "module": "SSL/TLS Analyzer",
        })
    except Exception as e:
        findings.append({
            "name": "SSL Check Error",
            "severity": "INFO",
            "url": base_url,
            "evidence": str(e),
            "parameter": "N/A",
            "description": "Could not perform SSL analysis.",
            "module": "SSL/TLS Analyzer",
        })

    for f in findings:
        if callback and f["severity"] != "INFO":
            callback("finding", f)

    return findings
