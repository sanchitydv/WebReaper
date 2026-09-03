import requests
import time
import urllib3
from urllib.parse import urlparse

from modules.crawler import Crawler
from modules.xss_scanner import scan_xss
from modules.sqli_scanner import scan_sqli
from modules.open_redirect import scan_open_redirect
from modules.sensitive_files import scan_sensitive_files
from modules.cookie_checker import scan_cookies
from modules.csrf_checker import scan_csrf
from modules.header_checker import scan_headers
from modules.ssl_analyzer import scan_ssl
from modules.cms_detector import scan_cms
from modules.cve_lookup import scan_cve
from modules.js_analyzer import scan_js
from modules.access_control import scan_access_control
from modules.api_discovery import scan_api
from modules.subdomain_takeover import scan_subdomain_takeover
from modules.email_security import scan_email_security
from modules.rate_limit_tester import scan_rate_limit
from modules.http_methods import scan_http_methods
from modules.screenshot import take_screenshots
from report.generator import generate_report, export_pdf
from report.diff import save_scan, load_previous_scan, diff_scans

urllib3.disable_warnings()

PROFILES = {
    "Quick": ["headers", "ssl", "sensitive_files", "cookies", "csrf"],
    "Full": None,
    "Stealth": None,
}

STEALTH_DELAY = 2


class WebReaper:
    def __init__(self, target, enabled_modules=None, profile="Full", email=None, callback=None):
        if not target.startswith("http"):
            target = "https://" + target
        self.target = target
        self.profile = profile
        self.email = email
        self.callback = callback
        self.findings = []
        self.crawl_data = {}
        self.screenshot_paths = []
        self.start_time = None

        if profile == "Quick":
            self.enabled = set(PROFILES["Quick"])
        else:
            self.enabled = set(enabled_modules) if enabled_modules else {
                "crawler", "xss", "sqli", "open_redirect", "sensitive_files",
                "cookies", "csrf", "headers", "ssl", "cms", "cve", "js",
                "access_control", "api", "subdomain", "email", "rate_limit",
                "http_methods", "screenshots",
            }

        parsed = urlparse(target)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        })
        if profile == "Stealth":
            self.session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1)"})

    def _notify(self, event, data=None):
        if self.callback:
            self.callback(event, data)

    def _module_start(self, name):
        self._notify("module_start", name)

    def _module_done(self, name, count):
        self._notify("module_done", {"name": name, "count": count})

    def _add_findings(self, new_findings):
        self.findings.extend(new_findings)

    def _stealth_sleep(self):
        if self.profile == "Stealth":
            time.sleep(STEALTH_DELAY)

    def run(self):
        self.start_time = time.time()

        # Step 1: Crawl
        self._module_start("Crawler")
        crawler = Crawler(self.target, self.session, callback=lambda e, d: self._notify(e, d))
        self.crawl_data = crawler.crawl()
        self._module_done("Crawler", len(self.crawl_data.get("pages", [])))
        self._stealth_sleep()

        # Step 2: Run all enabled modules
        module_map = [
            ("xss",           "XSS Scanner",          lambda: scan_xss(self.crawl_data, self.session, lambda e, f: self._notify("finding", f))),
            ("sqli",          "SQL Injection",         lambda: scan_sqli(self.crawl_data, self.session, lambda e, f: self._notify("finding", f))),
            ("open_redirect", "Open Redirect",         lambda: scan_open_redirect(self.crawl_data, self.session, lambda e, f: self._notify("finding", f))),
            ("sensitive_files","Sensitive Files",      lambda: scan_sensitive_files(self.target, self.session, lambda e, f: self._notify("finding", f))),
            ("cookies",       "Cookie Security",       lambda: scan_cookies(self.crawl_data, lambda e, f: self._notify("finding", f))),
            ("csrf",          "CSRF Checker",          lambda: scan_csrf(self.crawl_data, lambda e, f: self._notify("finding", f))),
            ("headers",       "Security Headers",      lambda: scan_headers(self.target, self.session, lambda e, f: self._notify("finding", f))),
            ("ssl",           "SSL/TLS Analyzer",      lambda: scan_ssl(self.target, lambda e, f: self._notify("finding", f))),
            ("cms",           "CMS Detection",         lambda: scan_cms(self.target, self.session, lambda e, f: self._notify("finding", f))),
            ("js",            "JS Analyzer",           lambda: scan_js(self.crawl_data, self.session, lambda e, f: self._notify("finding", f))),
            ("access_control","Access Control",        lambda: scan_access_control(self.crawl_data, self.session, self.target, lambda e, f: self._notify("finding", f))),
            ("api",           "API Discovery",         lambda: scan_api(self.target, self.session, lambda e, f: self._notify("finding", f))),
            ("subdomain",     "Subdomain Takeover",    lambda: scan_subdomain_takeover(self.target, lambda e, f: self._notify("finding", f))),
            ("email",         "Email Security",        lambda: scan_email_security(self.target, lambda e, f: self._notify("finding", f))),
            ("rate_limit",    "Rate Limit Tester",     lambda: scan_rate_limit(self.crawl_data, self.session, self.target, lambda e, f: self._notify("finding", f))),
            ("http_methods",  "HTTP Methods",          lambda: scan_http_methods(self.crawl_data, self.session, self.target, lambda e, f: self._notify("finding", f))),
        ]

        cms_findings = []
        for key, name, fn in module_map:
            if key not in self.enabled:
                continue
            self._module_start(name)
            try:
                results = fn()
                self._add_findings(results)
                if key == "cms":
                    cms_findings = results
            except Exception as e:
                pass
            self._module_done(name, len([f for f in self.findings if f.get("module") == name]))
            self._stealth_sleep()

        # CVE lookup depends on CMS results
        if "cve" in self.enabled and cms_findings:
            self._module_start("CVE Lookup")
            try:
                cve_results = scan_cve(cms_findings, callback=lambda e, f: self._notify("finding", f))
                self._add_findings(cve_results)
            except Exception:
                pass
            self._module_done("CVE Lookup", len([f for f in self.findings if f.get("module") == "CVE Lookup"]))

        # Screenshots
        if "screenshots" in self.enabled:
            self._module_start("Screenshots")
            try:
                sc_findings, sc_paths = take_screenshots(self.crawl_data.get("pages", []), self.target)
                self._add_findings(sc_findings)
                self.screenshot_paths = sc_paths
            except Exception:
                pass
            self._module_done("Screenshots", len(self.screenshot_paths))

        duration = time.time() - self.start_time

        # Load previous scan for diff
        previous = load_previous_scan(self.target)
        diff = diff_scans(previous, self.findings)

        # Save current scan
        save_scan(self.target, self.findings)

        # Generate report
        self._notify("generating_report", None)
        report_path = generate_report(
            target=self.target,
            findings=self.findings,
            crawl_data=self.crawl_data,
            diff=diff,
            profile=self.profile,
            scan_duration=duration,
        )

        self._notify("scan_complete", {
            "report_path": report_path,
            "findings": self.findings,
            "duration": duration,
            "pages_crawled": len(self.crawl_data.get("pages", [])),
            "forms_found": len(self.crawl_data.get("forms", [])),
            "js_files": len(self.crawl_data.get("js_files", [])),
            "modules_run": len(self.enabled),
        })
        return report_path, self.findings
