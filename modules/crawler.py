import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode, parse_qs
from collections import deque
import re


class Crawler:
    def __init__(self, base_url, session, callback=None):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.session = session
        self.callback = callback
        self.visited = set()
        self.pages = []
        self.forms = []
        self.js_files = []
        self.cookies = []
        self.url_params = []

    def is_same_domain(self, url):
        parsed = urlparse(url)
        return parsed.netloc == self.domain or parsed.netloc == ""

    def normalize_url(self, url, source):
        url = urljoin(source, url)
        parsed = urlparse(url)
        return parsed.scheme + "://" + parsed.netloc + parsed.path

    def extract_forms(self, url, soup):
        for form in soup.find_all("form"):
            action = form.get("action", url)
            action = urljoin(url, action)
            method = form.get("method", "get").lower()
            fields = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                itype = inp.get("type", "text")
                value = inp.get("value", "")
                if name:
                    fields.append({"name": name, "type": itype, "value": value})
            if fields:
                self.forms.append({"url": action, "method": method, "fields": fields, "source": url})

    def extract_params(self, url):
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            self.url_params.append({"url": url, "params": {k: v[0] for k, v in params.items()}})

    def crawl(self):
        queue = deque([self.base_url])
        self.visited.add(self.base_url)

        while queue:
            url = queue.popleft()
            try:
                resp = self.session.get(url, timeout=8, allow_redirects=True, verify=False)
                self.pages.append({"url": url, "status": resp.status_code, "content_type": resp.headers.get("Content-Type", "")})
                self.extract_params(url)

                if "text/html" not in resp.headers.get("Content-Type", ""):
                    continue

                soup = BeautifulSoup(resp.text, "html.parser")
                self.extract_forms(url, soup)

                for tag in soup.find_all("script", src=True):
                    js_url = urljoin(url, tag["src"])
                    if self.is_same_domain(js_url) and js_url not in self.js_files:
                        self.js_files.append(js_url)

                for tag in soup.find_all("a", href=True):
                    href = tag["href"]
                    if href.startswith(("mailto:", "tel:", "javascript:", "#")):
                        continue
                    full_url = self.normalize_url(href, url)
                    if self.is_same_domain(full_url) and full_url not in self.visited:
                        self.visited.add(full_url)
                        queue.append(full_url)
                        if self.callback:
                            self.callback("crawl_page", full_url)

            except Exception:
                continue

        for cookie in self.session.cookies:
            self.cookies.append({
                "name": cookie.name, "value": cookie.value,
                "domain": cookie.domain, "secure": cookie.secure,
                "http_only": bool(cookie.has_nonstandard_attr("HttpOnly")),
                "same_site": cookie._rest.get("SameSite", None),
            })

        return {
            "pages": self.pages,
            "forms": self.forms,
            "js_files": self.js_files,
            "cookies": self.cookies,
            "url_params": self.url_params,
        }
