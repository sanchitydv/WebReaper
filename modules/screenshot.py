import os
from urllib.parse import urlparse


SCREENSHOTS_DIR = os.path.join(os.path.dirname(__file__), "..", "scans", "screenshots")


def take_screenshots(pages, base_url, callback=None):
    findings = []
    os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        findings.append({
            "name": "Screenshots Skipped",
            "severity": "INFO",
            "url": base_url,
            "evidence": "Playwright not installed. Run: pip install playwright && playwright install chromium",
            "parameter": "N/A",
            "description": "Install Playwright to enable screenshots.",
            "module": "Screenshots",
        })
        return findings, []

    screenshot_paths = []
    urls_to_capture = [base_url] + [p["url"] for p in pages[:9] if p.get("status") == 200]

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(ignore_https_errors=True)

            for url in urls_to_capture:
                try:
                    page.goto(url, timeout=10000, wait_until="domcontentloaded")
                    parsed = urlparse(url)
                    safe_name = (parsed.path.strip("/").replace("/", "_") or "home") + ".png"
                    path = os.path.join(SCREENSHOTS_DIR, safe_name)
                    page.screenshot(path=path, full_page=False)
                    screenshot_paths.append({"url": url, "path": path})
                except Exception:
                    continue

            browser.close()

        findings.append({
            "name": f"Screenshots Captured ({len(screenshot_paths)} pages)",
            "severity": "INFO",
            "url": base_url,
            "evidence": f"Screenshots saved to {SCREENSHOTS_DIR}",
            "parameter": "N/A",
            "description": "Visual snapshots of discovered pages.",
            "module": "Screenshots",
        })
    except Exception as e:
        findings.append({
            "name": "Screenshot Error",
            "severity": "INFO",
            "url": base_url,
            "evidence": str(e),
            "parameter": "N/A",
            "description": "Could not capture screenshots.",
            "module": "Screenshots",
        })

    return findings, screenshot_paths
