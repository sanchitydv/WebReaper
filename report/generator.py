import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from .recommendations import get_recommendation


TEMPLATE_DIR = os.path.dirname(__file__)


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def calculate_risk_score(findings):
    score = 0
    weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}
    for f in findings:
        score += weights.get(f.get("severity", "INFO"), 0)
    return min(score, 100)


def get_overall_risk(score):
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFO"


def check_clickjacking(findings):
    for f in findings:
        if "X-Frame-Options" in f.get("name", ""):
            return f.get("url", "")
    return None


def generate_report(target, findings, crawl_data, diff=None, profile="Full", scan_duration=0, output_path=None):
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template("template.html")

    for f in findings:
        f["recommendation"] = get_recommendation(f.get("name", ""))

    sorted_findings = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 4))

    risk_score = calculate_risk_score(findings)
    overall_risk = get_overall_risk(risk_score)

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1

    clickjacking_url = check_clickjacking(findings)

    context = {
        "target": target,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "profile": profile,
        "findings": sorted_findings,
        "total_findings": len([f for f in findings if f.get("severity") != "INFO"]),
        "risk_score": risk_score,
        "overall_risk": overall_risk,
        "critical_count": counts["CRITICAL"],
        "high_count": counts["HIGH"],
        "medium_count": counts["MEDIUM"],
        "low_count": counts["LOW"],
        "info_count": counts["INFO"],
        "pages_crawled": len(crawl_data.get("pages", [])),
        "forms_found": len(crawl_data.get("forms", [])),
        "js_files": len(crawl_data.get("js_files", [])),
        "scan_duration": int(scan_duration),
        "diff": diff,
        "clickjacking_url": clickjacking_url,
    }

    html = template.render(**context)

    if output_path is None:
        safe_target = target.replace("://", "_").replace("/", "_").replace(".", "_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"webreaper_{safe_target}_{ts}.html"

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path


def export_pdf(html_path, pdf_path=None):
    if pdf_path is None:
        pdf_path = html_path.replace(".html", ".pdf")
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(f"file://{os.path.abspath(html_path)}")
            page.pdf(path=pdf_path, format="A4", print_background=True)
            browser.close()
        return pdf_path
    except Exception as e:
        return None
