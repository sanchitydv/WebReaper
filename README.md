# ◈ WebReaper

> **Automated Web Vulnerability Scanner — Desktop Application**

A professional, standalone desktop security tool that scans websites for 18 types of vulnerabilities and displays results in a live, interactive dashboard. No terminal required.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Windows%20%7C%20Linux-lightgrey?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## ⚠ Legal Disclaimer

> This tool is intended **only for authorized security testing**. Only use WebReaper on websites you own or have explicit written permission to test. Unauthorized scanning is illegal and unethical.

---

## Screenshots

| Home | Scanning | Dashboard |
|------|----------|-----------|
| Configure target, profile & modules | Live progress with animated module status | Risk gauge, charts, findings table & detail panel |

---

## Features

- **18 Scan Modules** covering injection, authentication, transport, discovery, and more
- **3 Scan Profiles** — Quick (3 min), Full (15 min), Stealth (20 min)
- **Live Dashboard** — risk gauge, donut chart, severity cards, sortable findings table
- **Click-to-inspect** — select any finding to see description, URL, and fix recommendation
- **Severity Filters** — filter findings by Critical / High / Medium / Low instantly
- **No terminal needed** — fully packaged as a `.app` (macOS) or `.exe` (Windows)
- **Scan diff** — compares with previous scans to show new findings
- **Email notifications** — optional scan completion alerts

---

## Scan Modules

| Category | Module | What It Checks |
|---|---|---|
| **Injection** | XSS Scanner | Reflected/stored JavaScript injection |
| | SQL Injection | Database query manipulation |
| | Open Redirect | Unvalidated URL redirects |
| **Authentication** | Cookie Security | HttpOnly, Secure, SameSite flags |
| | CSRF Checker | Missing anti-CSRF tokens on forms |
| | Access Control | Unauthorized access to restricted pages |
| **Transport** | Security Headers | CSP, HSTS, X-Frame-Options, etc. |
| | SSL/TLS Analyzer | Certificate validity, cipher strength |
| **Discovery** | CMS Detection | WordPress, Joomla, Drupal fingerprinting |
| | CVE Lookup | Known CVEs for detected CMS version |
| | JS Analyzer | Exposed API keys and secrets in JS files |
| | API Discovery | Hidden/undocumented API endpoints |
| | Subdomain Takeover | Abandoned subdomains attackers can claim |
| | Sensitive Files | Exposed `.env`, backups, config files |
| **Extras** | Email Security | SPF, DMARC, DKIM record validation |
| | Rate Limit Tester | Brute-force protection checks |
| | HTTP Methods | Dangerous methods (PUT, DELETE) enabled |
| | Screenshots | Visual snapshots of crawled pages |

---

## Severity Levels

| Level | Color | Score Weight | Meaning |
|---|---|---|---|
| **CRITICAL** | 🔴 Red | 25 pts | Immediate risk, actively exploitable |
| **HIGH** | 🟠 Orange | 15 pts | Serious vulnerability, fix urgently |
| **MEDIUM** | 🟡 Yellow | 8 pts | Notable issue, fix soon |
| **LOW** | 🔵 Blue | 3 pts | Minor issue, fix when possible |
| **INFO** | ⚪ Grey | 0 pts | Informational only |

The **Risk Score** (0–100) is calculated from all findings combined and displayed as a gauge on the dashboard.

---

## Installation

### Option 1 — Run from source (recommended for development)

**Requirements:** Python 3.10+ with Tkinter support

```bash
# Clone the repository
git clone https://github.com/sanchitydv/WebReaper.git
cd WebReaper

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate        # macOS/Linux
# .venv\Scripts\activate.bat     # Windows

# Install dependencies
pip install -r requirements.txt

# Run the app
python main.py
```

> **macOS note:** If you see `No module named '_tkinter'`, your Python was compiled without Tk support. Install a Tk-enabled Python: the one at `/usr/local/bin/python3` usually works, or install via `brew install python-tk`.

---

### Option 2 — Build a standalone executable

```bash
# macOS / Linux
chmod +x build.sh && ./build.sh
# Output: dist/WebReaper.app

# Windows
build.bat
# Output: dist\WebReaper\WebReaper.exe
```

The build script automatically creates a virtual environment, installs all dependencies, and runs PyInstaller. The output is a fully self-contained application — no Python installation needed on the target machine.

---

## Usage

### 1. Configure the scan

- Enter the **target URL** (e.g. `https://example.com`)
- Choose a **scan profile:**
  - `Quick` — 5 essential checks, ~3 minutes
  - `Full` — all 18 modules, ~15 minutes
  - `Stealth` — slow, low-noise mode that mimics Googlebot, ~20 minutes
- Select or deselect individual modules using the category checkboxes
- Optionally enter an **email address** for a completion notification

### 2. Run the scan

Click **START SCAN**. The scan screen shows:
- A pulsing amber dot on the currently running module
- Live output log with color-coded findings
- Running severity counters at the bottom

### 3. View the dashboard

When the scan completes, the dashboard opens automatically:

| Panel | Contents |
|---|---|
| **Risk Gauge** | Arc gauge showing score 0–100 |
| **Severity Cards** | Critical / High / Medium / Low counts |
| **Scan Stats** | Pages crawled, forms, JS files, duration |
| **Donut Chart** | Visual severity distribution |
| **Module Breakdown** | Which scanner found the most issues |
| **Findings Table** | Full sortable list of all vulnerabilities |
| **Detail Panel** | Click any row → description + fix recommendation |

Use the **filter bar** to show only findings of a specific severity. Click any **column header** to sort the table.

---

## Project Structure

```
WebReaper/
├── main.py                  # GUI — all three screens (Home, Scan, Dashboard)
├── scanner.py               # Core scan orchestrator
├── notifications.py         # Email notification sender
├── requirements.txt         # Python dependencies
├── WebReaper.spec           # PyInstaller build recipe
├── build.sh                 # One-command build (macOS/Linux)
├── build.bat                # One-command build (Windows)
│
├── modules/                 # One file per scan module
│   ├── crawler.py
│   ├── xss_scanner.py
│   ├── sqli_scanner.py
│   ├── open_redirect.py
│   ├── sensitive_files.py
│   ├── cookie_checker.py
│   ├── csrf_checker.py
│   ├── header_checker.py
│   ├── ssl_analyzer.py
│   ├── cms_detector.py
│   ├── cve_lookup.py
│   ├── js_analyzer.py
│   ├── access_control.py
│   ├── api_discovery.py
│   ├── subdomain_takeover.py
│   ├── email_security.py
│   ├── rate_limit_tester.py
│   ├── http_methods.py
│   └── screenshot.py
│
├── report/                  # Report generation
│   ├── generator.py         # HTML report + PDF export
│   ├── template.html        # Jinja2 HTML template
│   ├── diff.py              # Scan comparison (new vs previous)
│   └── recommendations.py   # Fix recommendations per finding type
│
├── wordlists/               # Payload and path lists
│   ├── xss_payloads.txt
│   ├── sqli_payloads.txt
│   ├── sensitive_paths.txt
│   └── api_paths.txt
│
├── scripts/
│   └── make_icon.py         # Generates icon.ico / icon.icns
│
└── icon.png / icon.ico / icon.icns   # App icons
```

---

## Tech Stack

| Component | Technology |
|---|---|
| Desktop UI | [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) |
| Charts & Gauges | `tkinter.Canvas` (native drawing) |
| Findings Table | `tkinter.ttk.Treeview` |
| HTTP Requests | `requests` + `BeautifulSoup4` |
| DNS Lookups | `dnspython` |
| Report Templates | `Jinja2` |
| App Packaging | `PyInstaller` |
| Icon Generation | `Pillow (PIL)` |
| Background Scanning | `threading` + `queue` |

---

## Dependencies

```
requests          # HTTP client
beautifulsoup4    # HTML parser
dnspython         # DNS queries
rich              # Terminal formatting (used by scanner internals)
jinja2            # HTML report templates
customtkinter     # Modern dark-themed desktop UI
pillow            # Image processing (icon generation)
playwright        # PDF export (optional)
weasyprint        # PDF export fallback (optional)
urllib3           # HTTP utilities
pyinstaller       # App packaging
```

Install all at once:
```bash
pip install -r requirements.txt
```

---

## How the Scan Works (Internals)

```
User clicks START
      │
      ▼
scanner.py → WebReaper.run()
      │
      ├── 1. Crawl the site (discover all pages, forms, JS files)
      │
      ├── 2. Run each enabled module in sequence
      │         Each module:  receives crawl_data → makes HTTP requests
      │                       → calls callback("finding", {...}) for each issue
      │
      ├── 3. CVE Lookup (uses CMS detection result as input)
      │
      ├── 4. Screenshots (Playwright headless browser)
      │
      ├── 5. Compare with previous scan (diff)
      │
      └── 6. Fire callback("scan_complete", {...})
                    └── GUI switches to Dashboard
```

The GUI runs the scan on a **background thread** and receives events through a `queue.Queue`, so the interface stays responsive throughout.

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-module`
3. Add your module to `modules/` following the existing pattern
4. Register it in `scanner.py` and `main.py` (MODULES list)
5. Submit a pull request

---

## Author

**Sanchit Kumar**
- GitHub: [@sanchitydv](https://github.com/sanchitydv)

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

*Built for educational purposes and authorized security testing only.*
