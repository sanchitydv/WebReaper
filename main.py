import os
import sys
import threading
import subprocess
from datetime import datetime

from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Input, Button, Checkbox, Label, Log, Static, DataTable
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.screen import Screen
from textual import on
from textual.binding import Binding
from rich.text import Text


BANNER = """[bold red]
 ██╗    ██╗███████╗██████╗ ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗
 ██║    ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
 ██║ █╗ ██║█████╗  ██████╔╝██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
 ██║███╗██║██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
 ╚███╔███╔╝███████╗██████╔╝██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
[/bold red][dim]                    Web Vulnerability Scanner v1.0 | Authorized Use Only[/dim]"""

MODULES = [
    ("xss",            "XSS Scanner"),
    ("sqli",           "SQL Injection"),
    ("open_redirect",  "Open Redirect"),
    ("sensitive_files","Sensitive Files"),
    ("cookies",        "Cookie Security"),
    ("csrf",           "CSRF Checker"),
    ("headers",        "Security Headers"),
    ("ssl",            "SSL/TLS Analyzer"),
    ("cms",            "CMS Detection"),
    ("cve",            "CVE Lookup"),
    ("js",             "JS File Analyzer"),
    ("access_control", "Access Control"),
    ("api",            "API Discovery"),
    ("subdomain",      "Subdomain Takeover"),
    ("email",          "Email Security"),
    ("rate_limit",     "Rate Limit Tester"),
    ("http_methods",   "HTTP Methods"),
    ("screenshots",    "Screenshots"),
]


CSS = """
Screen { background: #0a0e1a; }

#banner { background: #0d1117; border: tall #ff3333; padding: 1 2; margin: 1 2; }
#banner Static { color: $text; }

#home-container { margin: 0 2; }

.section-title { background: #161b22; color: #ff3333; padding: 0 1; margin-top: 1; }

#url-input { margin: 0 0 1 0; }
Input { background: #161b22; border: tall #30363d; color: #e6edf3; }
Input:focus { border: tall #ff3333; }

#profile-row { height: 3; margin-bottom: 1; }
.profile-btn { background: #161b22; border: tall #30363d; color: #8b949e; margin: 0 1 0 0; min-width: 12; }
.profile-btn.active { background: #ff333322; border: tall #ff3333; color: #ff3333; }

#modules-grid { layout: vertical; height: auto; margin-bottom: 1; }
.mod-check-row { layout: horizontal; height: 3; }
.mod-check-row Checkbox { width: 1fr; background: #0d1117; color: #c9d1d9; height: 3; }
Checkbox { background: #0d1117; color: #c9d1d9; margin: 0; padding: 0 1; }
Checkbox:focus { background: #161b22; }

#email-input { margin-bottom: 1; }

#start-btn { background: #ff3333; color: white; border: tall #ff6666; width: 100%; height: 3; margin-bottom: 1; }
#start-btn:hover { background: #cc0000; }
#start-btn:focus { background: #cc0000; }

/* Scan screen */
#scan-container { margin: 0 2; height: 100%; }
#scan-header { background: #161b22; border: tall #ff3333; padding: 0 2; margin-bottom: 1; height: 3; }
#scan-header Label { color: #e6edf3; }

#modules-status { width: 35; border: tall #21262d; background: #0d1117; padding: 1; margin-right: 1; }
.mod-row { height: 1; }
.mod-pending { color: #30363d; }
.mod-running { color: #ffaa00; }
.mod-done-ok  { color: #00ff88; }
.mod-done-warn { color: #ff6b00; }

#live-log { border: tall #21262d; background: #0d1117; }
Log { background: #0d1117; color: #c9d1d9; }

#counters { height: 3; background: #161b22; margin-top: 1; }
.counter-label { width: 1fr; text-align: center; }
.c-crit { color: #ff3333; }
.c-high { color: #ff6b00; }
.c-med  { color: #ffaa00; }
.c-low  { color: #00aaff; }

/* Results screen */
#results-container { margin: 0 2; }
#results-header { background: #161b22; border: tall #00ff88; padding: 1 2; margin-bottom: 1; }
#results-header Label { color: #00ff88; }
#action-row { height: 3; margin-bottom: 1; }
.action-btn { background: #161b22; border: tall #30363d; color: #e6edf3; margin-right: 1; min-width: 20; }
.action-btn:hover { background: #21262d; border: tall #ff3333; color: #ff3333; }
DataTable { border: tall #21262d; background: #0d1117; }
"""


class HomeScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield ScrollableContainer(
            Static(BANNER, markup=True, id="banner"),
            Container(
                Static("TARGET URL", classes="section-title"),
                Input(placeholder="https://example.com", id="url-input"),

                Static("SCAN PROFILE", classes="section-title"),
                Horizontal(
                    Button("Quick  (~3 min)", id="profile-quick", classes="profile-btn"),
                    Button("Full   (~15 min)", id="profile-full", classes="profile-btn active"),
                    Button("Stealth (~20 min)", id="profile-stealth", classes="profile-btn"),
                    id="profile-row",
                ),

                Static("MODULES", classes="section-title"),
                Container(
                    *[
                        Horizontal(
                            Checkbox(MODULES[i][1],   value=True, id=f"mod-{MODULES[i][0]}"),
                            Checkbox(MODULES[i+1][1], value=True, id=f"mod-{MODULES[i+1][0]}"),
                            Checkbox(MODULES[i+2][1], value=True, id=f"mod-{MODULES[i+2][0]}"),
                            classes="mod-check-row",
                        )
                        for i in range(0, len(MODULES) - len(MODULES) % 3, 3)
                    ] + (
                        [Horizontal(
                            *[Checkbox(MODULES[j][1], value=True, id=f"mod-{MODULES[j][0]}") for j in range(-(len(MODULES) % 3), 0)],
                            classes="mod-check-row",
                        )] if len(MODULES) % 3 != 0 else []
                    ),
                    id="modules-grid",
                ),

                Static("NOTIFICATION EMAIL (optional)", classes="section-title"),
                Input(placeholder="your@email.com (leave blank to skip)", id="email-input"),

                Button("💀  START SCAN", id="start-btn", variant="error"),
                id="home-container",
            ),
        )
        yield Footer()

    def on_mount(self):
        self.profile = "Full"

    @on(Button.Pressed, "#profile-quick")
    def set_quick(self):
        self._set_profile("Quick")

    @on(Button.Pressed, "#profile-full")
    def set_full(self):
        self._set_profile("Full")

    @on(Button.Pressed, "#profile-stealth")
    def set_stealth(self):
        self._set_profile("Stealth")

    def _set_profile(self, profile):
        self.profile = profile
        for btn_id in ("profile-quick", "profile-full", "profile-stealth"):
            btn = self.query_one(f"#{btn_id}", Button)
            btn.remove_class("active")
        mapping = {"Quick": "profile-quick", "Full": "profile-full", "Stealth": "profile-stealth"}
        self.query_one(f"#{mapping[profile]}", Button).add_class("active")

        quick_modules = {"headers", "ssl", "sensitive_files", "cookies", "csrf"}
        for key, _ in MODULES:
            cb = self.query_one(f"#mod-{key}", Checkbox)
            if profile == "Quick":
                cb.value = key in quick_modules
            else:
                cb.value = True

    @on(Button.Pressed, "#start-btn")
    def start_scan(self):
        url = self.query_one("#url-input", Input).value.strip()
        if not url:
            self.notify("Please enter a target URL", severity="error")
            return

        enabled = [key for key, _ in MODULES if self.query_one(f"#mod-{key}", Checkbox).value]
        email = self.query_one("#email-input", Input).value.strip() or None

        self.app.push_screen(ScanScreen(url, enabled, self.profile, email))


class ScanScreen(Screen):
    def __init__(self, target, enabled_modules, profile, email):
        super().__init__()
        self.target = target
        self.enabled_modules = enabled_modules
        self.profile = profile
        self.email = email
        self.findings = []
        self.report_path = None
        self.module_labels = {}
        self.counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Container(
            Horizontal(
                Label(f"💀 WebReaper — Target: {self.target}  |  Profile: {self.profile}", id="scan-header-label"),
                id="scan-header",
            ),
            Horizontal(
                ScrollableContainer(
                    Static("MODULES", classes="section-title"),
                    *[Label(f"○  {label}", id=f"status-{key}", classes="mod-row mod-pending") for key, label in MODULES],
                    id="modules-status",
                ),
                Log(id="live-log", highlight=True),
            ),
            Horizontal(
                Label("CRITICAL: 0", id="cnt-critical", classes="counter-label c-crit"),
                Label("HIGH: 0", id="cnt-high", classes="counter-label c-high"),
                Label("MEDIUM: 0", id="cnt-medium", classes="counter-label c-med"),
                Label("LOW: 0", id="cnt-low", classes="counter-label c-low"),
                id="counters",
            ),
            id="scan-container",
        )
        yield Footer()

    def on_mount(self):
        self.log_widget = self.query_one("#live-log", Log)
        self.log_msg(f"[bold]Starting scan of {self.target}...[/bold]")
        self.log_msg(f"Profile: {self.profile}  |  Modules: {len(self.enabled_modules)}")
        self.log_msg("─" * 60)
        thread = threading.Thread(target=self._run_scan, daemon=True)
        thread.start()

    def log_msg(self, msg):
        self.app.call_from_thread(self._append_log, msg)

    def _append_log(self, msg):
        try:
            self.log_widget.write_line(msg)
        except Exception:
            pass

    def set_module_status(self, key, status, count=None):
        self.app.call_from_thread(self._update_module_label, key, status, count)

    def _update_module_label(self, key, status, count):
        try:
            label = self.query_one(f"#status-{key}", Label)
            icons = {"pending": "○", "running": "◌", "done": "✓"}
            classes = {"pending": "mod-pending", "running": "mod-running", "done": "mod-done-ok"}
            name = next((n for k, n in MODULES if k == key), key)
            text = f"{icons.get(status,'○')}  {name}"
            if count is not None:
                text += f"  [{count}]"
            label.update(text)
            label.remove_class("mod-pending", "mod-running", "mod-done-ok")
            label.add_class(classes.get(status, "mod-pending"))
        except Exception:
            pass

    def update_counters(self):
        self.app.call_from_thread(self._refresh_counters)

    def _refresh_counters(self):
        try:
            self.query_one("#cnt-critical", Label).update(f"CRITICAL: {self.counts['CRITICAL']}")
            self.query_one("#cnt-high", Label).update(f"HIGH: {self.counts['HIGH']}")
            self.query_one("#cnt-medium", Label).update(f"MEDIUM: {self.counts['MEDIUM']}")
            self.query_one("#cnt-low", Label).update(f"LOW: {self.counts['LOW']}")
        except Exception:
            pass

    def _scan_callback(self, event, data):
        if event == "module_start":
            key = next((k for k, n in MODULES if n == data), data.lower().replace(" ", "_"))
            self.set_module_status(key, "running")
            self.log_msg(f"[yellow]⟳  Running: {data}[/yellow]")

        elif event == "module_done":
            name = data["name"]
            count = data["count"]
            key = next((k for k, n in MODULES if n == name), name.lower().replace(" ", "_"))
            status = "done" if count == 0 else "done"
            self.set_module_status(key, status, count)
            self.log_msg(f"[green]✓  {name}: {count} finding(s)[/green]")

        elif event == "finding":
            finding = data
            sev = finding.get("severity", "INFO")
            if sev in self.counts:
                self.counts[sev] += 1
                self.update_counters()
            colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "INFO": "dim"}
            color = colors.get(sev, "white")
            self.log_msg(f"  [{color}][{sev}][/{color}] {finding['name']} — {finding['url'][:60]}")

        elif event == "crawl_page":
            self.log_msg(f"  [dim]Crawled: {str(data)[:80]}[/dim]")

        elif event == "generating_report":
            self.log_msg("[cyan]Generating HTML report...[/cyan]")

        elif event == "scan_complete":
            self.report_path = data["report_path"]
            self.findings = data["findings"]
            duration = data["duration"]
            self.log_msg("─" * 60)
            self.log_msg(f"[bold green]✓ SCAN COMPLETE in {int(duration)}s[/bold green]")
            self.log_msg(f"[bold]Report: {os.path.abspath(self.report_path)}[/bold]")
            self.app.call_from_thread(self._go_to_results)

    def _run_scan(self):
        try:
            from scanner import WebReaper
            reaper = WebReaper(
                target=self.target,
                enabled_modules=self.enabled_modules,
                profile=self.profile,
                email=self.email,
                callback=self._scan_callback,
            )
            reaper.run()
        except Exception as e:
            self.log_msg(f"[bold red]Error: {e}[/bold red]")
            import traceback
            self.log_msg(traceback.format_exc())

    def _go_to_results(self):
        self.app.push_screen(ResultsScreen(self.target, self.findings, self.report_path))


class ResultsScreen(Screen):
    def __init__(self, target, findings, report_path):
        super().__init__()
        self.target = target
        self.findings = findings
        self.report_path = report_path

    def compose(self) -> ComposeResult:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[f.get("severity", "INFO")] = counts.get(f.get("severity", "INFO"), 0) + 1

        yield Header(show_clock=True)
        yield Container(
            Label(
                f"💀 Scan Complete — {len(self.findings)} findings  |  "
                f"Critical: {counts['CRITICAL']}  High: {counts['HIGH']}  "
                f"Medium: {counts['MEDIUM']}  Low: {counts['LOW']}",
                id="results-header-label",
            ),
            Horizontal(
                Button("📄  Open Report", id="btn-report", classes="action-btn"),
                Button("📤  Export PDF", id="btn-pdf", classes="action-btn"),
                Button("🔄  New Scan", id="btn-new", classes="action-btn"),
                id="action-row",
            ),
            self._build_table(),
            id="results-container",
        )
        yield Footer()

    def _build_table(self):
        table = DataTable(id="findings-table")
        table.add_columns("#", "Severity", "Vulnerability", "URL", "Module")
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_f = sorted(self.findings, key=lambda x: sev_order.get(x.get("severity", "INFO"), 4))
        colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "INFO": "dim"}
        for i, f in enumerate(sorted_f, 1):
            sev = f.get("severity", "INFO")
            color = colors.get(sev, "white")
            table.add_row(
                str(i),
                Text(sev, style=color),
                f.get("name", "")[:60],
                f.get("url", "")[:50],
                f.get("module", ""),
            )
        return table

    @on(Button.Pressed, "#btn-report")
    def open_report(self):
        if self.report_path:
            path = os.path.abspath(self.report_path)
            subprocess.Popen(["open", path])
            self.notify(f"Opening report: {path}")

    @on(Button.Pressed, "#btn-pdf")
    def export_pdf(self):
        if self.report_path:
            self.notify("Generating PDF...")
            from report.generator import export_pdf
            pdf_path = export_pdf(self.report_path)
            if pdf_path:
                self.notify(f"PDF saved: {os.path.abspath(pdf_path)}", severity="information")
                subprocess.Popen(["open", os.path.abspath(pdf_path)])
            else:
                self.notify("PDF export failed. Install Playwright: playwright install chromium", severity="warning")

    @on(Button.Pressed, "#btn-new")
    def new_scan(self):
        self.app.pop_screen()
        self.app.pop_screen()


class WebReaperApp(App):
    TITLE = "WebReaper"
    CSS = CSS
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("ctrl+c", "quit", "Quit"),
    ]

    def on_mount(self):
        self.push_screen(HomeScreen())


if __name__ == "__main__":
    app = WebReaperApp()
    app.run()
