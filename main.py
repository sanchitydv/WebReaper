import os
import sys
import threading
import queue
import math
from datetime import datetime

import customtkinter as ctk
from tkinter import ttk, messagebox
import tkinter as tk

# ── Theme ──────────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

RED      = "#ff3333"
RED_DIM  = "#cc0000"
BG_DARK  = "#0a0e1a"
BG_MID   = "#0d1117"
BG_PANEL = "#161b22"
BG_CARD  = "#21262d"
TXT_MAIN = "#e6edf3"
TXT_DIM  = "#8b949e"
GREEN    = "#00ff88"
YELLOW   = "#ffaa00"
ORANGE   = "#ff6b00"
BLUE     = "#00aaff"

MODULES = [
    ("xss",             "XSS Scanner"),
    ("sqli",            "SQL Injection"),
    ("open_redirect",   "Open Redirect"),
    ("sensitive_files", "Sensitive Files"),
    ("cookies",         "Cookie Security"),
    ("csrf",            "CSRF Checker"),
    ("headers",         "Security Headers"),
    ("ssl",             "SSL/TLS Analyzer"),
    ("cms",             "CMS Detection"),
    ("cve",             "CVE Lookup"),
    ("js",              "JS File Analyzer"),
    ("access_control",  "Access Control"),
    ("api",             "API Discovery"),
    ("subdomain",       "Subdomain Takeover"),
    ("email",           "Email Security"),
    ("rate_limit",      "Rate Limit Tester"),
    ("http_methods",    "HTTP Methods"),
    ("screenshots",     "Screenshots"),
]

QUICK_MODULES = {"headers", "ssl", "sensitive_files", "cookies", "csrf"}


# ── Reusable widgets ───────────────────────────────────────────────────────────

def section_label(parent, text, **kwargs):
    return ctk.CTkLabel(
        parent, text=text, font=ctk.CTkFont(size=11, weight="bold"),
        text_color=RED, fg_color=BG_PANEL, anchor="w",
        corner_radius=4, **kwargs
    )


def card(parent, **kwargs):
    return ctk.CTkFrame(parent, fg_color=BG_PANEL, corner_radius=8, **kwargs)


# ── Home screen ────────────────────────────────────────────────────────────────

class HomeFrame(ctk.CTkFrame):
    def __init__(self, master, on_start):
        super().__init__(master, fg_color=BG_DARK)
        self.on_start = on_start
        self.profile = "Full"
        self.module_vars = {}
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Banner
        banner = ctk.CTkLabel(
            self, text=(
                "██╗    ██╗███████╗██████╗ ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗\n"
                "██║    ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗\n"
                "██║ █╗ ██║█████╗  ██████╔╝██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝\n"
                "██║███╗██║██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗\n"
                "╚███╔███╔╝███████╗██████╔╝██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║\n"
                " ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝"
            ),
            font=ctk.CTkFont(family="Courier", size=11, weight="bold"),
            text_color=RED, fg_color=BG_MID,
            justify="left", anchor="w",
        )
        banner.grid(row=0, column=0, sticky="ew", padx=0, pady=(0, 4))

        sub = ctk.CTkLabel(
            self, text="Web Vulnerability Scanner v1.0  |  Authorized Use Only",
            font=ctk.CTkFont(size=11), text_color=TXT_DIM, fg_color=BG_MID,
        )
        sub.grid(row=1, column=0, sticky="ew", padx=0, pady=(0, 8))

        # Scrollable body
        scroll = ctk.CTkScrollableFrame(self, fg_color=BG_DARK)
        scroll.grid(row=2, column=0, sticky="nsew", padx=16, pady=0)
        scroll.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        row = 0

        # — URL —
        section_label(scroll, "  TARGET URL").grid(row=row, column=0, sticky="ew", pady=(8, 4)); row += 1
        self.url_entry = ctk.CTkEntry(
            scroll, placeholder_text="https://example.com",
            fg_color=BG_MID, border_color=BG_CARD, text_color=TXT_MAIN,
            font=ctk.CTkFont(size=13), height=38, corner_radius=6,
        )
        self.url_entry.grid(row=row, column=0, sticky="ew", pady=(0, 12)); row += 1

        # — Profile —
        section_label(scroll, "  SCAN PROFILE").grid(row=row, column=0, sticky="ew", pady=(0, 4)); row += 1
        prow = ctk.CTkFrame(scroll, fg_color="transparent")
        prow.grid(row=row, column=0, sticky="ew", pady=(0, 12)); row += 1
        prow.grid_columnconfigure((0, 1, 2), weight=1)
        self.profile_btns = {}
        for i, (pid, plabel) in enumerate([("Quick", "Quick  (~3 min)"), ("Full", "Full  (~15 min)"), ("Stealth", "Stealth  (~20 min)")]):
            b = ctk.CTkButton(
                prow, text=plabel,
                fg_color=BG_CARD if pid != "Full" else RED,
                hover_color=RED_DIM, text_color=TXT_MAIN,
                font=ctk.CTkFont(size=12), height=34, corner_radius=6,
                command=lambda p=pid: self._set_profile(p),
            )
            b.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 4, 0))
            self.profile_btns[pid] = b

        # — Modules —
        section_label(scroll, "  MODULES").grid(row=row, column=0, sticky="ew", pady=(0, 4)); row += 1
        mgrid = ctk.CTkFrame(scroll, fg_color=BG_MID, corner_radius=6)
        mgrid.grid(row=row, column=0, sticky="ew", pady=(0, 12)); row += 1

        cols = 3
        for idx, (key, label) in enumerate(MODULES):
            var = ctk.BooleanVar(value=True)
            self.module_vars[key] = var
            cb = ctk.CTkCheckBox(
                mgrid, text=label, variable=var,
                fg_color=RED, hover_color=RED_DIM,
                text_color=TXT_MAIN, font=ctk.CTkFont(size=12),
                border_color=BG_CARD, checkmark_color="white",
            )
            cb.grid(row=idx // cols, column=idx % cols, sticky="w", padx=16, pady=6)

        # — Email —
        section_label(scroll, "  NOTIFICATION EMAIL (optional)").grid(row=row, column=0, sticky="ew", pady=(0, 4)); row += 1
        self.email_entry = ctk.CTkEntry(
            scroll, placeholder_text="your@email.com  (leave blank to skip)",
            fg_color=BG_MID, border_color=BG_CARD, text_color=TXT_MAIN,
            font=ctk.CTkFont(size=13), height=38, corner_radius=6,
        )
        self.email_entry.grid(row=row, column=0, sticky="ew", pady=(0, 16)); row += 1

        # Start button
        self.start_btn = ctk.CTkButton(
            self, text="💀   START SCAN",
            fg_color=RED, hover_color=RED_DIM,
            text_color="white", font=ctk.CTkFont(size=15, weight="bold"),
            height=46, corner_radius=0,
            command=self._start,
        )
        self.start_btn.grid(row=3, column=0, sticky="ew", padx=0, pady=(8, 0))

    def _set_profile(self, profile):
        self.profile = profile
        for pid, btn in self.profile_btns.items():
            btn.configure(fg_color=RED if pid == profile else BG_CARD)
        for key, var in self.module_vars.items():
            if profile == "Quick":
                var.set(key in QUICK_MODULES)
            else:
                var.set(True)

    def _start(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a target URL.")
            return
        enabled = [k for k, _ in MODULES if self.module_vars[k].get()]
        email = self.email_entry.get().strip() or None
        self.on_start(url, enabled, self.profile, email)


# ── Scan screen ────────────────────────────────────────────────────────────────

class ScanFrame(ctk.CTkFrame):
    def __init__(self, master, target, enabled_modules, profile, email, on_complete):
        super().__init__(master, fg_color=BG_DARK)
        self.target = target
        self.enabled_modules = enabled_modules
        self.profile = profile
        self.email = email
        self.on_complete = on_complete
        self.counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        self.module_labels = {}
        self.q = queue.Queue()
        self._build()
        self.after(50, self._poll_queue)
        self._start_scan()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Header
        hdr = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=0, height=44)
        hdr.grid(row=0, column=0, sticky="ew")
        hdr.grid_propagate(False)
        ctk.CTkLabel(
            hdr, text=f"💀  WebReaper  —  {self.target}  |  Profile: {self.profile}",
            text_color=TXT_MAIN, font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="transparent",
        ).place(relx=0.5, rely=0.5, anchor="center")

        # Body
        body = ctk.CTkFrame(self, fg_color=BG_DARK)
        body.grid(row=1, column=0, sticky="nsew", padx=12, pady=8)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        # Left: module status list
        left = ctk.CTkScrollableFrame(body, fg_color=BG_MID, corner_radius=8, width=220)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        ctk.CTkLabel(left, text="MODULES", font=ctk.CTkFont(size=10, weight="bold"),
                     text_color=RED, fg_color="transparent").pack(anchor="w", padx=8, pady=(6, 4))

        for key, label in MODULES:
            lbl = ctk.CTkLabel(left, text=f"○  {label}",
                               font=ctk.CTkFont(family="Courier", size=11),
                               text_color=BG_CARD, fg_color="transparent", anchor="w")
            lbl.pack(anchor="w", padx=8, pady=1)
            self.module_labels[key] = lbl

        # Right: live log
        right = ctk.CTkFrame(body, fg_color=BG_MID, corner_radius=8)
        right.grid(row=0, column=1, sticky="nsew")
        right.grid_rowconfigure(0, weight=1)
        right.grid_columnconfigure(0, weight=1)

        self.log_box = tk.Text(
            right, bg=BG_MID, fg=TXT_MAIN, insertbackground=TXT_MAIN,
            font=("Courier", 11), relief="flat", wrap="word",
            padx=10, pady=8, state="disabled",
        )
        self.log_box.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)
        scroll = ctk.CTkScrollbar(right, command=self.log_box.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.log_box.configure(yscrollcommand=scroll.set)

        # Tags for coloring
        self.log_box.tag_config("critical", foreground="#ff3333")
        self.log_box.tag_config("high",     foreground="#ff6b00")
        self.log_box.tag_config("medium",   foreground="#ffaa00")
        self.log_box.tag_config("low",      foreground="#00aaff")
        self.log_box.tag_config("ok",       foreground="#00ff88")
        self.log_box.tag_config("dim",      foreground=TXT_DIM)
        self.log_box.tag_config("yellow",   foreground=YELLOW)
        self.log_box.tag_config("cyan",     foreground="#00ccff")

        # Counters
        ctr = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=0, height=44)
        ctr.grid(row=2, column=0, sticky="ew")
        ctr.grid_propagate(False)
        ctr.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.cnt_labels = {}
        for i, (sev, color) in enumerate([("CRITICAL", RED), ("HIGH", ORANGE), ("MEDIUM", YELLOW), ("LOW", BLUE)]):
            lbl = ctk.CTkLabel(ctr, text=f"{sev}: 0",
                               font=ctk.CTkFont(size=12, weight="bold"),
                               text_color=color, fg_color="transparent")
            lbl.grid(row=0, column=i, padx=8, pady=8)
            self.cnt_labels[sev] = lbl

    def _log(self, msg, tag=None):
        self.log_box.configure(state="normal")
        if tag:
            self.log_box.insert("end", msg + "\n", tag)
        else:
            self.log_box.insert("end", msg + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _set_module_status(self, key, status, count=None):
        lbl = self.module_labels.get(key)
        if not lbl:
            return
        icons = {"pending": "○", "running": "◌", "done": "✓"}
        colors = {"pending": BG_CARD, "running": YELLOW, "done": GREEN}
        name = next((n for k, n in MODULES if k == key), key)
        text = f"{icons[status]}  {name}"
        if count is not None:
            text += f"  [{count}]"
        lbl.configure(text=text, text_color=colors[status])

    def _update_counters(self):
        for sev, lbl in self.cnt_labels.items():
            lbl.configure(text=f"{sev}: {self.counts[sev]}")

    def _poll_queue(self):
        try:
            while True:
                event, data = self.q.get_nowait()
                self._handle_event(event, data)
        except queue.Empty:
            pass
        self.after(50, self._poll_queue)

    def _handle_event(self, event, data):
        if event == "module_start":
            key = next((k for k, n in MODULES if n == data), data.lower().replace(" ", "_"))
            self._set_module_status(key, "running")
            self._log(f"⟳  Running: {data}", "yellow")

        elif event == "module_done":
            name = data["name"]
            count = data["count"]
            key = next((k for k, n in MODULES if n == name), name.lower().replace(" ", "_"))
            self._set_module_status(key, "done", count)
            self._log(f"✓  {name}: {count} finding(s)", "ok")

        elif event == "finding":
            f = data
            sev = f.get("severity", "INFO")
            if sev in self.counts:
                self.counts[sev] += 1
                self._update_counters()
            tag = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(sev, "dim")
            self._log(f"  [{sev}] {f['name']} — {f.get('url','')[:70]}", tag)

        elif event == "crawl_page":
            self._log(f"  Crawled: {str(data)[:80]}", "dim")

        elif event == "generating_report":
            self._log("Generating HTML report...", "cyan")

        elif event == "scan_complete":
            self._log("─" * 60)
            self._log(f"✓ SCAN COMPLETE in {int(data['duration'])}s", "ok")
            self.after(800, lambda d=data: self.on_complete(self.target, d))

    def _scan_callback(self, event, data):
        self.q.put((event, data))

    def _start_scan(self):
        self._log(f"Starting scan of {self.target}...")
        self._log(f"Profile: {self.profile}  |  Modules: {len(self.enabled_modules)}")
        self._log("─" * 60)
        t = threading.Thread(target=self._run_scan, daemon=True)
        t.start()

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
            import traceback
            self.q.put(("log_error", traceback.format_exc()))


# ── Dashboard ──────────────────────────────────────────────────────────────────

SEV_COLORS = {
    "CRITICAL": "#ff3333",
    "HIGH":     "#ff6b00",
    "MEDIUM":   "#ffaa00",
    "LOW":      "#00aaff",
    "INFO":     "#8b949e",
}
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _risk_score(findings):
    weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}
    return min(sum(weights.get(f.get("severity", "INFO"), 0) for f in findings), 100)


def _risk_label(score):
    if score >= 75: return "CRITICAL", RED
    if score >= 50: return "HIGH", ORANGE
    if score >= 25: return "MEDIUM", YELLOW
    if score > 0:   return "LOW", BLUE
    return "SAFE", GREEN


class DonutChart(tk.Canvas):
    """Draws a severity donut chart."""
    def __init__(self, parent, counts, size=180, **kw):
        super().__init__(parent, width=size, height=size,
                         bg=BG_PANEL, highlightthickness=0, **kw)
        self._draw(counts, size)

    def _draw(self, counts, size):
        total = sum(counts.values()) or 1
        cx, cy, r_out, r_in = size // 2, size // 2, size // 2 - 6, size // 2 - 38
        sevs = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        start = -90.0
        for sev in sevs:
            n = counts.get(sev, 0)
            if n == 0:
                continue
            extent = 360.0 * n / total
            x0, y0 = cx - r_out, cy - r_out
            x1, y1 = cx + r_out, cy + r_out
            self.create_arc(x0, y0, x1, y1, start=start, extent=extent,
                            fill=SEV_COLORS[sev], outline=BG_MID, width=2, style="pieslice")
            start += extent
        # Hole
        self.create_oval(cx - r_in, cy - r_in, cx + r_in, cy + r_in,
                         fill=BG_PANEL, outline=BG_PANEL)
        # Center text
        total_issues = sum(counts.get(s, 0) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
        self.create_text(cx, cy - 10, text=str(total_issues),
                         fill=TXT_MAIN, font=("Courier", 22, "bold"))
        self.create_text(cx, cy + 14, text="findings",
                         fill=TXT_DIM, font=("Courier", 10))


class DashboardFrame(ctk.CTkFrame):
    def __init__(self, master, target, scan_data, on_new_scan):
        super().__init__(master, fg_color=BG_DARK)
        self.target      = target
        self.findings    = scan_data.get("findings", [])
        self.duration    = scan_data.get("duration", 0)
        self.pages       = scan_data.get("pages_crawled", 0)
        self.forms       = scan_data.get("forms_found", 0)
        self.js_files    = scan_data.get("js_files", 0)
        self.modules_run = scan_data.get("modules_run", 0)
        self.on_new_scan = on_new_scan
        self._sorted_findings = sorted(
            self.findings, key=lambda x: SEV_ORDER.get(x.get("severity", "INFO"), 4)
        )
        self._active_filter = "ALL"
        self._build()

    # ── layout ──────────────────────────────────────────────────────────────────

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        counts = {s: 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
        for f in self.findings:
            counts[f.get("severity", "INFO")] = counts.get(f.get("severity", "INFO"), 0) + 1

        score = _risk_score(self.findings)
        risk_label, risk_color = _risk_label(score)

        self._build_header(score, risk_label, risk_color)
        self._build_stat_cards(counts, score, risk_label, risk_color)
        self._build_main(counts)

    def _build_header(self, score, risk_label, risk_color):
        hdr = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=0, height=48)
        hdr.grid(row=0, column=0, sticky="ew")
        hdr.grid_propagate(False)
        hdr.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            hdr, text="💀  WebReaper Dashboard",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=RED, fg_color="transparent",
        ).grid(row=0, column=0, padx=16, pady=8, sticky="w")

        ctk.CTkLabel(
            hdr, text=f"Target: {self.target}  |  {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            font=ctk.CTkFont(size=11), text_color=TXT_DIM, fg_color="transparent",
        ).grid(row=0, column=1, padx=8, pady=8, sticky="w")

        ctk.CTkButton(
            hdr, text="🔄  New Scan", fg_color=BG_CARD, hover_color=RED,
            text_color=TXT_MAIN, font=ctk.CTkFont(size=11),
            height=30, width=110, corner_radius=6, command=self.on_new_scan,
        ).grid(row=0, column=2, padx=16, pady=8, sticky="e")

    def _build_stat_cards(self, counts, score, risk_label, risk_color):
        strip = ctk.CTkFrame(self, fg_color=BG_DARK)
        strip.grid(row=1, column=0, sticky="ew", padx=12, pady=(8, 0))
        strip.grid_columnconfigure((0, 1, 2, 3, 4, 5), weight=1)

        # Risk score card
        self._stat_card(strip, col=0,
                        top=f"{score}/100", bottom="RISK SCORE",
                        top_color=risk_color, badge=risk_label, badge_color=risk_color)

        # Severity count cards
        for col, sev in enumerate(("CRITICAL", "HIGH", "MEDIUM", "LOW"), start=1):
            self._stat_card(strip, col=col,
                            top=str(counts[sev]), bottom=sev,
                            top_color=SEV_COLORS[sev])

        # Scan stats card
        stats_card = ctk.CTkFrame(strip, fg_color=BG_PANEL, corner_radius=10)
        stats_card.grid(row=0, column=5, sticky="nsew", padx=(6, 0), pady=0)
        for i, (label, val) in enumerate([
            ("Pages crawled", self.pages),
            ("Forms found",   self.forms),
            ("JS files",      self.js_files),
            ("Duration",      f"{int(self.duration)}s"),
            ("Modules run",   self.modules_run),
        ]):
            ctk.CTkLabel(stats_card,
                text=f"{label}:", font=ctk.CTkFont(size=10),
                text_color=TXT_DIM, fg_color="transparent", anchor="w",
            ).grid(row=i, column=0, padx=(12, 4), pady=1, sticky="w")
            ctk.CTkLabel(stats_card,
                text=str(val), font=ctk.CTkFont(size=10, weight="bold"),
                text_color=TXT_MAIN, fg_color="transparent", anchor="e",
            ).grid(row=i, column=1, padx=(0, 12), pady=1, sticky="e")

    def _stat_card(self, parent, col, top, bottom, top_color, badge=None, badge_color=None):
        card = ctk.CTkFrame(parent, fg_color=BG_PANEL, corner_radius=10)
        card.grid(row=0, column=col, sticky="nsew", padx=(0 if col == 0 else 6, 0), pady=0)
        ctk.CTkLabel(card, text=top,
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color=top_color, fg_color="transparent",
        ).pack(pady=(14, 0))
        ctk.CTkLabel(card, text=bottom,
            font=ctk.CTkFont(size=10), text_color=TXT_DIM, fg_color="transparent",
        ).pack()
        if badge:
            ctk.CTkLabel(card, text=badge,
                font=ctk.CTkFont(size=9, weight="bold"),
                text_color=badge_color, fg_color="transparent",
            ).pack(pady=(0, 10))
        else:
            card.pack_configure() if False else None
            ctk.CTkFrame(card, height=10, fg_color="transparent").pack()

    # ── main area ───────────────────────────────────────────────────────────────

    def _build_main(self, counts):
        main = ctk.CTkFrame(self, fg_color=BG_DARK)
        main.grid(row=2, column=0, sticky="nsew", padx=12, pady=8)
        main.grid_columnconfigure(0, weight=0)
        main.grid_columnconfigure(1, weight=1)
        main.grid_rowconfigure(0, weight=1)

        # Left sidebar: donut + module breakdown
        sidebar = ctk.CTkFrame(main, fg_color=BG_PANEL, corner_radius=10, width=220)
        sidebar.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        sidebar.grid_propagate(False)
        self._build_sidebar(sidebar, counts)

        # Right: filter bar + table + detail panel
        right = ctk.CTkFrame(main, fg_color=BG_DARK)
        right.grid(row=0, column=1, sticky="nsew")
        right.grid_columnconfigure(0, weight=1)
        right.grid_rowconfigure(1, weight=1)

        self._build_filter_bar(right)
        self._build_table_area(right)

    def _build_sidebar(self, parent, counts):
        ctk.CTkLabel(parent, text="SEVERITY BREAKDOWN",
            font=ctk.CTkFont(size=9, weight="bold"),
            text_color=RED, fg_color="transparent",
        ).pack(pady=(14, 4))

        DonutChart(parent, counts, size=190).pack(pady=(0, 8))

        # Legend
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            n = counts.get(sev, 0)
            row = ctk.CTkFrame(parent, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=2)
            ctk.CTkFrame(row, width=10, height=10, corner_radius=2,
                         fg_color=SEV_COLORS[sev]).pack(side="left", padx=(0, 6))
            ctk.CTkLabel(row, text=sev, font=ctk.CTkFont(size=10),
                         text_color=TXT_DIM, fg_color="transparent").pack(side="left")
            ctk.CTkLabel(row, text=str(n), font=ctk.CTkFont(size=10, weight="bold"),
                         text_color=SEV_COLORS[sev], fg_color="transparent").pack(side="right")

        ctk.CTkFrame(parent, height=1, fg_color=BG_CARD).pack(fill="x", padx=12, pady=10)

        # Module hit breakdown
        ctk.CTkLabel(parent, text="BY MODULE",
            font=ctk.CTkFont(size=9, weight="bold"),
            text_color=RED, fg_color="transparent",
        ).pack(pady=(0, 6))

        module_counts = {}
        for f in self.findings:
            m = f.get("module", "Unknown")
            module_counts[m] = module_counts.get(m, 0) + 1

        scroll_mods = ctk.CTkScrollableFrame(parent, fg_color="transparent", height=160)
        scroll_mods.pack(fill="x", padx=8, pady=(0, 12))
        for mod, n in sorted(module_counts.items(), key=lambda x: -x[1]):
            row = ctk.CTkFrame(scroll_mods, fg_color="transparent")
            row.pack(fill="x", pady=1)
            ctk.CTkLabel(row, text=mod[:22], font=ctk.CTkFont(size=9),
                         text_color=TXT_DIM, fg_color="transparent", anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=str(n), font=ctk.CTkFont(size=9, weight="bold"),
                         text_color=TXT_MAIN, fg_color="transparent").pack(side="right")

    def _build_filter_bar(self, parent):
        bar = ctk.CTkFrame(parent, fg_color=BG_DARK)
        bar.grid(row=0, column=0, sticky="ew", pady=(0, 6))

        ctk.CTkLabel(bar, text="FINDINGS",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=RED, fg_color="transparent",
        ).pack(side="left", padx=(0, 12))

        self._filter_btns = {}
        for label in ("ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            btn = ctk.CTkButton(
                bar, text=label, width=70, height=26,
                font=ctk.CTkFont(size=10),
                fg_color=RED if label == "ALL" else BG_CARD,
                hover_color=RED_DIM, text_color=TXT_MAIN,
                corner_radius=6,
                command=lambda l=label: self._apply_filter(l),
            )
            btn.pack(side="left", padx=(0, 4))
            self._filter_btns[label] = btn

    def _apply_filter(self, label):
        self._active_filter = label
        for l, btn in self._filter_btns.items():
            btn.configure(fg_color=RED if l == label else BG_CARD)
        self._populate_table()

    def _build_table_area(self, parent):
        area = ctk.CTkFrame(parent, fg_color=BG_DARK)
        area.grid(row=1, column=0, sticky="nsew")
        area.grid_columnconfigure(0, weight=3)
        area.grid_columnconfigure(1, weight=2)
        area.grid_rowconfigure(0, weight=1)

        # Table
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Reaper.Treeview",
            background=BG_MID, foreground=TXT_MAIN, fieldbackground=BG_MID,
            borderwidth=0, font=("Courier", 11), rowheight=26,
        )
        style.configure("Reaper.Treeview.Heading",
            background=BG_PANEL, foreground=RED, font=("Courier", 10, "bold"), relief="flat",
        )
        style.map("Reaper.Treeview", background=[("selected", BG_CARD)])

        tframe = ctk.CTkFrame(area, fg_color=BG_MID, corner_radius=8)
        tframe.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        tframe.grid_rowconfigure(0, weight=1)
        tframe.grid_columnconfigure(0, weight=1)

        cols = ("#", "Sev", "Vulnerability", "URL", "Module")
        self.tree = ttk.Treeview(tframe, columns=cols, show="headings", style="Reaper.Treeview")
        for col, w in zip(cols, [32, 80, 220, 200, 110]):
            self.tree.heading(col, text=col,
                command=lambda c=col: self._sort_by(c))
            self.tree.column(col, width=w, minwidth=w, anchor="w")
        self.tree.grid(row=0, column=0, sticky="nsew")

        vsb = ctk.CTkScrollbar(tframe, command=self.tree.yview)
        vsb.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=vsb.set)
        for sev, color in SEV_COLORS.items():
            self.tree.tag_configure(sev, foreground=color)

        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self._populate_table()

        # Detail panel
        self.detail = ctk.CTkScrollableFrame(area, fg_color=BG_PANEL, corner_radius=8)
        self.detail.grid(row=0, column=1, sticky="nsew")
        self.detail.grid_columnconfigure(0, weight=1)
        self._detail_placeholder()

    def _populate_table(self):
        self.tree.delete(*self.tree.get_children())
        filtered = (
            self._sorted_findings if self._active_filter == "ALL"
            else [f for f in self._sorted_findings if f.get("severity") == self._active_filter]
        )
        self._row_data = {}
        for i, f in enumerate(filtered, 1):
            sev = f.get("severity", "INFO")
            iid = self.tree.insert("", "end", values=(
                i, sev, f.get("name", "")[:50], f.get("url", "")[:50], f.get("module", "")
            ), tags=(sev,))
            self._row_data[iid] = f

    def _sort_by(self, col):
        col_map = {"#": None, "Sev": "severity", "Vulnerability": "name",
                   "URL": "url", "Module": "module"}
        key = col_map.get(col)
        if key == "severity":
            self._sorted_findings.sort(key=lambda x: SEV_ORDER.get(x.get("severity", "INFO"), 4))
        elif key:
            self._sorted_findings.sort(key=lambda x: x.get(key, "").lower())
        self._populate_table()

    def _on_select(self, _event):
        sel = self.tree.selection()
        if not sel:
            return
        f = self._row_data.get(sel[0])
        if f:
            self._show_detail(f)

    def _detail_placeholder(self):
        for w in self.detail.winfo_children():
            w.destroy()
        ctk.CTkLabel(self.detail, text="← Click a finding\nto see details",
            font=ctk.CTkFont(size=12), text_color=TXT_DIM,
            fg_color="transparent", justify="center",
        ).pack(expand=True, pady=60)

    def _show_detail(self, f):
        for w in self.detail.winfo_children():
            w.destroy()

        sev = f.get("severity", "INFO")
        color = SEV_COLORS.get(sev, TXT_DIM)

        # Severity badge
        badge = ctk.CTkFrame(self.detail, fg_color=color, corner_radius=6, height=30)
        badge.pack(fill="x", padx=12, pady=(12, 6))
        badge.pack_propagate(False)
        ctk.CTkLabel(badge, text=f"  {sev}  ", font=ctk.CTkFont(size=11, weight="bold"),
                     text_color="white", fg_color="transparent").pack(side="left", padx=6)
        ctk.CTkLabel(badge, text=f.get("module", ""),
                     font=ctk.CTkFont(size=10), text_color="white",
                     fg_color="transparent").pack(side="right", padx=8)

        def field(label, value, value_color=TXT_MAIN):
            ctk.CTkLabel(self.detail, text=label,
                font=ctk.CTkFont(size=9, weight="bold"),
                text_color=RED, fg_color="transparent", anchor="w",
            ).pack(fill="x", padx=12, pady=(8, 1))
            ctk.CTkLabel(self.detail, text=value or "—",
                font=ctk.CTkFont(size=11), text_color=value_color,
                fg_color=BG_CARD, corner_radius=4, anchor="w",
                wraplength=300, justify="left",
            ).pack(fill="x", padx=12, pady=(0, 2), ipady=4, ipadx=6)

        field("VULNERABILITY", f.get("name", "—"))
        field("URL", f.get("url", "—"), TXT_DIM)
        field("PARAMETER", f.get("param", "—") if f.get("param") else "—", TXT_DIM)

        desc = f.get("description") or f.get("detail") or f.get("evidence") or "No description available."
        field("DESCRIPTION", str(desc)[:400])

        rec = f.get("recommendation", "")
        if rec:
            field("RECOMMENDATION", str(rec)[:400], GREEN)


# ── Main App Window ────────────────────────────────────────────────────────────

class WebReaperApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("WebReaper — Web Vulnerability Scanner")
        self.geometry("1100x760")
        self.minsize(900, 620)
        self.configure(fg_color=BG_DARK)

        try:
            self.iconbitmap(self._icon_path())
        except Exception:
            pass

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._current_frame = None
        self._show_home()

    def _icon_path(self):
        base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base, "icon.ico")

    def _show_home(self):
        self._swap(HomeFrame(self, on_start=self._start_scan))

    def _start_scan(self, url, enabled, profile, email):
        self._swap(ScanFrame(self, url, enabled, profile, email, on_complete=self._show_dashboard))

    def _show_dashboard(self, target, scan_data):
        self._swap(DashboardFrame(self, target, scan_data, on_new_scan=self._show_home))

    def _swap(self, frame):
        if self._current_frame:
            self._current_frame.destroy()
        self._current_frame = frame
        frame.grid(row=0, column=0, sticky="nsew")


if __name__ == "__main__":
    app = WebReaperApp()
    app.mainloop()
