import os
import sys
import threading
import subprocess
import queue
import webbrowser
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
            self._log(f"Report: {os.path.abspath(data['report_path'])}", "ok")
            self.after(800, lambda: self.on_complete(self.target, data["findings"], data["report_path"]))

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


# ── Results screen ─────────────────────────────────────────────────────────────

class ResultsFrame(ctk.CTkFrame):
    def __init__(self, master, target, findings, report_path, on_new_scan):
        super().__init__(master, fg_color=BG_DARK)
        self.target = target
        self.findings = findings
        self.report_path = report_path
        self.on_new_scan = on_new_scan
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            sev = f.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1

        # Header
        hdr = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=0, height=52)
        hdr.grid(row=0, column=0, sticky="ew")
        hdr.grid_propagate(False)
        ctk.CTkLabel(
            hdr,
            text=(f"✓  Scan Complete  —  {len(self.findings)} findings  |  "
                  f"Critical: {counts['CRITICAL']}   High: {counts['HIGH']}   "
                  f"Medium: {counts['MEDIUM']}   Low: {counts['LOW']}"),
            text_color=GREEN, font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="transparent",
        ).place(relx=0.5, rely=0.5, anchor="center")

        # Action buttons
        arow = ctk.CTkFrame(self, fg_color=BG_DARK)
        arow.grid(row=1, column=0, sticky="ew", padx=12, pady=8)
        for text, cmd in [
            ("📄  Open Report", self._open_report),
            ("📤  Export PDF",  self._export_pdf),
            ("🔄  New Scan",    self.on_new_scan),
        ]:
            ctk.CTkButton(
                arow, text=text, fg_color=BG_CARD, hover_color=RED,
                text_color=TXT_MAIN, font=ctk.CTkFont(size=12),
                height=36, corner_radius=6, command=cmd,
            ).pack(side="left", padx=(0, 8))

        # Findings table using ttk.Treeview (native, fast)
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Reaper.Treeview",
            background=BG_MID, foreground=TXT_MAIN, fieldbackground=BG_MID,
            borderwidth=0, font=("Courier", 11), rowheight=26,
        )
        style.configure("Reaper.Treeview.Heading",
            background=BG_PANEL, foreground=RED, font=("Courier", 11, "bold"),
            relief="flat",
        )
        style.map("Reaper.Treeview", background=[("selected", BG_CARD)])

        tframe = ctk.CTkFrame(self, fg_color=BG_MID, corner_radius=8)
        tframe.grid(row=2, column=0, sticky="nsew", padx=12, pady=(0, 12))
        tframe.grid_rowconfigure(0, weight=1)
        tframe.grid_columnconfigure(0, weight=1)

        cols = ("#", "Severity", "Vulnerability", "URL", "Module")
        self.tree = ttk.Treeview(tframe, columns=cols, show="headings", style="Reaper.Treeview")
        self.tree.grid(row=0, column=0, sticky="nsew")

        widths = [40, 90, 260, 300, 130]
        for col, w in zip(cols, widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, minwidth=w, anchor="w")

        vsb = ctk.CTkScrollbar(tframe, command=self.tree.yview)
        vsb.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=vsb.set)

        self.tree.tag_configure("CRITICAL", foreground="#ff3333")
        self.tree.tag_configure("HIGH",     foreground="#ff6b00")
        self.tree.tag_configure("MEDIUM",   foreground="#ffaa00")
        self.tree.tag_configure("LOW",      foreground="#00aaff")
        self.tree.tag_configure("INFO",     foreground=TXT_DIM)

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_f = sorted(self.findings, key=lambda x: sev_order.get(x.get("severity", "INFO"), 4))
        for i, f in enumerate(sorted_f, 1):
            sev = f.get("severity", "INFO")
            self.tree.insert("", "end", values=(
                i, sev, f.get("name", "")[:60], f.get("url", "")[:60], f.get("module", "")
            ), tags=(sev,))

    def _open_report(self):
        if self.report_path:
            path = os.path.abspath(self.report_path)
            webbrowser.open(f"file://{path}")

    def _export_pdf(self):
        if not self.report_path:
            return
        messagebox.showinfo("Export PDF", "Generating PDF... this may take a moment.")
        def _do():
            from report.generator import export_pdf
            pdf_path = export_pdf(self.report_path)
            if pdf_path:
                webbrowser.open(f"file://{os.path.abspath(pdf_path)}")
                messagebox.showinfo("PDF Exported", f"Saved to:\n{os.path.abspath(pdf_path)}")
            else:
                messagebox.showwarning("PDF Failed", "PDF export failed.\nInstall Playwright: playwright install chromium")
        threading.Thread(target=_do, daemon=True).start()


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
        self._swap(ScanFrame(self, url, enabled, profile, email, on_complete=self._show_results))

    def _show_results(self, target, findings, report_path):
        self._swap(ResultsFrame(self, target, findings, report_path, on_new_scan=self._show_home))

    def _swap(self, frame):
        if self._current_frame:
            self._current_frame.destroy()
        self._current_frame = frame
        frame.grid(row=0, column=0, sticky="nsew")


if __name__ == "__main__":
    app = WebReaperApp()
    app.mainloop()
