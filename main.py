import os
import sys
import threading
import queue
from datetime import datetime

import customtkinter as ctk
from tkinter import ttk, messagebox
import tkinter as tk

# ─── Design System ────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

BG      = "#0d1117"
SURF    = "#161b22"
SURF2   = "#21262d"
BORDER  = "#30363d"
RED     = "#ff3333"
RED2    = "#cc0000"
GREEN   = "#3fb950"
YELLOW  = "#e3b341"
ORANGE  = "#ff6b00"
BLUE    = "#58a6ff"
CYAN    = "#56d3e8"
TXT     = "#e6edf3"
TXT2    = "#8b949e"
TXT3    = "#3d444d"

SEV_COLOR = {
    "CRITICAL": "#ff3333",
    "HIGH":     "#ff6b00",
    "MEDIUM":   "#e3b341",
    "LOW":      "#58a6ff",
    "INFO":     "#8b949e",
}
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

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
    ("js",              "JS Analyzer"),
    ("access_control",  "Access Control"),
    ("api",             "API Discovery"),
    ("subdomain",       "Subdomain Takeover"),
    ("email",           "Email Security"),
    ("rate_limit",      "Rate Limit Tester"),
    ("http_methods",    "HTTP Methods"),
    ("screenshots",     "Screenshots"),
]
MODULE_LABEL = dict(MODULES)
QUICK_MODULES = {"headers", "ssl", "sensitive_files", "cookies", "csrf"}

MODULE_CATEGORIES = [
    ("INJECTION ATTACKS",  ["xss", "sqli", "open_redirect"]),
    ("AUTHENTICATION",     ["cookies", "csrf", "access_control"]),
    ("TRANSPORT SECURITY", ["headers", "ssl"]),
    ("DISCOVERY",          ["cms", "cve", "js", "api", "subdomain", "sensitive_files"]),
    ("EXTRAS",             ["email", "rate_limit", "http_methods", "screenshots"]),
]


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _bind_all(widget, seq, cb):
    widget.bind(seq, cb)
    for child in widget.winfo_children():
        _bind_all(child, seq, cb)

def _sep(parent, color=BORDER, pad_y=12, pad_x=0):
    ctk.CTkFrame(parent, fg_color=color, height=1).pack(
        fill="x", padx=pad_x, pady=pad_y)

def _section_title(parent, text, color=TXT2):
    f = ctk.CTkFrame(parent, fg_color="transparent")
    ctk.CTkFrame(f, fg_color=RED, width=3, height=16, corner_radius=2).pack(
        side="left", padx=(0, 8))
    ctk.CTkLabel(f, text=text, font=ctk.CTkFont(size=10, weight="bold"),
                 text_color=color, fg_color="transparent").pack(side="left")
    return f


# ─── Top-bar (shared across all screens) ─────────────────────────────────────

def _topbar(parent, subtitle="", right_widget=None):
    bar = ctk.CTkFrame(parent, fg_color=SURF, corner_radius=0, height=52)
    bar.grid_columnconfigure(1, weight=1)

    logo = ctk.CTkFrame(bar, fg_color="transparent")
    logo.grid(row=0, column=0, padx=20, pady=8, sticky="w")
    ctk.CTkLabel(logo, text="◈", font=ctk.CTkFont(size=22, weight="bold"),
                 text_color=RED, fg_color="transparent").pack(side="left", padx=(0, 6))
    ctk.CTkLabel(logo, text="WEBREAPER", font=ctk.CTkFont(size=16, weight="bold"),
                 text_color=TXT, fg_color="transparent").pack(side="left")

    if subtitle:
        ctk.CTkLabel(bar, text=subtitle, font=ctk.CTkFont(size=11),
                     text_color=TXT2, fg_color="transparent").grid(
            row=0, column=1, padx=12, sticky="w")

    if right_widget:
        right_widget(bar).grid(row=0, column=2, padx=20, pady=8, sticky="e")

    return bar


# ─── Home Screen ──────────────────────────────────────────────────────────────

class HomeFrame(ctk.CTkFrame):
    def __init__(self, master, on_start):
        super().__init__(master, fg_color=BG)
        self.on_start = on_start
        self.profile = "Full"
        self.module_vars = {}
        self._profile_frames = {}
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # ── Top bar ──
        def _right(bar):
            f = ctk.CTkFrame(bar, fg_color="#1a0f00", corner_radius=6,
                             border_color=ORANGE, border_width=1)
            ctk.CTkLabel(f, text="⚠  Authorized Testing Only",
                         font=ctk.CTkFont(size=10, weight="bold"),
                         text_color=ORANGE, fg_color="transparent").pack(padx=12, pady=5)
            return f

        tb = _topbar(self, subtitle="Web Vulnerability Scanner  ·  v1.0", right_widget=_right)
        tb.grid(row=0, column=0, sticky="ew")

        # ── Body (two columns) ──
        body = ctk.CTkFrame(self, fg_color=BG)
        body.grid(row=1, column=0, sticky="nsew")
        body.grid_columnconfigure(0, weight=0, minsize=380)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        self._build_config(body)
        self._build_modules(body)

        # ── Bottom action bar ──
        bar = ctk.CTkFrame(self, fg_color=SURF, corner_radius=0, height=60)
        bar.grid(row=2, column=0, sticky="ew")
        bar.grid_propagate(False)
        bar.grid_columnconfigure(0, weight=1)

        self._count_lbl = ctk.CTkLabel(bar,
            text=f"{len(MODULES)} of {len(MODULES)} modules selected",
            font=ctk.CTkFont(size=11), text_color=TXT2, fg_color="transparent")
        self._count_lbl.grid(row=0, column=0, padx=24, sticky="w")

        ctk.CTkButton(bar, text="▶   START SCAN",
            fg_color=RED, hover_color=RED2, text_color="white",
            font=ctk.CTkFont(size=13, weight="bold"),
            height=40, width=180, corner_radius=8,
            command=self._start,
        ).grid(row=0, column=1, padx=24, pady=10, sticky="e")

    # ── Left config panel ────────────────────────────────────────────────────

    def _build_config(self, parent):
        panel = ctk.CTkFrame(parent, fg_color=SURF, corner_radius=0)
        panel.grid(row=0, column=0, sticky="nsew")
        panel.grid_columnconfigure(0, weight=1)

        # Right divider
        ctk.CTkFrame(panel, fg_color=BORDER, width=1).place(
            relx=1.0, rely=0, anchor="ne", relheight=1.0)

        inner = ctk.CTkScrollableFrame(panel, fg_color="transparent")
        inner.grid(row=0, column=0, sticky="nsew", padx=24, pady=20)
        inner.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(0, weight=1)

        r = 0

        # URL
        _section_title(inner, "TARGET URL").grid(row=r, column=0, sticky="w", pady=(0, 8)); r += 1
        self.url_entry = ctk.CTkEntry(
            inner, placeholder_text="https://target.com",
            fg_color=SURF2, border_color=BORDER, border_width=1,
            text_color=TXT, placeholder_text_color=TXT3,
            font=ctk.CTkFont(size=13), height=42, corner_radius=8,
        )
        self.url_entry.grid(row=r, column=0, sticky="ew", pady=(0, 20)); r += 1

        # Profile
        _section_title(inner, "SCAN PROFILE").grid(row=r, column=0, sticky="w", pady=(0, 10)); r += 1

        profiles = [
            ("Quick",   "⚡", "~3 min",  "5 core security checks"),
            ("Full",    "◈",  "~15 min", "All 18 scan modules"),
            ("Stealth", "◉",  "~20 min", "Slow, low-noise mode"),
        ]
        for pid, icon, eta, desc in profiles:
            active = pid == "Full"
            pf = ctk.CTkFrame(inner,
                fg_color=RED if active else SURF2,
                border_color=RED if active else BORDER,
                border_width=1, corner_radius=8)
            pf.grid(row=r, column=0, sticky="ew", pady=(0, 6)); r += 1
            pf.grid_columnconfigure(1, weight=1)

            ctk.CTkLabel(pf, text=icon, font=ctk.CTkFont(size=20),
                text_color="white", fg_color="transparent",
            ).grid(row=0, column=0, rowspan=2, padx=(16, 10), pady=12)
            ctk.CTkLabel(pf, text=pid, font=ctk.CTkFont(size=13, weight="bold"),
                text_color="white", fg_color="transparent", anchor="w",
            ).grid(row=0, column=1, sticky="w", pady=(10, 0), padx=(0, 12))
            ctk.CTkLabel(pf, text=f"{eta}  ·  {desc}",
                font=ctk.CTkFont(size=10),
                text_color="#ffffff99" if active else TXT2,
                fg_color="transparent", anchor="w",
            ).grid(row=1, column=1, sticky="w", pady=(0, 10), padx=(0, 12))

            ctk.CTkLabel(pf, text=eta, font=ctk.CTkFont(size=9, weight="bold"),
                text_color="#ffffff66" if active else TXT3,
                fg_color="transparent",
            ).grid(row=0, column=2, rowspan=2, padx=(0, 14))

            self._profile_frames[pid] = pf
            _bind_all(pf, "<Button-1>", lambda e, p=pid: self._set_profile(p))
            pf.configure(cursor="hand2")

        # Email
        ctk.CTkFrame(inner, fg_color=BORDER, height=1).grid(
            row=r, column=0, sticky="ew", pady=(14, 16)); r += 1
        _section_title(inner, "NOTIFICATION EMAIL (optional)").grid(
            row=r, column=0, sticky="w", pady=(0, 8)); r += 1
        self.email_entry = ctk.CTkEntry(
            inner, placeholder_text="your@email.com",
            fg_color=SURF2, border_color=BORDER, border_width=1,
            text_color=TXT, placeholder_text_color=TXT3,
            font=ctk.CTkFont(size=12), height=38, corner_radius=8,
        )
        self.email_entry.grid(row=r, column=0, sticky="ew"); r += 1

    # ── Right modules panel ──────────────────────────────────────────────────

    def _build_modules(self, parent):
        panel = ctk.CTkFrame(parent, fg_color=BG)
        panel.grid(row=0, column=1, sticky="nsew")
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(1, weight=1)

        # Module panel header
        hdr = ctk.CTkFrame(panel, fg_color=SURF, corner_radius=0, height=44)
        hdr.grid(row=0, column=0, sticky="ew")
        hdr.grid_propagate(False)
        hdr.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(hdr, text="SCAN MODULES",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=TXT2, fg_color="transparent",
        ).grid(row=0, column=0, padx=20, sticky="w")

        btn_row = ctk.CTkFrame(hdr, fg_color="transparent")
        btn_row.grid(row=0, column=2, padx=16, sticky="e")
        for label, val in [("All", True), ("None", False)]:
            ctk.CTkButton(btn_row, text=label, width=48, height=24,
                fg_color=SURF2, hover_color=RED2, text_color=TXT2,
                font=ctk.CTkFont(size=9), corner_radius=4,
                command=lambda v=val: self._set_all(v),
            ).pack(side="left", padx=(0, 4))

        # Scrollable module grid
        scroll = ctk.CTkScrollableFrame(panel, fg_color=BG)
        scroll.grid(row=1, column=0, sticky="nsew", padx=16, pady=16)
        scroll.grid_columnconfigure(0, weight=1)

        r = 0
        for cat_name, keys in MODULE_CATEGORIES:
            cat_card = ctk.CTkFrame(scroll, fg_color=SURF, corner_radius=8,
                                    border_color=BORDER, border_width=1)
            cat_card.grid(row=r, column=0, sticky="ew", pady=(0, 8)); r += 1
            cat_card.grid_columnconfigure(0, weight=1)

            # Category header row
            cat_hdr = ctk.CTkFrame(cat_card, fg_color="transparent")
            cat_hdr.grid(row=0, column=0, sticky="ew", padx=12, pady=(10, 6))
            cat_hdr.grid_columnconfigure(1, weight=1)

            ctk.CTkFrame(cat_hdr, fg_color=RED, width=3, height=12,
                         corner_radius=2).grid(row=0, column=0, padx=(0, 8))
            ctk.CTkLabel(cat_hdr, text=cat_name,
                font=ctk.CTkFont(size=10, weight="bold"),
                text_color=TXT2, fg_color="transparent",
            ).grid(row=0, column=1, sticky="w")

            n_selected = len(keys)
            self._cat_count_labels = getattr(self, "_cat_count_labels", {})
            count_lbl = ctk.CTkLabel(cat_hdr,
                text=f"{n_selected}/{len(keys)}",
                font=ctk.CTkFont(size=9), text_color=TXT3, fg_color="transparent")
            count_lbl.grid(row=0, column=2, padx=(4, 8))
            self._cat_count_labels[cat_name] = (count_lbl, keys)

            ctk.CTkButton(cat_hdr, text="toggle", width=52, height=20,
                fg_color=SURF2, hover_color=SURF, text_color=TXT2,
                font=ctk.CTkFont(size=9), corner_radius=4,
                command=lambda ks=keys, cn=cat_name: self._toggle_category(ks, cn),
            ).grid(row=0, column=3, padx=(4, 0))

            # Checkbox grid
            cb_grid = ctk.CTkFrame(cat_card, fg_color="transparent")
            cb_grid.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 10))
            for c in range(3):
                cb_grid.grid_columnconfigure(c, weight=1)

            for j, key in enumerate(keys):
                var = ctk.BooleanVar(value=True)
                self.module_vars[key] = var
                cb = ctk.CTkCheckBox(
                    cb_grid, text=MODULE_LABEL.get(key, key), variable=var,
                    fg_color=RED, hover_color=RED2,
                    text_color=TXT, font=ctk.CTkFont(size=11),
                    border_color=BORDER, checkmark_color="white",
                    command=self._update_count,
                )
                cb.grid(row=j // 3, column=j % 3, sticky="w", padx=(4, 4), pady=3)

    # ── Logic ───────────────────────────────────────────────────────────────

    def _set_profile(self, profile):
        self.profile = profile
        for pid, pf in self._profile_frames.items():
            active = pid == profile
            pf.configure(
                fg_color=RED if active else SURF2,
                border_color=RED if active else BORDER,
            )
            for w in pf.winfo_children():
                if isinstance(w, ctk.CTkLabel):
                    try:
                        txt = w.cget("text")
                        if txt in ("⚡", "◈", "◉"):
                            w.configure(text_color="white")
                        elif w.cget("font").cget("weight") == "bold":
                            w.configure(text_color="white")
                        else:
                            w.configure(text_color="#ffffff99" if active else TXT2)
                    except Exception:
                        pass
        for key, var in self.module_vars.items():
            var.set(key in QUICK_MODULES if profile == "Quick" else True)
        self._update_count()

    def _set_all(self, val):
        for var in self.module_vars.values():
            var.set(val)
        self._update_count()

    def _toggle_category(self, keys, cat_name):
        any_off = any(not self.module_vars[k].get() for k in keys if k in self.module_vars)
        for k in keys:
            if k in self.module_vars:
                self.module_vars[k].set(any_off)
        self._update_count()

    def _update_count(self):
        n = sum(1 for v in self.module_vars.values() if v.get())
        if hasattr(self, "_count_lbl"):
            self._count_lbl.configure(text=f"{n} of {len(MODULES)} modules selected")
        if hasattr(self, "_cat_count_labels"):
            for cat_name, (lbl, keys) in self._cat_count_labels.items():
                sel = sum(1 for k in keys if k in self.module_vars and self.module_vars[k].get())
                lbl.configure(text=f"{sel}/{len(keys)}")

    def _start(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("WebReaper", "Please enter a target URL.")
            return
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        enabled = [k for k, _ in MODULES if self.module_vars.get(k, ctk.BooleanVar()).get()]
        if not enabled:
            messagebox.showerror("WebReaper", "Select at least one module.")
            return
        self.on_start(url, enabled, self.profile, self.email_entry.get().strip() or None)


# ─── Scan Screen ──────────────────────────────────────────────────────────────

class ScanFrame(ctk.CTkFrame):
    def __init__(self, master, target, enabled_modules, profile, email, on_complete):
        super().__init__(master, fg_color=BG)
        self.target          = target
        self.enabled_modules = enabled_modules
        self.profile         = profile
        self.email           = email
        self.on_complete     = on_complete
        self.counts          = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        self.module_rows     = {}
        self.q               = queue.Queue()
        self._pulse_state    = False
        self._current_key    = None
        self._build()
        self.after(50, self._poll_queue)
        self._start_scan()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # ── Top bar ──
        tb = _topbar(self, subtitle=f"{self.target}  ·  {self.profile} profile")
        tb.grid(row=0, column=0, sticky="ew")

        # ── Body ──
        body = ctk.CTkFrame(self, fg_color=BG)
        body.grid(row=1, column=0, sticky="nsew", padx=16, pady=12)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        # Left — module list
        self._build_module_panel(body)

        # Right — live log
        self._build_log_panel(body)

        # ── Status bar ──
        self._build_status_bar()

    def _build_module_panel(self, parent):
        panel = ctk.CTkFrame(parent, fg_color=SURF, corner_radius=10,
                             border_color=BORDER, border_width=1)
        panel.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        panel.grid_rowconfigure(1, weight=1)
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_propagate(False)
        panel.configure(width=240)

        ctk.CTkLabel(panel, text="MODULES",
            font=ctk.CTkFont(size=9, weight="bold"),
            text_color=TXT2, fg_color="transparent",
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(12, 6))

        scroll = ctk.CTkScrollableFrame(panel, fg_color="transparent")
        scroll.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))
        scroll.grid_columnconfigure(0, weight=1)

        for key, label in MODULES:
            row_f = ctk.CTkFrame(scroll, fg_color="transparent", height=30)
            row_f.grid(sticky="ew", pady=1)
            row_f.grid_columnconfigure(1, weight=1)
            row_f.grid_propagate(False)

            dot = tk.Canvas(row_f, width=10, height=10, bg=SURF,
                            highlightthickness=0)
            dot.grid(row=0, column=0, padx=(8, 8))
            dot.create_oval(1, 1, 9, 9, fill=TXT3, outline="")

            lbl = ctk.CTkLabel(row_f, text=label,
                font=ctk.CTkFont(size=11), text_color=TXT3,
                fg_color="transparent", anchor="w")
            lbl.grid(row=0, column=1, sticky="w")

            count_lbl = ctk.CTkLabel(row_f, text="",
                font=ctk.CTkFont(size=9), text_color=TXT3,
                fg_color="transparent")
            count_lbl.grid(row=0, column=2, padx=(0, 8))

            self.module_rows[key] = (dot, lbl, count_lbl)

    def _build_log_panel(self, parent):
        panel = ctk.CTkFrame(parent, fg_color=SURF, corner_radius=10,
                             border_color=BORDER, border_width=1)
        panel.grid(row=0, column=1, sticky="nsew")
        panel.grid_rowconfigure(1, weight=1)
        panel.grid_columnconfigure(0, weight=1)

        # Log header
        log_hdr = ctk.CTkFrame(panel, fg_color="transparent", height=36)
        log_hdr.grid(row=0, column=0, sticky="ew", padx=14, pady=(10, 0))
        log_hdr.grid_columnconfigure(1, weight=1)
        log_hdr.grid_propagate(False)

        ctk.CTkLabel(log_hdr, text="LIVE OUTPUT",
            font=ctk.CTkFont(size=9, weight="bold"),
            text_color=TXT2, fg_color="transparent",
        ).grid(row=0, column=0, sticky="w")

        self._status_dot = tk.Canvas(log_hdr, width=8, height=8,
                                     bg=SURF, highlightthickness=0)
        self._status_dot.grid(row=0, column=2, padx=(0, 6))
        self._status_dot.create_oval(1, 1, 7, 7, fill=GREEN, outline="", tags="dot")

        ctk.CTkLabel(log_hdr, text="SCANNING",
            font=ctk.CTkFont(size=9, weight="bold"),
            text_color=GREEN, fg_color="transparent",
        ).grid(row=0, column=3)

        # Log text
        log_frame = ctk.CTkFrame(panel, fg_color="transparent")
        log_frame.grid(row=1, column=0, sticky="nsew", padx=2, pady=(6, 2))
        log_frame.grid_rowconfigure(0, weight=1)
        log_frame.grid_columnconfigure(0, weight=1)

        self.log_box = tk.Text(
            log_frame, bg=BG, fg=TXT, insertbackground=TXT,
            font=("Courier", 11), relief="flat", wrap="word",
            padx=14, pady=10, state="disabled",
            selectbackground=SURF2,
        )
        self.log_box.grid(row=0, column=0, sticky="nsew")
        sb = ctk.CTkScrollbar(log_frame, command=self.log_box.yview)
        sb.grid(row=0, column=1, sticky="ns", padx=(0, 4))
        self.log_box.configure(yscrollcommand=sb.set)

        for tag, color in [
            ("critical", "#ff3333"), ("high", "#ff6b00"),
            ("medium", "#e3b341"), ("low", "#58a6ff"),
            ("ok", GREEN), ("dim", TXT2), ("warn", YELLOW),
            ("cyan", CYAN), ("head", TXT),
        ]:
            self.log_box.tag_config(tag, foreground=color)

    def _build_status_bar(self):
        bar = ctk.CTkFrame(self, fg_color=SURF, corner_radius=0, height=44)
        bar.grid(row=2, column=0, sticky="ew")
        bar.grid_propagate(False)
        bar.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)

        self._cnt_labels = {}
        for i, (sev, color, label) in enumerate([
            ("CRITICAL", "#ff3333", "Critical"),
            ("HIGH",     "#ff6b00", "High"),
            ("MEDIUM",   "#e3b341", "Medium"),
            ("LOW",      "#58a6ff", "Low"),
        ]):
            f = ctk.CTkFrame(bar, fg_color="transparent")
            f.grid(row=0, column=i, padx=20, pady=6, sticky="")
            n_lbl = ctk.CTkLabel(f, text="0",
                font=ctk.CTkFont(size=16, weight="bold"),
                text_color=color, fg_color="transparent")
            n_lbl.pack(side="left", padx=(0, 6))
            ctk.CTkLabel(f, text=label, font=ctk.CTkFont(size=10),
                text_color=TXT2, fg_color="transparent").pack(side="left")
            self._cnt_labels[sev] = n_lbl

        self._scanning_lbl = ctk.CTkLabel(bar, text="Initializing…",
            font=ctk.CTkFont(size=10), text_color=TXT2, fg_color="transparent")
        self._scanning_lbl.grid(row=0, column=4, padx=20, sticky="e")

    # ── Internals ────────────────────────────────────────────────────────────

    def _log(self, msg, tag=None):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", msg + "\n", tag or ())
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _set_module(self, key, status, count=None):
        row = self.module_rows.get(key)
        if not row:
            return
        dot, lbl, clbl = row
        cfg = {
            "pending": (TXT3,   TXT3,  ""),
            "running": (YELLOW, TXT,   ""),
            "done0":   (GREEN,  TXT2,  ""),
            "done":    (RED,    TXT,   ""),
        }
        dot_c, txt_c, _ = cfg.get(status, cfg["pending"])
        dot.delete("all")
        dot.create_oval(1, 1, 9, 9, fill=dot_c, outline="")
        lbl.configure(text_color=txt_c)
        if count is not None:
            clbl.configure(text=f"[{count}]" if count > 0 else "✓",
                           text_color=RED if count > 0 else GREEN)

    def _pulse(self):
        if self._current_key:
            row = self.module_rows.get(self._current_key)
            if row:
                dot, _, _ = row
                self._pulse_state = not self._pulse_state
                c = YELLOW if self._pulse_state else "#7a5f00"
                dot.delete("all")
                dot.create_oval(1, 1, 9, 9, fill=c, outline="")
        self.after(500, self._pulse)

    def _poll_queue(self):
        try:
            while True:
                self._handle(*self.q.get_nowait())
        except queue.Empty:
            pass
        self.after(50, self._poll_queue)

    def _handle(self, event, data):
        if event == "module_start":
            key = next((k for k, n in MODULES if n == data), None)
            self._current_key = key
            if key:
                self._set_module(key, "running")
            self._log(f"▶  {data}", "warn")
            self._scanning_lbl.configure(text=f"Running: {data}")

        elif event == "module_done":
            name, count = data["name"], data["count"]
            key = next((k for k, n in MODULES if n == name), None)
            if key:
                self._set_module(key, "done" if count > 0 else "done0", count)
            self._log(f"✓  {name}  —  {count} finding(s)", "ok" if count == 0 else "critical" if count > 3 else "warn")

        elif event == "finding":
            f = data
            sev = f.get("severity", "INFO")
            if sev in self.counts:
                self.counts[sev] += 1
                self._cnt_labels[sev].configure(text=str(self.counts[sev]))
            tag = {"CRITICAL": "critical", "HIGH": "high",
                   "MEDIUM": "medium", "LOW": "low"}.get(sev, "dim")
            self._log(f"    [{sev:8}]  {f.get('name','')}", tag)

        elif event == "crawl_page":
            self._log(f"  ↳ {str(data)[:90]}", "dim")

        elif event == "generating_report":
            self._scanning_lbl.configure(text="Generating report…")
            self._log("Generating report…", "cyan")

        elif event == "scan_complete":
            self._current_key = None
            self._scanning_lbl.configure(text="Complete")
            self._log("─" * 56)
            self._log(f"✓  Scan complete  ·  {int(data['duration'])}s", "ok")
            self.after(700, lambda d=data: self.on_complete(self.target, d))

    def _scan_callback(self, event, data):
        self.q.put((event, data))

    def _start_scan(self):
        self._log(f"Target   {self.target}", "dim")
        self._log(f"Profile  {self.profile}  ·  {len(self.enabled_modules)} modules", "dim")
        self._log("─" * 56)
        self.after(200, self._pulse)
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        try:
            from scanner import WebReaper
            WebReaper(
                target=self.target,
                enabled_modules=self.enabled_modules,
                profile=self.profile,
                email=self.email,
                callback=self._scan_callback,
            ).run()
        except Exception:
            import traceback
            self.q.put(("log_error", traceback.format_exc()))


# ─── Dashboard ────────────────────────────────────────────────────────────────

def _risk_score(findings):
    w = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}
    return min(sum(w.get(f.get("severity", "INFO"), 0) for f in findings), 100)

def _risk_label(score):
    if score >= 75: return "CRITICAL", "#ff3333"
    if score >= 50: return "HIGH",     "#ff6b00"
    if score >= 25: return "MEDIUM",   "#e3b341"
    if score > 0:   return "LOW",      "#58a6ff"
    return "SAFE", GREEN


class RiskGauge(tk.Canvas):
    def __init__(self, parent, score, color, size=130, **kw):
        super().__init__(parent, width=size, height=size,
                         bg=SURF, highlightthickness=0, **kw)
        cx, cy = size // 2, size // 2
        r = size // 2 - 10
        # Track
        self.create_arc(cx-r, cy-r, cx+r, cy+r,
                        start=220, extent=-260,
                        style="arc", outline=SURF2, width=10)
        # Fill
        if score > 0:
            extent = -260 * score / 100
            self.create_arc(cx-r, cy-r, cx+r, cy+r,
                            start=220, extent=extent,
                            style="arc", outline=color, width=10)
        self.create_text(cx, cy - 6, text=str(score),
                         fill=color, font=("Courier", 22, "bold"))
        self.create_text(cx, cy + 16, text="/ 100",
                         fill=TXT2, font=("Courier", 9))


class DonutChart(tk.Canvas):
    def __init__(self, parent, counts, size=180, **kw):
        super().__init__(parent, width=size, height=size,
                         bg=SURF, highlightthickness=0, **kw)
        cx, cy = size // 2, size // 2
        r_out  = size // 2 - 8
        r_in   = size // 2 - 40
        sevs   = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        total  = sum(counts.get(s, 0) for s in sevs) or 1
        start  = -90.0
        for sev in sevs:
            n = counts.get(sev, 0)
            if n == 0:
                continue
            ext = 360.0 * n / total
            self.create_arc(cx-r_out, cy-r_out, cx+r_out, cy+r_out,
                            start=start, extent=ext,
                            fill=SEV_COLOR[sev], outline=SURF, width=3,
                            style="pieslice")
            start += ext
        self.create_oval(cx-r_in, cy-r_in, cx+r_in, cy+r_in,
                         fill=SURF, outline=SURF)
        issues = sum(counts.get(s, 0) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
        self.create_text(cx, cy - 8,  text=str(issues),
                         fill=TXT, font=("Courier", 20, "bold"))
        self.create_text(cx, cy + 14, text="findings",
                         fill=TXT2, font=("Courier", 9))


class DashboardFrame(ctk.CTkFrame):
    def __init__(self, master, target, scan_data, on_new_scan):
        super().__init__(master, fg_color=BG)
        self.target      = target
        self.findings    = scan_data.get("findings", [])
        self.duration    = scan_data.get("duration", 0)
        self.pages       = scan_data.get("pages_crawled", 0)
        self.forms       = scan_data.get("forms_found", 0)
        self.js_files    = scan_data.get("js_files", 0)
        self.mods_run    = scan_data.get("modules_run", 0)
        self.on_new_scan = on_new_scan
        self._active_filter = "ALL"
        self._sorted     = sorted(self.findings,
                                   key=lambda x: SEV_ORDER.get(x.get("severity", "INFO"), 4))
        self._row_data   = {}
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        counts = {s: 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
        for f in self.findings:
            counts[f.get("severity", "INFO")] += 1

        score = _risk_score(self.findings)
        rl, rc = _risk_label(score)

        self._build_topbar()
        self._build_metrics(counts, score, rl, rc)
        self._build_main(counts)

    # ── Top bar ──────────────────────────────────────────────────────────────

    def _build_topbar(self):
        tb = _topbar(self,
            subtitle=f"Target: {self.target}  ·  {datetime.now().strftime('%Y-%m-%d  %H:%M')}")
        tb.grid(row=0, column=0, sticky="ew")
        ctk.CTkButton(tb, text="← New Scan",
            fg_color=SURF2, hover_color=RED2, text_color=TXT2,
            font=ctk.CTkFont(size=11), height=30, width=110, corner_radius=6,
            command=self.on_new_scan,
        ).grid(row=0, column=2, padx=20, pady=10, sticky="e")

    # ── Metric cards row ─────────────────────────────────────────────────────

    def _build_metrics(self, counts, score, risk_label, risk_color):
        strip = ctk.CTkFrame(self, fg_color=BG)
        strip.grid(row=1, column=0, sticky="ew", padx=16, pady=(10, 0))
        strip.grid_columnconfigure((0, 1, 2, 3, 4, 5), weight=1)

        # Risk card with gauge
        risk_card = self._card(strip, col=0, accent=risk_color)
        RiskGauge(risk_card, score, risk_color, size=110).pack(pady=(10, 0))
        ctk.CTkLabel(risk_card, text="RISK SCORE",
            font=ctk.CTkFont(size=9, weight="bold"),
            text_color=TXT2, fg_color="transparent",
        ).pack()
        ctk.CTkLabel(risk_card, text=risk_label,
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=risk_color, fg_color="transparent",
        ).pack(pady=(0, 8))

        # Severity cards
        for col, (sev, color) in enumerate([
            ("CRITICAL", "#ff3333"), ("HIGH", "#ff6b00"),
            ("MEDIUM", "#e3b341"),   ("LOW",  "#58a6ff"),
        ], start=1):
            c = self._card(strip, col=col, accent=color)
            ctk.CTkLabel(c, text=str(counts[sev]),
                font=ctk.CTkFont(size=32, weight="bold"),
                text_color=color, fg_color="transparent",
            ).pack(pady=(18, 2))
            ctk.CTkLabel(c, text=sev,
                font=ctk.CTkFont(size=9, weight="bold"),
                text_color=TXT2, fg_color="transparent",
            ).pack(pady=(0, 18))

        # Stats card
        stats = self._card(strip, col=5, accent=BORDER)
        for label, val in [
            ("Pages crawled",  self.pages),
            ("Forms found",    self.forms),
            ("JS files",       self.js_files),
            (f"Duration",      f"{int(self.duration)}s"),
            ("Modules run",    self.mods_run),
        ]:
            row = ctk.CTkFrame(stats, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=2)
            ctk.CTkLabel(row, text=label, font=ctk.CTkFont(size=10),
                         text_color=TXT2, fg_color="transparent", anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=str(val), font=ctk.CTkFont(size=10, weight="bold"),
                         text_color=TXT, fg_color="transparent").pack(side="right")

    def _card(self, parent, col, accent=BORDER):
        outer = ctk.CTkFrame(parent, fg_color=accent, corner_radius=10)
        outer.grid(row=0, column=col, sticky="nsew", padx=(0 if col == 0 else 6, 0))
        inner = ctk.CTkFrame(outer, fg_color=SURF, corner_radius=9)
        inner.pack(side="right", fill="both", expand=True, padx=(3, 0))
        return inner

    # ── Main area ────────────────────────────────────────────────────────────

    def _build_main(self, counts):
        main = ctk.CTkFrame(self, fg_color=BG)
        main.grid(row=2, column=0, sticky="nsew", padx=16, pady=10)
        main.grid_columnconfigure(0, weight=0)
        main.grid_columnconfigure(1, weight=1)
        main.grid_rowconfigure(0, weight=1)

        self._build_sidebar(main, counts)
        self._build_findings(main, counts)

    # ── Sidebar ──────────────────────────────────────────────────────────────

    def _build_sidebar(self, parent, counts):
        sb = ctk.CTkFrame(parent, fg_color=SURF, corner_radius=10,
                          border_color=BORDER, border_width=1, width=220)
        sb.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        sb.grid_propagate(False)

        ctk.CTkLabel(sb, text="SEVERITY BREAKDOWN",
            font=ctk.CTkFont(size=9, weight="bold"),
            text_color=TXT2, fg_color="transparent",
        ).pack(pady=(14, 6))

        DonutChart(sb, counts, size=200).pack()

        # Legend
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            n = counts.get(sev, 0)
            row = ctk.CTkFrame(sb, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=2)
            ctk.CTkFrame(row, width=10, height=10, corner_radius=2,
                         fg_color=SEV_COLOR[sev]).pack(side="left", padx=(0, 8))
            ctk.CTkLabel(row, text=sev, font=ctk.CTkFont(size=10),
                         text_color=TXT2, fg_color="transparent").pack(side="left")
            ctk.CTkLabel(row, text=str(n),
                         font=ctk.CTkFont(size=10, weight="bold"),
                         text_color=SEV_COLOR[sev] if n > 0 else TXT3,
                         fg_color="transparent").pack(side="right")

        _sep(sb, pad_y=10, pad_x=12)

        ctk.CTkLabel(sb, text="BY MODULE",
            font=ctk.CTkFont(size=9, weight="bold"),
            text_color=TXT2, fg_color="transparent",
        ).pack(pady=(0, 6))

        mc = {}
        for f in self.findings:
            mc[f.get("module", "—")] = mc.get(f.get("module", "—"), 0) + 1

        mod_scroll = ctk.CTkScrollableFrame(sb, fg_color="transparent", height=140)
        mod_scroll.pack(fill="x", padx=12, pady=(0, 12))
        for mod, n in sorted(mc.items(), key=lambda x: -x[1]):
            row = ctk.CTkFrame(mod_scroll, fg_color="transparent")
            row.pack(fill="x", pady=1)
            pct = int(n / max(sum(mc.values()), 1) * 100)
            ctk.CTkProgressBar(row, progress_color=RED, fg_color=SURF2,
                               height=4, corner_radius=2, width=80,
            ).pack(side="left", padx=(0, 6))
            # set value after creation
            bar = row.winfo_children()[0]
            bar.set(pct / 100)
            ctk.CTkLabel(row, text=mod[:18], font=ctk.CTkFont(size=9),
                         text_color=TXT2, fg_color="transparent", anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=str(n), font=ctk.CTkFont(size=9, weight="bold"),
                         text_color=TXT, fg_color="transparent").pack(side="right")

    # ── Findings area ─────────────────────────────────────────────────────────

    def _build_findings(self, parent, counts):
        right = ctk.CTkFrame(parent, fg_color=BG)
        right.grid(row=0, column=1, sticky="nsew")
        right.grid_columnconfigure(0, weight=1)
        right.grid_rowconfigure(1, weight=1)

        # Filter bar
        fbar = ctk.CTkFrame(right, fg_color=SURF, corner_radius=8,
                            border_color=BORDER, border_width=1)
        fbar.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        fbar.grid_columnconfigure(0, weight=1)

        filters = ctk.CTkFrame(fbar, fg_color="transparent")
        filters.pack(side="left", padx=12, pady=8)

        ctk.CTkLabel(filters, text="FILTER",
            font=ctk.CTkFont(size=9, weight="bold"),
            text_color=TXT2, fg_color="transparent",
        ).pack(side="left", padx=(0, 10))

        self._fbtns = {}
        filter_defs = [("ALL", TXT2, len(self.findings))] + [
            (s, SEV_COLOR[s], counts[s])
            for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        ]
        for label, color, n in filter_defs:
            active = label == "ALL"
            txt = f"{label}  {n}" if n > 0 else label
            b = ctk.CTkButton(filters,
                text=txt, width=max(64, len(txt) * 7), height=26,
                font=ctk.CTkFont(size=10, weight="bold"),
                fg_color=color if active else SURF2,
                hover_color=color, text_color="white" if active else TXT2,
                corner_radius=5,
                command=lambda l=label, c=color: self._filter(l, c),
            )
            b.pack(side="left", padx=(0, 4))
            self._fbtns[label] = (b, color)

        total_lbl = ctk.CTkLabel(fbar,
            text=f"{len(self.findings)} total findings",
            font=ctk.CTkFont(size=10), text_color=TXT2, fg_color="transparent")
        total_lbl.pack(side="right", padx=16)

        # Table + detail split
        split = ctk.CTkFrame(right, fg_color=BG)
        split.grid(row=1, column=0, sticky="nsew")
        split.grid_columnconfigure(0, weight=55)
        split.grid_columnconfigure(1, weight=45)
        split.grid_rowconfigure(0, weight=1)

        self._build_table(split)
        self._build_detail(split)

    def _filter(self, label, color):
        self._active_filter = label
        for lbl, (btn, c) in self._fbtns.items():
            active = lbl == label
            btn.configure(
                fg_color=c if active else SURF2,
                text_color="white" if active else TXT2,
            )
        self._populate_table()

    def _build_table(self, parent):
        style = ttk.Style()
        style.theme_use("default")
        style.configure("R.Treeview",
            background=SURF, foreground=TXT, fieldbackground=SURF,
            borderwidth=0, font=("Courier", 11), rowheight=28,
        )
        style.configure("R.Treeview.Heading",
            background=BG, foreground=TXT2,
            font=("Courier", 10, "bold"), relief="flat",
        )
        style.map("R.Treeview",
            background=[("selected", SURF2)],
            foreground=[("selected", TXT)],
        )

        tf = ctk.CTkFrame(parent, fg_color=SURF, corner_radius=10,
                          border_color=BORDER, border_width=1)
        tf.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        tf.grid_rowconfigure(0, weight=1)
        tf.grid_columnconfigure(0, weight=1)

        cols = ("#", "Severity", "Vulnerability", "URL", "Module")
        self.tree = ttk.Treeview(tf, columns=cols, show="headings", style="R.Treeview")
        for col, w in zip(cols, [32, 90, 240, 220, 120]):
            self.tree.heading(col, text=col,
                              command=lambda c=col: self._sort(c))
            self.tree.column(col, width=w, minwidth=w, anchor="w")
        self.tree.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)

        vsb = ctk.CTkScrollbar(tf, command=self.tree.yview)
        vsb.grid(row=0, column=1, sticky="ns", pady=4, padx=(0, 2))
        self.tree.configure(yscrollcommand=vsb.set)

        for sev, color in SEV_COLOR.items():
            self.tree.tag_configure(sev, foreground=color)

        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self._populate_table()

    def _populate_table(self):
        self.tree.delete(*self.tree.get_children())
        rows = (self._sorted if self._active_filter == "ALL"
                else [f for f in self._sorted
                      if f.get("severity") == self._active_filter])
        self._row_data = {}
        for i, f in enumerate(rows, 1):
            sev = f.get("severity", "INFO")
            iid = self.tree.insert("", "end", values=(
                i, sev,
                f.get("name", "")[:48],
                f.get("url",  "")[:52],
                f.get("module", ""),
            ), tags=(sev,))
            self._row_data[iid] = f

    def _sort(self, col):
        key = {"#": None, "Severity": "severity", "Vulnerability": "name",
               "URL": "url", "Module": "module"}.get(col)
        if key == "severity":
            self._sorted.sort(key=lambda x: SEV_ORDER.get(x.get("severity", "INFO"), 4))
        elif key:
            self._sorted.sort(key=lambda x: x.get(key, "").lower())
        self._populate_table()

    def _on_select(self, _):
        sel = self.tree.selection()
        if sel and sel[0] in self._row_data:
            self._show_detail(self._row_data[sel[0]])

    # ── Detail panel ─────────────────────────────────────────────────────────

    def _build_detail(self, parent):
        self.detail_frame = ctk.CTkScrollableFrame(
            parent, fg_color=SURF, corner_radius=10,
            border_color=BORDER, border_width=1,
        )
        self.detail_frame.grid(row=0, column=1, sticky="nsew")
        self.detail_frame.grid_columnconfigure(0, weight=1)
        self._detail_empty()

    def _detail_empty(self):
        for w in self.detail_frame.winfo_children():
            w.destroy()
        ctk.CTkLabel(self.detail_frame,
            text="Select a finding\nto view details",
            font=ctk.CTkFont(size=12), text_color=TXT3,
            fg_color="transparent", justify="center",
        ).pack(expand=True, pady=80)

    def _show_detail(self, f):
        for w in self.detail_frame.winfo_children():
            w.destroy()

        sev   = f.get("severity", "INFO")
        color = SEV_COLOR.get(sev, TXT2)

        # Severity banner
        banner = ctk.CTkFrame(self.detail_frame, fg_color=color, corner_radius=8, height=38)
        banner.pack(fill="x", padx=14, pady=(14, 10))
        banner.pack_propagate(False)
        ctk.CTkLabel(banner, text=f"  {sev}",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="white", fg_color="transparent",
        ).pack(side="left", padx=8)
        ctk.CTkLabel(banner, text=f.get("module", ""),
            font=ctk.CTkFont(size=10),
            text_color="#ffffffcc", fg_color="transparent",
        ).pack(side="right", padx=12)

        def field(label, value, val_color=TXT):
            if not value or value == "—":
                return
            ctk.CTkLabel(self.detail_frame, text=label,
                font=ctk.CTkFont(size=9, weight="bold"),
                text_color=TXT2, fg_color="transparent", anchor="w",
            ).pack(fill="x", padx=14, pady=(8, 2))
            ctk.CTkLabel(self.detail_frame, text=str(value),
                font=ctk.CTkFont(size=11), text_color=val_color,
                fg_color=SURF2, corner_radius=6, anchor="w",
                wraplength=320, justify="left",
            ).pack(fill="x", padx=14, pady=(0, 2), ipady=6, ipadx=8)

        field("VULNERABILITY", f.get("name"))
        field("URL", f.get("url"), TXT2)
        field("PARAMETER", f.get("param") or f.get("parameter"))

        desc = (f.get("description") or f.get("detail")
                or f.get("evidence") or "No description available.")
        field("DESCRIPTION", str(desc)[:500])

        rec = f.get("recommendation", "")
        if rec:
            ctk.CTkLabel(self.detail_frame, text="RECOMMENDATION",
                font=ctk.CTkFont(size=9, weight="bold"),
                text_color=TXT2, fg_color="transparent", anchor="w",
            ).pack(fill="x", padx=14, pady=(8, 2))
            ctk.CTkLabel(self.detail_frame, text=str(rec)[:400],
                font=ctk.CTkFont(size=11), text_color=GREEN,
                fg_color="#0d2115", corner_radius=6, anchor="w",
                wraplength=320, justify="left",
            ).pack(fill="x", padx=14, pady=(0, 14), ipady=6, ipadx=8)


# ─── App Window ───────────────────────────────────────────────────────────────

class WebReaperApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("WebReaper")
        self.geometry("1240x820")
        self.minsize(980, 680)
        self.configure(fg_color=BG)
        try:
            base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
            self.iconbitmap(os.path.join(base, "icon.ico"))
        except Exception:
            pass
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._frame = None
        self._show_home()

    def _show_home(self):
        self._swap(HomeFrame(self, on_start=self._start_scan))

    def _start_scan(self, url, enabled, profile, email):
        self._swap(ScanFrame(self, url, enabled, profile, email,
                             on_complete=self._show_dashboard))

    def _show_dashboard(self, target, scan_data):
        self._swap(DashboardFrame(self, target, scan_data,
                                  on_new_scan=self._show_home))

    def _swap(self, frame):
        if self._frame:
            self._frame.destroy()
        self._frame = frame
        frame.grid(row=0, column=0, sticky="nsew")


if __name__ == "__main__":
    WebReaperApp().mainloop()
