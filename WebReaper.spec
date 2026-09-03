# -*- mode: python ; coding: utf-8 -*-
import sys
import os
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# Collect customtkinter assets
ctk_datas = collect_data_files("customtkinter")

# Wordlists + report template
extra_datas = [
    ("wordlists",       "wordlists"),
    ("report/template.html", "report"),
    ("modules",         "modules"),
]

a = Analysis(
    ["main.py"],
    pathex=["."],
    binaries=[],
    datas=ctk_datas + extra_datas,
    hiddenimports=[
        "customtkinter",
        "PIL",
        "PIL._tkinter_finder",
        "tkinter",
        "tkinter.ttk",
        "jinja2",
        "jinja2.ext",
        "dns",
        "dns.resolver",
        "bs4",
        "urllib3",
        "requests",
        "scanner",
        "modules.crawler",
        "modules.xss_scanner",
        "modules.sqli_scanner",
        "modules.open_redirect",
        "modules.sensitive_files",
        "modules.cookie_checker",
        "modules.csrf_checker",
        "modules.header_checker",
        "modules.ssl_analyzer",
        "modules.cms_detector",
        "modules.cve_lookup",
        "modules.js_analyzer",
        "modules.access_control",
        "modules.api_discovery",
        "modules.subdomain_takeover",
        "modules.email_security",
        "modules.rate_limit_tester",
        "modules.http_methods",
        "modules.screenshot",
        "report.generator",
        "report.diff",
        "report.recommendations",
        "notifications",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["textual"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="WebReaper",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,          # no terminal window
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon="icon.ico" if sys.platform == "win32" else "icon.icns",
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="WebReaper",
)

# macOS .app bundle
if sys.platform == "darwin":
    app = BUNDLE(
        coll,
        name="WebReaper.app",
        icon="icon.icns",
        bundle_identifier="com.webreaper.scanner",
        info_plist={
            "CFBundleShortVersionString": "1.0.0",
            "CFBundleName": "WebReaper",
            "NSHighResolutionCapable": True,
        },
    )
