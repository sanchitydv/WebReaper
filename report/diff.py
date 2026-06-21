import json
import os
from datetime import datetime


SCANS_DIR = os.path.join(os.path.dirname(__file__), "..", "scans")


def save_scan(target, findings):
    os.makedirs(SCANS_DIR, exist_ok=True)
    safe_target = target.replace("://", "_").replace("/", "_").replace(".", "_")
    path = os.path.join(SCANS_DIR, f"{safe_target}_latest.json")
    data = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "findings": findings,
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


def load_previous_scan(target):
    safe_target = target.replace("://", "_").replace("/", "_").replace(".", "_")
    path = os.path.join(SCANS_DIR, f"{safe_target}_latest.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def fingerprint(finding):
    return f"{finding.get('name','')}__{finding.get('url','')}__{finding.get('parameter','')}"


def diff_scans(previous_scan, current_findings):
    if not previous_scan:
        return {"new": current_findings, "fixed": [], "persistent": [], "previous_date": None}

    prev_fps = {fingerprint(f): f for f in previous_scan.get("findings", [])}
    curr_fps = {fingerprint(f): f for f in current_findings}

    new_findings = [f for fp, f in curr_fps.items() if fp not in prev_fps]
    fixed_findings = [f for fp, f in prev_fps.items() if fp not in curr_fps]
    persistent = [f for fp, f in curr_fps.items() if fp in prev_fps]

    return {
        "new": new_findings,
        "fixed": fixed_findings,
        "persistent": persistent,
        "previous_date": previous_scan.get("timestamp"),
    }
