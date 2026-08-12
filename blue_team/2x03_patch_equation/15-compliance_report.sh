#!/bin/bash

# 15-compliance_report.sh
# MedDefense - Patch Management
# Task 15: The Patch Compliance Artifact
# Determines the current state of every CVE in inventory history

set -uo pipefail

OUTPUT_FILE="patch_compliance.json"

# Dependency checks
for cmd in python3 jq; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "[ERROR] Missing required command: $cmd" >&2; exit 1; }
done

echo "[*] Generating patch compliance report..."

# ---------------------------------------------------------------------------
# Python Compliance Aggregation & Scoring Engine
# Determines current state (resolved, open, deferred_held, deferred_window)
# ---------------------------------------------------------------------------
python3 - << 'EOF'
import os
import glob
import json
import datetime
import socket
import platform
import sys

output_path = "patch_compliance.json"
vuln_inventory_path = "vulnerability_inventory.json"
hold_mgmt_path = "hold_management.json"
change_log_path = "patch_change_log.json"
pipeline_run_path = "pipeline_run.json"

hostname = socket.gethostname()
kernel = platform.release()
generated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

# Gather all historical vulnerability entries (current + history under ./history/)
all_cves_raw = []
if os.path.exists(vuln_inventory_path):
    try:
        with open(vuln_inventory_path, "r") as f:
            data = json.load(f)
            if isinstance(data, list):
                all_cves_raw.extend(data)
            elif isinstance(data, dict):
                all_cves_raw.extend(data.get("vulnerabilities", data.get("cves", [])))
    except Exception:
        pass

history_files = glob.glob("./history/vulnerability_inventory*.json") + glob.glob("vulnerability_inventory*.json.bak")
for hfile in history_files:
    try:
        with open(hfile, "r") as f:
            data = json.load(f)
            if isinstance(data, list):
                all_cves_raw.extend(data)
            elif isinstance(data, dict):
                all_cves_raw.extend(data.get("vulnerabilities", data.get("cves", [])))
    except Exception:
        pass

# Load hold management info
held_pkgs = set()
if os.path.exists(hold_mgmt_path):
    try:
        with open(hold_mgmt_path, "r") as f:
            hm_data = json.load(f)
            for h in hm_data.get("applied", []):
                held_pkgs.add(h.get("package"))
    except Exception:
        pass

today = datetime.date.today()

cve_map = {}
for item in all_cves_raw:
    cve_id = item.get("cve", item.get("id", "CVE-UNKNOWN"))
    pkg = item.get("package", "unknown")
    severity = str(item.get("severity", item.get("cvss_severity", "MEDIUM"))).upper()
    
    # Determine current state for compliance reporting
    state = "open"
    if pkg in held_pkgs:
        state = "deferred_held"
    elif "window" in str(item.get("status", "")).lower():
        state = "deferred_window"
    elif item.get("resolved", False) or item.get("status") == "resolved":
        state = "resolved"

    cve_map[cve_id] = {
        "id": cve_id,
        "package": pkg,
        "severity": severity,
        "state": state,
        "first_seen": item.get("first_seen", datetime.datetime.now().strftime("%Y-%m-%d")),
        "resolved_at": item.get("resolved_at", None),
        "justification": item.get("justification", "Managed via MedDefense patch pipeline")
    }

cves_list = list(cve_map.values())

counts = {
    "resolved": 0,
    "open": 0,
    "deferred_held": 0,
    "deferred_window": 0
}

crit_high_total = 0
crit_high_resolved = 0
overdue_count = 0

for c in cves_list:
    st = c["state"]
    if st in counts:
        counts[st] += 1
    
    sev = c["severity"]
    is_crit_high = sev in ["CRITICAL", "HIGH", "9.0", "8.0", "7.0"] or (isinstance(sev, (int, float)) and sev >= 7.0)
    
    if is_crit_high:
        crit_high_total += 1
        if st == "resolved":
            crit_high_resolved += 1
        elif st == "open":
            try:
                f_seen = datetime.datetime.strptime(c["first_seen"], "%Y-%m-%d").date()
                if (today - f_seen).days > 7:
                    overdue_count += 1
            except Exception:
                pass

if crit_high_total > 0:
    score = round((crit_high_resolved / crit_high_total) * 100.0, 2)
else:
    score = 100.00

target_score = 95.00

summary = {
    "resolved": counts["resolved"],
    "open": counts["open"],
    "deferred_held": counts["deferred_held"],
    "deferred_window": counts["deferred_window"],
    "score": score,
    "target_score": target_score,
    "overdue": overdue_count
}

report = {
    "generated_at": generated_at,
    "hostname": hostname,
    "kernel": kernel,
    "summary": summary,
    "cves": cves_list
}

with open(output_path, "w") as of:
    json.dump(report, of, indent=2)

print(f"Compliance Score: {score}% (Target: {target_score}%)")
print(f"Report saved to: {output_path}")

if score >= target_score:
    sys.exit(0)
else:
    sys.exit(1)
EOF
PY_EXIT=$?

exit $PY_EXIT
