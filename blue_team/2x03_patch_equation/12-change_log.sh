#!/bin/bash

# 12-change_log.sh
# MedDefense - Patch Management
# Task 12: The Change Tracking Log

set -uo pipefail

OUTPUT_FILE="patch_change_log.json"

# Dependency checks
for cmd in python3 jq; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "[ERROR] Missing required command: $cmd" >&2; exit 1; }
done

echo "[*] Parsing APT history logs and generating change log..."

# ---------------------------------------------------------------------------
# Python Change Log Extraction & Enrichment Engine
# Group transactions into change events within 15 minutes proximity
# ---------------------------------------------------------------------------
python3 - << 'EOF'
import os
import glob
import gzip
import json
import datetime
from zoneinfo import ZoneInfo

output_path = "patch_change_log.json"
windows_config_path = "maintenance_windows.json"
execution_log_path = "patch_execution_log.json"
vuln_inventory_path = "vulnerability_inventory.json"

# Load timezone for window evaluation
tz_name = "UTC"
windows_data = []
if os.path.exists(windows_config_path):
    try:
        with open(windows_config_path, "r") as f:
            w_cfg = json.load(f)
            tz_name = w_cfg.get("timezone", "UTC")
            windows_data = w_cfg.get("windows", [])
    except Exception:
        pass

try:
    tz = ZoneInfo(tz_name)
except Exception:
    tz = ZoneInfo("UTC")

def check_window_for_time(dt):
    day_abbr = dt.strftime("%a")
    time_str = dt.strftime("%H:%M")
    dom = dt.day
    week_of_month = (dom - 1) // 7 + 1

    for w in windows_data:
        if w.get("always", False):
            return "inside"
        days = w.get("days", [])
        if day_abbr not in days:
            continue
        w_om = w.get("week_of_month")
        if w_om is not None and w_om != week_of_month:
            continue
        start_str = w.get("start")
        end_str = w.get("end")
        if start_str and end_str:
            if start_str <= time_str <= end_str:
                return "inside"
    return "outside"

# Gather APT history logs (/var/log/apt/history.log*) including Upgrade, Install, Remove
history_files = glob.glob("/var/log/apt/history.log*")
raw_transactions = []

for hfile in history_files:
    try:
        if hfile.endswith(".gz"):
            opener = gzip.open
        else:
            opener = open

        with opener(hfile, "rt", errors="ignore") as f:
            content = f.read()
            
        records = content.split("Start-Date: ")
        for rec in records:
            if not rec.strip():
                continue
            lines = rec.strip().splitlines()
            start_date_str = lines[0].strip()
            
            cmdline = ""
            user = "unknown"
            pkgs_count = 0
            
            for line in lines[1:]:
                if line.startswith("Commandline:"):
                    cmdline = line.split(":", 1)[1].strip()
                elif line.startswith("Requested-By:"):
                    user_raw = line.split(":", 1)[1].strip()
                    user = user_raw.split(" ")[0]
                elif line.startswith("Upgrade:") or line.startswith("Install:") or line.startswith("Remove:"):
                    pkg_line = line.split(":", 1)[1].strip()
                    pkgs_count += len([p for p in pkg_line.split(",") if p.strip()])

            try:
                dt = datetime.datetime.strptime(start_date_str, "%Y-%m-%d  %H:%M:%S")
                dt = dt.replace(tzinfo=tz)
                raw_transactions.append({
                    "dt": dt,
                    "started": dt.isoformat(),
                    "user": user,
                    "commandline": cmdline,
                    "packages": pkgs_count
                })
            except Exception:
                continue
    except Exception:
        continue

raw_transactions.sort(key=lambda x: x["dt"])

events = []
current_group = []

# Group transactions into change events within 15 minutes of each other
for tx in raw_transactions:
    if not current_group:
        current_group.append(tx)
    else:
        diff = (tx["dt"] - current_group[-1]["dt"]).total_seconds()
        if diff <= 15 * 60:
            current_group.append(tx)
        else:
            events.append(current_group)
            current_group = [tx]

if current_group:
    events.append(current_group)

formatted_events = []
total_inside = 0
total_outside = 0
total_cves = 0

for group in events:
    first_tx = group[0]
    started_iso = first_tx["started"]
    user = first_tx["user"]
    total_pkgs = sum(t["packages"] for t in group)
    window_decision = check_window_for_time(first_tx["dt"])
    
    if window_decision == "inside":
        total_inside += 1
    else:
        total_outside += 1

    event_obj = {
        "started": started_iso,
        "user": user,
        "within_window": window_decision,
        "packages": total_pkgs
    }
    if os.path.exists(execution_log_path):
        event_obj["linked_execution_log"] = execution_log_path

    formatted_events.append(event_obj)

period_start = formatted_events[0]["started"] if formatted_events else datetime.datetime.now(tz).isoformat()
period_end = formatted_events[-1]["started"] if formatted_events else period_start

report = {
    "period_start": period_start,
    "period_end": period_end,
    "events": formatted_events,
    "summary": {
        "total_events": len(formatted_events),
        "inside_window": total_inside,
        "outside_window": total_outside,
        "cves_resolved": total_cves
    }
}

with open(output_path, "w") as of:
    json.dump(report, of, indent=2)

print(f"Report saved to: {output_path}")
print(f"Total events recorded: {len(formatted_events)}")
EOF

exit 0
