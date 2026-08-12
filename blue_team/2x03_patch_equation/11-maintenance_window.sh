#!/bin/bash

# 11-maintenance_window.sh
# MedDefense - Patch Management
# Task 11: The Maintenance Window Enforcement

set -uo pipefail

CONFIG_FILE="maintenance_windows.json"
OUTPUT_FILE="maintenance_window.json"

# Dependency checks
for cmd in python3 jq; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "[ERROR] Missing required command: $cmd" >&2; exit 1; }
done

if [ ! -f "$CONFIG_FILE" ]; then
    echo "[ERROR] Configuration file not found: $CONFIG_FILE" >&2
    exit 1
fi

MODE="check"
WAIT_SECONDS=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check)
            MODE="check"
            shift
            ;;
        --report)
            MODE="report"
            shift
            ;;
        --wait)
            MODE="wait"
            if [[ -n "${2:-}" ]] && [[ "$2" =~ ^[0-9]+$ ]]; then
                WAIT_SECONDS="$2"
                shift 2
            else
                WAIT_SECONDS=3600 # default wait if unspecified
                shift
            fi
            ;;
        *)
            shift
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Python Maintenance Window Engine
# ---------------------------------------------------------------------------
python3 - << 'EOF'
import json
import datetime
import os
import sys
import time
from zoneinfo import ZoneInfo

config_path = "maintenance_windows.json"
output_path = "maintenance_window.json"
mode = sys.argv[1] if len(sys.argv) > 1 else "check"

try:
    with open(config_path, "r") as f:
        config = json.load(f)
except Exception as e:
    print(f"[ERROR] Failed to load {config_path}: {e}", file=sys.stderr)
    sys.exit(1)

tz_name = config.get("timezone", "UTC")
windows = config.get("windows", [])

try:
    tz = ZoneInfo(tz_name)
except Exception:
    tz = ZoneInfo("UTC")

def get_current_time():
    return datetime.datetime.now(tz)

def check_windows(now):
    day_abbr = now.strftime("%a") # Mon, Tue, Wed, Thu, Fri, Sat, Sun
    current_time_str = now.strftime("%H:%M")
    
    # Calculate week of month
    dom = now.day
    week_of_month = (dom - 1) // 7 + 1

    active_window = None
    is_emergency_only = False

    for w in windows:
        if w.get("always", False):
            # Emergency window
            is_emergency_only = True
            continue
        
        days = w.get("days", [])
        if day_abbr not in days:
            continue
            
        w_om = w.get("week_of_month")
        if w_om is not None and w_om != week_of_month:
            continue
            
        start_str = w.get("start")
        end_str = w.get("end")
        
        if start_str and end_str:
            if start_str <= current_time_str <= end_str:
                active_window = w.get("name")
                return active_window, False

    if is_emergency_only and not active_window:
        return "emergency", True

    return None, False

def find_next_window(now):
    # Search ahead minute by minute up to 14 days to find the next standard/extended window
    check_time = now.replace(second=0, microsecond=0)
    for _ in range(14 * 24 * 60):
        check_time += datetime.timedelta(minutes=1)
        w, emergency = check_windows(check_time)
        if w and not emergency:
            diff_seconds = int((check_time - now).total_seconds())
            return w, check_time.strftime("%Y-%m-%d %H:%M"), diff_seconds
    return "standard", (now + datetime.timedelta(days=7)).strftime("%Y-%m-%d %H:%M"), 604800

now = get_current_time()
active_w, is_emergency = check_windows(now)

emergency_override = os.environ.get("MEDDEFENSE_EMERGENCY", "0") == "1"

decision = "defer"
exit_code = 20

if active_w and not is_emergency:
    decision = "proceed"
    exit_code = 0
elif is_emergency:
    if emergency_override:
        decision = "proceed"
        exit_code = 0
    else:
        decision = "defer"
        exit_code = 10
else:
    decision = "defer"
    exit_code = 20

next_name, next_ts, seconds_until = find_next_window(now)

now_str = now.strftime(f"%Y-%m-%d %H:%M {tz_name} (%a)")

report = {
    "now": now.strftime("%Y-%m-%d %H:%M:%S %Z"),
    "timezone": tz_name,
    "active_window": active_w if (active_w and not is_emergency) or (is_emergency and emergency_override) else None,
    "next_window": {
        "name": next_name,
        "timestamp": next_ts
    },
    "seconds_until_next": seconds_until,
    "decision": decision
}

with open(output_path, "w") as of:
    json.dump(report, of, indent=2)

print(f"now:            {now_str}")
if active_w and not is_emergency:
    print(f"active window:  {active_w}")
elif is_emergency and emergency_override:
    print(f"active window:  emergency (override active)")
else:
    print(f"active window:  (none)")
    print(f"next window:    {next_name}  at {next_ts}")
    print(f"seconds until:  {seconds_until}")

print(f"decision:       {decision}")
print(f"Report saved to: {output_path}")

sys.exit(exit_code)
EOF
