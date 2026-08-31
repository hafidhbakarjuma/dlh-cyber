#!/bin/bash
set -euo pipefail

# Default HANDOFF_DIR if unset, following project specifications
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
DATA_FILE="labeled_events.json"

if [ ! -f "$DATA_FILE" ]; then
    echo "Error: labeled_events.json not found. Run Task 3 (3-event_taxonomy.sh) first." >&2
    exit 1
fi

python3 - << 'PY_SCRIPT'
import json
import os
import sys
from datetime import datetime, timedelta

data_file = "labeled_events.json"
baseline_days = int(os.environ.get("BASELINE_DAYS", 7))

events = []
with open(data_file, "r") as f:
    for line in f:
        line = line.strip()
        if line:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

if not events:
    print("Error: No valid events found in labeled_events.json", file=sys.stderr)
    sys.exit(1)

# Derive dataset start timestamp dynamically
timestamps = []
for e in events:
    ts_str = e.get("timestamp") or e.get("time") or e.get("@timestamp")
    if ts_str:
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            timestamps.append(dt)
        except ValueError:
            pass

if not timestamps:
    print("Error: No valid timestamps found in dataset.", file=sys.stderr)
    sys.exit(1)

min_ts = min(timestamps)
baseline_end = min_ts + timedelta(days=baseline_days)

# Filter events within the baseline window
baseline_events = []
for e in events:
    ts_str = e.get("timestamp") or e.get("time") or e.get("@timestamp")
    if ts_str:
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if min_ts <= dt < baseline_end:
                e["_dt"] = dt
                baseline_events.append(e)
        except ValueError:
            pass

auth_labels = {'login_success', 'login_failure', 'logout', 'account_lockout', 'privilege_escalation'}
auth_events = [e for e in baseline_events if e.get("canonical_label") in auth_labels or str(e.get("source", "")).lower() == "auth"]

per_host = {}
per_user_data = {}
known_accounts_set = set()

biz_succ = 0
biz_fail = 0
off_succ = 0
off_fail = 0

biz_total_hours = baseline_days * 12  # 06:00 to 17:59 (12 hours/day)
off_total_hours = baseline_days * 12  # 18:00 to 05:59 (12 hours/day)

ip_failures = {}

for e in auth_events:
    host = e.get("host") or e.get("hostname") or e.get("source_host") or "unknown"
    label = e.get("canonical_label", "unknown")
    user = e.get("user") or e.get("username") or e.get("account") or e.get("src_user") or "unknown"
    src_ip = e.get("src_ip") or e.get("source_ip") or e.get("ip") or "unknown"
    dt = e["_dt"]

    # per_host tally
    if host not in per_host:
        per_host[host] = {"login_success": 0, "login_failure": 0, "logout": 0, "account_lockout": 0, "privilege_escalation": 0}
    if label in per_host[host]:
        per_host[host][label] += 1

    # users & known accounts
    if user and user != "unknown":
        known_accounts_set.add(user)
        if user not in per_user_data:
            per_user_data[user] = {"success": 0, "failure": 0}
        if label == "login_success":
            per_user_data[user]["success"] += 1
        elif label == "login_failure":
            per_user_data[user]["failure"] += 1

    # Business hours (06:00 - 17:59) vs Off-hours
    hour = dt.hour
    is_biz = 6 <= hour <= 17
    if label == "login_success":
        if is_biz: biz_succ += 1
        else: off_succ += 1
    elif label == "login_failure":
        if is_biz: biz_fail += 1
        else: off_fail += 1

    # Track failure bursts by src_ip for 1-hour sliding window calculation
    if label == "login_failure" and src_ip != "unknown":
        if src_ip not in ip_failures:
            ip_failures[src_ip] = []
        ip_failures[src_ip].append(dt)

biz_success_avg = round(biz_succ / biz_total_hours, 2) if biz_total_hours > 0 else 0.0
biz_failure_avg = round(biz_fail / biz_total_hours, 2) if biz_total_hours > 0 else 0.0
off_success_avg = round(off_succ / off_total_hours, 2) if off_total_hours > 0 else 0.0
off_failure_avg = round(off_fail / off_total_hours, 2) if off_total_hours > 0 else 0.0

per_user_list = [{"user": u, "success": d["success"], "failure": d["failure"]} for u, d in per_user_data.items()]

# Compute max failures in any 1-hour rolling window from a single src_ip
max_fail_1h = 0
for ip, times in ip_failures.items():
    times.sort()
    left = 0
    for right in range(len(times)):
        while (times[right] - times[left]).total_seconds() > 3600:
            left += 1
        count = right - left + 1
        if count > max_fail_1h:
            max_fail_1h = count

output_data = {
    "window": {
        "start": min_ts.isoformat(),
        "end": baseline_end.isoformat()
    },
    "per_host": per_host,
    "per_user": per_user_list,
    "known_accounts": sorted(list(known_accounts_set)),
    "business_hours_avg": {
        "success": biz_success_avg,
        "failure": biz_failure_avg
    },
    "offhours_avg": {
        "success": off_success_avg,
        "failure": off_failure_avg
    },
    "max_failures_1h_window": max_fail_1h
}

with open("baseline_auth.json", "w") as out_f:
    json.dump(output_data, out_f, indent=2)

print(f"baseline window : {min_ts.isoformat()} -> {baseline_end.isoformat()}")
print(f"hosts           : {len(per_host)}")
print(f"known accounts  : {len(known_accounts_set)}")
print(f"business hours  : {biz_success_avg} success/h  |  {biz_failure_avg} failure/h")
print(f"off hours       : {off_success_avg} success/h  |  {off_failure_avg} failure/h")
print(f"max 1h src_ip failures : {max_fail_1h}")
print("baseline_auth.json written")
PY_SCRIPT
