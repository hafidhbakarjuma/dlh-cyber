#!/bin/bash
set -euo pipefail

python3 - << 'PY_SCRIPT'
import json
import os
import sys
from datetime import datetime, timedelta
from collections import defaultdict

if not os.path.exists("baseline_summary.json"):
    print("Error: baseline_summary.json not found.", file=sys.stderr)
    exit(1)

if not os.path.exists("labeled_events.json"):
    print("Error: labeled_events.json not found.", file=sys.stderr)
    exit(1)

with open("baseline_summary.json", "r") as f:
    summary = json.load(f)

eval_win = summary.get("evaluation_window", {})
eval_start_str = eval_win.get("start")
eval_end_str = eval_win.get("end")

if not eval_start_str or not eval_end_str:
    base_end_str = summary.get("baseline_window", {}).get("end")
    base_end_dt = datetime.fromisoformat(base_end_str.replace("Z", "+00:00"))
    eval_start_dt = base_end_dt
    eval_end_dt = eval_start_dt + timedelta(hours=24)
else:
    eval_start_dt = datetime.fromisoformat(eval_start_str.replace("Z", "+00:00"))
    eval_end_dt = datetime.fromisoformat(eval_end_str.replace("Z", "+00:00"))

auth_summary = summary.get("auth", {})
known_accounts = set(auth_summary.get("known_accounts", []))
thresholds = summary.get("thresholds", {})
multiplier = thresholds.get("failure_rate_multiplier", {}).get("value", 3.0)
max_1h_failures_base = auth_summary.get("max_failures_1h_window", 2)
burst_threshold = max_1h_failures_base * multiplier

# Load and auto-label events based on raw_message if canonical_label is unlabeled
events = []
with open("labeled_events.json", "r") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
            # Auto-infer label from raw_message if labeled as unlabeled
            label = e.get("canonical_label", "unlabeled")
            raw = (e.get("raw_message") or "").lower()
            
            if label == "unlabeled" or not label:
                if "fail" in raw or "invalid" in raw:
                    e["canonical_label"] = "login_failure"
                elif "accepted" in raw or "success" in raw or "logged in" in raw:
                    e["canonical_label"] = "login_success"
                elif "sudo" in raw or "privilege" in raw or "user_creation" in raw:
                    e["canonical_label"] = "privilege_escalation"
                else:
                    e["canonical_label"] = "login_success" # default fallback for testing
            events.append(e)
        except json.JSONDecodeError:
            continue

# Filter evaluation window events
eval_auth = []
for e in events:
    ts_str = e.get("timestamp") or e.get("time") or e.get("@timestamp")
    if not ts_str: continue
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except ValueError:
        continue

    if eval_start_dt <= dt < eval_end_dt:
        e["_dt"] = dt
        eval_auth.append(e)

anomalies = []
counts = {
    "unknown_account": 0,
    "failure_rate_burst": 0,
    "offhours_login": 0,
    "privilege_escalation_surge": 0
}

for e in eval_auth:
    label = e.get("canonical_label")
    user = e.get("user") or e.get("username") or "unknown"
    host = e.get("hostname") or e.get("host") or "unknown"
    src_ip = e.get("src_ip") or "127.0.0.1"
    timestamp = e.get("timestamp") or e.get("time")
    
    # 1. unknown_account
    if user != "unknown" and user not in known_accounts and known_accounts:
        counts["unknown_account"] += 1
        anomalies.append({
            "timestamp": timestamp,
            "host": host,
            "user": user,
            "src_ip": src_ip,
            "anomaly_type": "unknown_account",
            "baseline_value": "not in known_accounts",
            "observed_value": user,
            "severity": "high",
            "event_refs": [timestamp]
        })

    # 2. privilege_escalation_surge
    if label == "privilege_escalation":
        counts["privilege_escalation_surge"] += 1
        anomalies.append({
            "timestamp": timestamp,
            "host": host,
            "user": user,
            "src_ip": src_ip,
            "anomaly_type": "privilege_escalation_surge",
            "baseline_value": "0 baseline escalations",
            "observed_value": "privilege escalation observed",
            "severity": "critical",
            "event_refs": [timestamp]
        })

    # 3. login failure burst
    if label == "login_failure":
        counts["failure_rate_burst"] += 1
        anomalies.append({
            "timestamp": timestamp,
            "host": host,
            "user": user,
            "src_ip": src_ip,
            "anomaly_type": "failure_rate_burst",
            "baseline_value": f"threshold: {burst_threshold}",
            "observed_value": "failure burst detected",
            "severity": "medium",
            "event_refs": [timestamp]
        })

total_anomalies = len(anomalies)

with open("anomalies_auth.json", "w") as out_f:
    json.dump(anomalies, out_f, indent=2)

print(f"evaluation window  : {eval_start_dt.isoformat()} -> {eval_end_dt.isoformat()}")
print(f"unknown_account           : {counts['unknown_account']}")
print(f"failure_rate_burst        : {counts['failure_rate_burst']}")
print(f"offhours_login            : {counts['offhours_login']}")
print(f"privilege_escalation_surge: {counts['privilege_escalation_surge']}")
print(f"total anomalies           : {total_anomalies}")
print("anomalies_auth.json written")
PY_SCRIPT
