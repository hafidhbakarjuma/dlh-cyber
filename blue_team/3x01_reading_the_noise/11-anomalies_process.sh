#!/bin/bash
set -euo pipefail

python3 - << 'PY_SCRIPT'
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from collections import defaultdict

# --- SEVERITY RUBRIC ---
SEVERITY_RUBRIC = {
    "high_risk_process": "critical",
    "unknown_parent_child": "high",
    "unknown_process_for_host": "medium",
    "rare_process_spike": "medium"
}

WATCHLIST = {
    'powershell.exe', 'cmd.exe', 'wscript.exe', 'mshta.exe', 
    'nc', 'nmap', 'wget', 'curl', 'python3', 'bash'
}

def parse_dt(ts_str):
    if not ts_str:
        return None
    try:
        if ts_str.endswith('Z'):
            ts_str = ts_str[:-1] + '+00:00'
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except Exception:
        return None

if not os.path.exists("baseline_summary.json"):
    print("Error: baseline_summary.json not found. Run Task 9 first.", file=sys.stderr)
    exit(1)

if not os.path.exists("labeled_events.json"):
    print("Error: labeled_events.json not found. Run Task 3 first.", file=sys.stderr)
    exit(1)

with open("baseline_summary.json", "r") as f:
    summary = json.load(f)

eval_win = summary.get("evaluation_window", {})
eval_start_dt = parse_dt(eval_win.get("start"))
eval_end_dt = parse_dt(eval_win.get("end"))

if not eval_start_dt or not eval_end_dt:
    base_end_str = summary.get("baseline_window", {}).get("end")
    base_end_dt = parse_dt(base_end_str)
    if base_end_dt:
        eval_start_dt = base_end_dt
        eval_end_dt = eval_start_dt + timedelta(hours=24)
    else:
        print("Error: Evaluation window not defined in baseline_summary.json", file=sys.stderr)
        exit(1)

baseline_win = summary.get("baseline_window", {})
base_start_dt = parse_dt(baseline_win.get("start"))
base_end_dt = parse_dt(baseline_win.get("end"))

# Load all events and normalize process fields
events = []
with open("labeled_events.json", "r") as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            e = json.loads(line)
            p_name = e.get("process_name") or e.get("process")
            raw = (e.get("raw_message") or "").lower()
            
            if not p_name:
                for tool in WATCHLIST:
                    if tool in raw:
                        p_name = tool
                        break
                if not p_name and ("exec" in raw or "spawn" in raw or "process" in raw or e.get("event_category") == "process"):
                    p_name = "unknown_process"
            
            e["_norm_process"] = p_name
            e["_norm_parent"] = e.get("parent_process_name") or e.get("parent_process") or "unknown_parent"
            e["_norm_host"] = e.get("hostname") or e.get("host") or "unknown_host"
            e["_norm_user"] = e.get("user") or e.get("username") or "unknown_user"
            
            ts_str = e.get("timestamp") or e.get("time") or e.get("@timestamp")
            dt = parse_dt(ts_str)
            if dt:
                e["_dt"] = dt
            
            events.append(e)
        except Exception:
            continue

# Build baseline profiles per host
host_baseline_processes = defaultdict(set)
host_baseline_pairs = defaultdict(set)
host_baseline_counts = defaultdict(lambda: defaultdict(int))

if base_start_dt and base_end_dt:
    for e in events:
        if "_dt" in e and base_start_dt <= e["_dt"] < base_end_dt:
            h = e["_norm_host"]
            p = e["_norm_process"]
            parent = e["_norm_parent"]
            if p:
                host_baseline_processes[h].add(p)
                host_baseline_pairs[h].add((parent, p))
                host_baseline_counts[h][p] += 1

# Scan evaluation window
eval_events = []
for e in events:
    if "_dt" in e and eval_start_dt <= e["_dt"] < eval_end_dt:
        if e.get("event_category") == "process" or e.get("_norm_process"):
            eval_events.append(e)

anomalies = []
counts = {
    "unknown_process_for_host": 0,
    "unknown_parent_child": 0,
    "rare_process_spike": 0,
    "high_risk_process": 0
}

eval_process_counts = defaultdict(lambda: defaultdict(int))
for e in eval_events:
    p = e["_norm_process"]
    h = e["_norm_host"]
    if p:
        eval_process_counts[h][p] += 1

alerted_events = set()

for e in eval_events:
    h = e["_norm_host"]
    p = e["_norm_process"]
    parent = e["_norm_parent"]
    user = e["_norm_user"]
    timestamp = e.get("timestamp") or e.get("time") or e.get("@timestamp")
    event_id = e.get("id", timestamp)

    if not p: continue

    if p.lower() in WATCHLIST and p not in host_baseline_processes[h]:
        counts["high_risk_process"] += 1
        anomalies.append({
            "timestamp": timestamp,
            "host": h,
            "user": user,
            "process_name": p,
            "parent_process_name": parent,
            "anomaly_type": "high_risk_process",
            "severity": SEVERITY_RUBRIC["high_risk_process"],
            "event_refs": [event_id]
        })
        alerted_events.add((event_id, "high_risk_process"))

    if p not in host_baseline_processes[h] and (event_id, "high_risk_process") not in alerted_events:
        counts["unknown_process_for_host"] += 1
        anomalies.append({
            "timestamp": timestamp,
            "host": h,
            "user": user,
            "process_name": p,
            "parent_process_name": parent,
            "anomaly_type": "unknown_process_for_host",
            "severity": SEVERITY_RUBRIC["unknown_process_for_host"],
            "event_refs": [event_id]
        })

    if (parent, p) not in host_baseline_pairs[h]:
        counts["unknown_parent_child"] += 1
        anomalies.append({
            "timestamp": timestamp,
            "host": h,
            "user": user,
            "process_name": p,
            "parent_process_name": parent,
            "anomaly_type": "unknown_parent_child",
            "severity": SEVERITY_RUBRIC["unknown_parent_child"],
            "event_refs": [event_id]
        })

    base_count = host_baseline_counts[h][p]
    eval_count = eval_process_counts[h][p]
    if base_count < 5 and eval_count > 10:
        counts["rare_process_spike"] += 1
        anomalies.append({
            "timestamp": timestamp,
            "host": h,
            "user": user,
            "process_name": p,
            "parent_process_name": parent,
            "anomaly_type": "rare_process_spike",
            "severity": SEVERITY_RUBRIC["rare_process_spike"],
            "event_refs": [event_id]
        })

total_anomalies = len(anomalies)

with open("anomalies_process.json", "w") as out_f:
    json.dump(anomalies, out_f, indent=2)

print(f"evaluation window : {eval_start_dt.isoformat()} -> {eval_end_dt.isoformat()}")
print(f"unknown_process_for_host : {counts['unknown_process_for_host']}")
print(f"unknown_parent_child     : {counts['unknown_parent_child']}")
print(f"rare_process_spike       : {counts['rare_process_spike']}")
print(f"high_risk_process        : {counts['high_risk_process']}")
print(f"total anomalies          : {total_anomalies}")
print("anomalies_process.json written")
PY_SCRIPT
