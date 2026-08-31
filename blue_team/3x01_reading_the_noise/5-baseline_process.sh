#!/bin/bash
set -euo pipefail

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
from collections import defaultdict

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

# Filter process-related events
process_labels = {'process_start', 'process_stop', 'child_process_spawn'}
process_events = []
for e in baseline_events:
    lbl = e.get("canonical_label", "")
    src = str(e.get("source", "")).lower()
    if lbl in process_labels or src in ["auditd", "sysmon"] or e.get("event_id") in ["1", "5"] or e.get("type") == "EXECVE":
        process_events.append(e)

# Data structures for aggregation
host_processes = defaultdict(lambda: defaultdict(lambda: {"count": 0, "first_seen": None, "last_seen": None, "users": set()}))
global_process_counts = defaultdict(int)
process_host_mapping = defaultdict(set)
parent_child_by_host = defaultdict(set)

for e in process_events:
    host = e.get("host") or e.get("hostname") or e.get("source_host") or "unknown"
    proc_name = (
        e.get("process_name") or 
        e.get("image") or 
        e.get("comm") or 
        e.get("path") or 
        e.get("name") or 
        "unknown"
    )
    # Clean up full paths to executable names if needed, or keep as is
    user = e.get("user") or e.get("username") or e.get("account") or "unknown"
    dt = e["_dt"]
    dt_str = dt.isoformat()

    if proc_name == "unknown":
        continue

    # Host process stats
    hp = host_processes[host][proc_name]
    hp["count"] += 1
    if hp["first_seen"] is None or dt_str < hp["first_seen"]:
        hp["first_seen"] = dt_str
    if hp["last_seen"] is None or dt_str > hp["last_seen"]:
        hp["last_seen"] = dt_str
    if user != "unknown":
        hp["users"].add(user)

    # Global tracking
    global_process_counts[proc_name] += 1
    process_host_mapping[proc_name].add(host)

    # Parent-child tracking
    parent_name = (
        e.get("parent_process_name") or 
        e.get("parent_image") or 
        e.get("parent") or 
        e.get("pcomm") or 
        ""
    )
    if parent_name:
        parent_child_by_host[host].add(f"{parent_name} -> {proc_name}")

# Format per_host output
per_host_output = {}
for host, procs in host_processes.items():
    per_host_output[host] = []
    for proc, stats in procs.items():
        per_host_output[host].append({
            "process_name": proc,
            "execution_count": stats["count"],
            "first_seen": stats["first_seen"],
            "last_seen": stats["last_seen"],
            "executing_users": sorted(list(stats["users"]))
        })

# Global top 50
sorted_global = sorted(global_process_counts.items(), key=lambda x: x[1], reverse=True)
global_top = [{"process_name": p, "count": c} for p, c in sorted_global[:50]]

# Rare processes (appear on only 1 host OR run fewer than 5 times total)
rare_processes = []
for proc, count in global_process_counts.items():
    hosts_seen = process_host_mapping[proc]
    if len(hosts_seen) == 1 or count < 5:
        rare_processes.append({
            "process_name": proc,
            "total_count": count,
            "hosts": sorted(list(hosts_seen))
        })

# Parent-child pairs formatting
parent_child_output = {}
total_pc_pairs = 0
for host, pairs in parent_child_by_host.items():
    parent_child_output[host] = sorted(list(pairs))
    total_pc_pairs += len(pairs)

output_data = {
    "window": {
        "start": min_ts.isoformat(),
        "end": baseline_end.isoformat()
    },
    "per_host": per_host_output,
    "global_top": global_top,
    "rare_processes": rare_processes,
    "parent_child_pairs": parent_child_output
}

with open("baseline_process.json", "w") as out_f:
    json.dump(output_data, out_f, indent=2)

top_proc_name = sorted_global[0][0] if sorted_global else "N/A"
top_proc_count = sorted_global[0][1] if sorted_global else 0

print(f"baseline window : {min_ts.isoformat()} -> {baseline_end.isoformat()}")
print(f"processes indexed by host: {len(per_host_output)} hosts")
print(f"global top process    : {top_proc_name} ({top_proc_count} executions)")
print(f"rare processes        : {len(rare_processes)}")
print(f"parent->child pairs   : {total_pc_pairs}")
print("baseline_process.json written")
PY_SCRIPT
