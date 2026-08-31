#!/bin/bash
set -euo pipefail

python3 - << 'PY_SCRIPT'
import json
import os
from datetime import datetime, timedelta

# Helper to safely load JSON files if they exist
def load_json_file(filename):
    if os.path.exists(filename):
        try:
            with open(filename, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

auth_data = load_json_file("baseline_auth.json")
process_data = load_json_file("baseline_process.json")
network_data = load_json_file("baseline_network.json")
file_data = load_json_file("baseline_file.json")
temporal_data = load_json_file("temporal_profile.json")

# Extract or derive window details
window_info = auth_data.get("window") or process_data.get("window") or {}
start_str = window_info.get("start")
end_str = window_info.get("end")

if not start_str or not end_str:
    # Fallback to current time or sensible default if individual files are incomplete
    start_dt = datetime.utcnow() - timedelta(days=7)
    end_dt = datetime.utcnow() - timedelta(days=1)
else:
    start_dt = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
    end_dt = datetime.fromisoformat(end_str.replace("Z", "+00:00"))

baseline_duration_days = max(1, round((end_dt - start_dt).total_seconds() / 86400))

# Evaluation window is the 24 hours immediately following the baseline window
eval_start_dt = end_dt
eval_end_dt = eval_start_dt + timedelta(hours=24)

# Collect host inventory across sections
hosts_set = set()
if "per_host" in auth_data:
    hosts_set.update(auth_data["per_host"].keys())
if "per_host" in process_data:
    hosts_set.update(process_data["per_host"].keys())
if "per_host" in network_data:
    hosts_set.update(network_data["per_host"].keys())
if "per_host" in file_data:
    hosts_set.update(file_data["per_host"].keys())

host_inventory = sorted(list(hosts_set))

# Define anomaly scoring thresholds derived from baseline analysis
thresholds = {
    "failure_rate_multiplier": {
        "value": 3.0,
        "comment": "Derived from baseline variance: authentication failures exceeding 3x the baseline hourly average trigger high priority alerts."
    },
    "unknown_process_penalty": {
        "value": 5,
        "comment": "Assigned weight for any process execution not found in the host's historical baseline inventory."
    },
    "unknown_port_penalty": {
        "value": 4,
        "comment": "Assigned weight for outbound network connections destined to unbaselined external ports or destinations."
    },
    "burst_failure_threshold": {
        "value": auth_data.get("max_failures_1h_window", 10) * 2,
        "comment": "Double the maximum single-source 1-hour failure burst observed during clean baseline window."
    }
}

summary_doc = {
    "version": "1.0",
    "generated_at": datetime.utcnow().isoformat() + "Z",
    "baseline_window": {
        "start": start_dt.isoformat(),
        "end": end_dt.isoformat(),
        "duration_days": baseline_duration_days
    },
    "evaluation_window": {
        "start": eval_start_dt.isoformat(),
        "end": eval_end_dt.isoformat(),
        "duration_hours": 24
    },
    "host_inventory": host_inventory,
    "auth": auth_data,
    "process": process_data,
    "network": network_data,
    "file": file_data,
    "temporal": temporal_data,
    "thresholds": thresholds
}

with open("baseline_summary.json", "w") as out_f:
    json.dump(summary_doc, out_f, indent=2)

print(f"version           : 1.0")
print(f"baseline window   : {start_dt.isoformat()} -> {end_dt.isoformat()}  ({baseline_duration_days} days)")
print(f"evaluation window : {eval_start_dt.isoformat()} -> {eval_end_dt.isoformat()}  (24h)")
print(f"hosts             : {len(host_inventory)}")
print(f"sections included : auth, process, network, file, temporal, thresholds")
print("baseline_summary.json written")
PY_SCRIPT
