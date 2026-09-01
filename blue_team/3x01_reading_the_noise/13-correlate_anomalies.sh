#!/bin/bash
set -euo pipefail

python3 - << 'PY_SCRIPT'
import json
import os
import sys
from datetime import datetime, timezone, timedelta
from collections import defaultdict
import hashlib

CORRELATION_WINDOW_SECONDS = 300

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

# Load individual anomaly files safely
all_anomalies = []

def load_anomalies(filename, source_name):
    if os.path.exists(filename):
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    for item in data:
                        item["_source_category"] = source_name
                        all_anomalies.append(item)
        except Exception as e:
            print(f"Warning: Could not parse {filename}: {e}", file=sys.stderr)

load_anomalies("anomalies_auth.json", "auth")
load_anomalies("anomalies_process.json", "process")
load_anomalies("anomalies_network.json", "network")

total_single_source = len(all_anomalies)

# Load asset criticality map if available from baseline summary
asset_criticality = {}
if os.path.exists("baseline_summary.json"):
    try:
        with open("baseline_summary.json", "r") as f:
            summary = json.load(f)
            # Check host inventory or assets if present
            hosts = summary.get("host_inventory", [])
            for h in hosts:
                asset_criticality[h] = 1 # default multiplier
    except Exception:
        pass

# Group anomalies by host
host_groups = defaultdict(list)
for item in item_wrap := all_anomalies:
    host = item.get("host") or item.get("hostname") or "unknown"
    ts_str = item.get("timestamp") or item.get("time") or item.get("@timestamp")
    dt = parse_dt(ts_str)
    if dt:
        item["_dt"] = dt
        host_groups[host].append(item)

correlated_findings = []
multi_host_count = 0
max_score = 0

for host, items in host_groups.items():
    # Sort items by timestamp
    items.sort(key=lambda x: x["_dt"])
    
    # Sliding window clustering
    clusters = []
    current_cluster = []
    
    for item in items:
        if not current_cluster:
            current_cluster.append(item)
        else:
            # Check time difference from the start of the cluster or previous item
            if (item["_dt"] - current_cluster[0]["_dt"]).total_seconds() <= CORRELATION_WINDOW_SECONDS:
                current_cluster.append(item)
            else:
                if len(current_cluster) >= 2:
                    clusters.append(current_cluster)
                current_cluster = [item]
    if len(current_cluster) >= 2:
        clusters.append(current_cluster)

    for cluster in clusters:
        sources_involved = set(item.get("_source_category") for item in cluster)
        anomaly_types = set(item.get("anomaly_type") for item in cluster if item.get("anomaly_type"))
        member_refs = [item.get("event_refs", [item.get("timestamp")]) for item in cluster]
        flat_refs = [ref for sublist in member_refs for ref in (sublist if isinstance(sublist, list) else [sublist])]
        
        window_start = min(item["_dt"] for item in cluster).isoformat()
        window_end = max(item["_dt"] for item in cluster).isoformat()
        
        # Calculate score: 1 per involved source + 2 per distinct anomaly type * asset criticality multiplier
        crit_multiplier = asset_criticality.get(host, 1)
        score = (len(sources_involved) + (len(anomaly_types) * 2)) * crit_multiplier
        if score > max_score:
            max_score = score

        raw_id_string = f"{host}_{window_start}_{len(cluster)}"
        correlation_id = "corr_" + hashlib.md5(raw_id_string.encode()).hexdigest()[:8]

        finding = {
            "correlation_id": correlation_id,
            "host": host,
            "window_start": window_start,
            "window_end": window_end,
            "sources_involved": sorted(list(sources_involved)),
            "anomaly_types": sorted(list(anomaly_types)),
            "member_refs": flat_refs,
            "score": score
        }
        correlated_findings.append(finding)

with open("correlated_anomalies.json", "w") as out_f:
    json.dump(correlated_findings, out_f, indent=2)

print(f"single-source anomalies  : {total_single_source}")
print(f"correlated findings      : {len(correlated_findings)}")
print(f"multi-host findings      : {multi_host_count}")
print(f"max score                : {max_score}")
print("correlated_anomalies.json written")
PY_SCRIPT
