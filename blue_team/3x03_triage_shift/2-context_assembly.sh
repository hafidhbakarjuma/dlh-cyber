#!/bin/bash
set -euo pipefail

# Set default environment variables if not already defined
: "${CATALOG_DIR:=$HOME/3x02_package/detection_catalog}"
: "${HANDOFF_DIR:=$HOME/3x00_handoff/evidence_handoff}"
: "${BASELINE_PKG:=$HOME/3x01_package/baseline_package}"
: "${ASSETS_DIR:=$HOME/3x03_assets}"

mkdir -p tickets

python3 - << 'PY'
import json
import os
import sys

catalog_dir = os.environ.get("CATALOG_DIR", os.path.expanduser("~/3x02_package/detection_catalog"))
handoff_dir = os.environ.get("HANDOFF_DIR", os.environ.get("HANDOFF_DIR", os.path.expanduser("~/3x00_handoff/evidence_handoff")))
baseline_pkg = os.environ.get("BASELINE_PKG", os.path.expanduser("~/3x01_package/baseline_package"))
assets_dir = os.environ.get("ASSETS_DIR", os.path.expanduser("~/3x03_assets"))

# Flexible path resolution
def locate_file(primary_path, filename):
    if os.path.exists(primary_path):
        return primary_path
    for root, dirs, files in os.walk(os.path.expanduser("~")):
        if filename in files:
            return os.path.join(root, filename)
    return primary_path

alert_path = locate_file(os.path.join(catalog_dir, "alerts", "alert_queue.json"), "alert_queue.json")
asset_inv_path = locate_file(os.path.join(handoff_dir, "context", "asset_inventory.json"), "asset_inventory.json")
events_path = locate_file(os.path.join(handoff_dir, "data", "enriched_events.json"), "enriched_events.json")
baseline_path = locate_file(os.path.join(baseline_pkg, "baselines", "baseline_summary.json"), "baseline_summary.json")
ioc_path = locate_file(os.path.join(assets_dir, "ioc_context.json"), "ioc_context.json")

# Load inputs safely
with open(alert_path, 'r', encoding='utf-8') as f:
    alert_data = json.load(f)
alerts = alert_data if isinstance(alert_data, list) else alert_data.get("alerts", [])

asset_inventory = {}
if os.path.exists(asset_inv_path):
    with open(asset_inv_path, 'r', encoding='utf-8') as f:
        inv_data = json.load(f)
        if isinstance(inv_data, list):
            for item in inv_data:
                h = item.get("hostname") or item.get("name")
                if h:
                    asset_inventory[h] = item
        elif isinstance(inv_data, dict):
            asset_inventory = inv_data.get("assets", inv_data)

events_store = {}
if os.path.exists(events_path):
    with open(events_path, 'r', encoding='utf-8') as f:
        ev_data = json.load(f)
        if isinstance(ev_data, list):
            for ev in ev_data:
                ev_id = ev.get("event_id") or ev.get("id") or ev.get("timestamp")
                if ev_id:
                    events_store[str(ev_id)] = ev
        elif isinstance(ev_data, dict):
            events_store = ev_data.get("events", ev_data)

baseline_summary = {}
if os.path.exists(baseline_path):
    with open(baseline_path, 'r', encoding='utf-8') as f:
        baseline_summary = json.load(f)

ioc_context = {}
if os.path.exists(ioc_path):
    with open(ioc_path, 'r', encoding='utf-8') as f:
        ioc_context = json.load(f)

alerts_processed = len(alerts)
assets_joined = 0
missing_assets = 0
alerts_with_ioc_hits = 0
ioc_stats = {"malicious": 0, "suspicious": 0, "unknown": 0, "clean": 0}
baseline_profiles_joined = 0

enriched_queue = []

for alert in alerts:
    score = alert.get("priority_score", 0)
    if score >= 20:
        band = "critical"
    elif score >= 10:
        band = "high"
    elif score >= 5:
        band = "medium"
    else:
        band = "low"
    alert["priority_band"] = band

    hostname = alert.get("target_host") or alert.get("hostname") or alert.get("event_summary", {}).get("hostname", "")
    asset_rec = asset_inventory.get(hostname)
    if not asset_rec:
        for k, v in asset_inventory.items():
            if k.lower() == hostname.lower():
                asset_rec = v
                break
    
    if asset_rec:
        assets_joined += 1
        alert["asset"] = asset_rec
    else:
        missing_assets += 1
        alert["asset"] = {"hostname": hostname, "criticality": "unknown", "role": "unknown", "data_classification": "unknown", "owner": "unknown", "network_zone": "unknown"}

    bp = baseline_summary.get(hostname, baseline_summary.get("hosts", {}).get(hostname, {}))
    if bp:
        baseline_profiles_joined += 1
        alert["baseline_host_profile"] = bp
    else:
        alert["baseline_host_profile"] = {}

    event_ref = alert.get("event_ref") or alert.get("event_id") or alert.get("event_summary", {}).get("event_id")
    event_rec = {}
    if event_ref and str(event_ref) in events_store:
        event_rec = events_store[str(event_ref)]
    else:
        summary = alert.get("event_summary", {})
        ts = summary.get("timestamp")
        for ev in (events_store.values() if isinstance(events_store, dict) else events_store):
            if isinstance(ev, dict) and (ev.get("timestamp") == ts or ev.get("event_id") == event_ref):
                event_rec = ev
                break
    alert["event_record"] = event_rec

    strings_to_check = set()
    def extract_strings(obj):
        if isinstance(obj, str):
            strings_to_check.add(obj)
        elif isinstance(obj, dict):
            for k, v in obj.items():
                extract_strings(v)
        elif isinstance(obj, list):
            for item in obj:
                extract_strings(item)
    
    extract_strings(alert)
    extract_strings(event_rec)

    hits = []
    has_hit = False
    matched_reps = set()
    for s in strings_to_check:
        if s in ioc_context:
            ioc_info = ioc_context[s]
            rep = ioc_info.get("reputation", "clean")
            hit_entry = {"indicator": s, **ioc_info}
            if rep != "clean":
                hit_entry["ioc_flag"] = True
            hits.append(hit_entry)
            has_hit = True
            matched_reps.add(rep)

    if has_hit:
        alerts_with_ioc_hits += 1
        # Count highest severity reputation per alert for reporting
        for rep in ["malicious", "suspicious", "unknown", "clean"]:
            if rep in matched_reps:
                ioc_stats[rep] += 1
                break

    alert["ioc_hits"] = hits
    enriched_queue.append(alert)

out_file = "enriched_queue.json"
with open(out_file, 'w', encoding='utf-8') as f:
    json.dump(enriched_queue, f, indent=2)
    f.write("\n")

file_size_kb = round(os.path.getsize(out_file) / 1024)

print(f"alerts processed          : {alerts_processed}")
print(f"assets joined             : {assets_joined}")
print(f"missing asset records     : {missing_assets}")
print(f"alerts with IOC hits      : {alerts_with_ioc_hits}")
print(f"  malicious               : {ioc_stats.get('malicious', 0)}")
print(f"  suspicious              : {ioc_stats.get('suspicious', 0)}")
print(f"  unknown                 : {ioc_stats.get('unknown', 0)}")
print(f"baseline profiles joined  : {baseline_profiles_joined}")
print(f"enriched_queue.json written ({file_size_kb} KB)")
PY
