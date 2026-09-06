#!/bin/bash
set -euo pipefail

RULES_DIR="rules/sigma"
TUNED_DIR="rules/sigma/tuned"
PRIORITY_JSON="rule_prioritization.json"
OUTPUT_ALERTS="alert_queue.json"
OUTPUT_SCHEMA="alert_queue_schema.json"

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff}"
if [[ ! -d "$HANDOFF_DIR" ]]; then
    HANDOFF_DIR="/home/student/3x00_handoff"
fi
ASSET_INVENTORY="$HANDOFF_DIR/context/asset_inventory.json"
if [[ ! -f "$ASSET_INVENTORY" ]] && [[ -f "$ASSETS_DIR/asset_inventory.json" ]]; then
    ASSET_INVENTORY="$ASSETS_DIR/asset_inventory.json"
fi

python3 - "$RULES_DIR" "$TUNED_DIR" "$PRIORITY_JSON" "$OUTPUT_ALERTS" "$OUTPUT_SCHEMA" "$ASSET_INVENTORY" << 'PY'
import sys
import os
import json
import subprocess
import yaml
import uuid
import hashlib
from datetime import datetime, timezone

rules_dir = sys.argv[1]
tuned_dir = sys.argv[2]
priority_json_path = sys.argv[3]
output_alerts_path = sys.argv[4]
output_schema_path = sys.argv[5]
asset_inventory_path = sys.argv[6]

# 1. Load priority scores from rule_prioritization.json
priority_map = {}
if os.path.exists(priority_json_path):
    try:
        with open(priority_json_path, 'r', encoding='utf-8') as f:
            for item in json.load(f):
                priority_map[item.get("rule_title")] = item.get("priority_score", 0.0)
    except Exception:
        pass

# 2. Load Asset Inventory
asset_inventory = {}
if os.path.exists(asset_inventory_path):
    try:
        with open(asset_inventory_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if isinstance(data, list):
                for ast in data:
                    name = ast.get("hostname") or ast.get("name")
                    if name:
                        asset_inventory[name] = ast
            elif isinstance(data, dict):
                asset_inventory = data
    except Exception:
        pass

# 3. Enumerate active rules (tuned overrides original by filename/title)
active_rules = {} # key: filename or rule_id, value: path
for d in [rules_dir, tuned_dir]:
    if os.path.exists(d):
        for root, _, files in os.walk(d):
            for file in files:
                if file.endswith(('.yml', '.yaml')):
                    # tuned overrides rules/sigma
                    active_rules[file] = os.path.join(root, file)

rule_paths = list(active_rules.values())
rules_executed = len(rule_paths)

raw_matches_count = 0
all_raw_alerts = []

for rpath in sorted(rule_paths):
    try:
        with open(rpath, 'r', encoding='utf-8') as f:
            rdata = yaml.safe_load(f)
    except Exception:
        continue

    rule_id = rdata.get("id", "unknown")
    rule_title = rdata.get("title", os.path.basename(rpath))
    rule_level = rdata.get("level", "medium")
    
    # Extract ATT&CK techniques from tags
    tags = rdata.get("tags", [])
    attack_techs = []
    for tag in tags:
        t_low = str(tag).lower()
        if "attack.t" in t_low:
            attack_techs.append(t_low.split("attack.")[-1].upper())

    # Run runner
    cmd = ["./3-sigma_runner.sh", rpath]
    matches = []
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if res.returncode == 0 and res.stdout.strip():
            out_json = json.loads(res.stdout.strip())
            matches = out_json.get("matches", [])
    except Exception:
        pass

    for ev in matches:
        raw_matches_count += 1
        event_ref = str(ev.get("event_ref") or ev.get("id") or ev.get("timestamp") or "unknown_ref")
        
        # Deterministic UUID5
        uuid_input = f"{rule_id}:{event_ref}"
        alert_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, uuid_input))

        timestamp = ev.get("timestamp") or datetime.now(timezone.utc).isoformat()
        hostname = ev.get("hostname", "unknown_host")
        user = ev.get("user", "unknown_user")
        src_ip = ev.get("src_ip", ev.get("source_ip"))
        dst_ip = ev.get("dst_ip", ev.get("destination_ip"))
        process_name = ev.get("process_name", ev.get("image"))
        canonical_label = ev.get("canonical_label", ev.get("label", "unknown"))
        event_category = ev.get("event_category", ev.get("category", "unknown"))

        event_summary = {
            "timestamp": timestamp,
            "hostname": hostname,
            "user": user,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "process_name": process_name,
            "canonical_label": canonical_label,
            "event_category": event_category
        }

        asset_ctx = asset_inventory.get(hostname, {"hostname": hostname, "criticality": "unknown"})
        
        raw_record_str = json.dumps(ev, sort_keys=True)
        evidence_hash = hashlib.sha256(raw_record_str.encode('utf-8')).hexdigest()

        priority_score = priority_map.get(rule_title, 0.0)

        all_raw_alerts.append({
            "alert_id": alert_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "rule_id": rule_id,
            "rule_title": rule_title,
            "rule_level": rule_level,
            "priority_score": priority_score,
            "event_ref": event_ref,
            "event_summary": event_summary,
            "asset_context": asset_ctx,
            "attack_techniques": attack_techs,
            "status": "new",
            "evidence_hash": evidence_hash
        })

# 4. Deduplicate alerts that fire within 60 seconds on same (rule_id, hostname, user)
deduped_alerts = []
seen_keys = {} # (rule_id, hostname, user) -> timestamp_dt

for alert in all_raw_alerts:
    r_id = alert["rule_id"]
    h_name = alert["event_summary"]["hostname"]
    u_name = alert["event_summary"]["user"]
    ts_str = alert["event_summary"]["timestamp"]
    
    try:
        # Parse timestamp safely
        ts_dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
    except Exception:
        ts_dt = datetime.now(timezone.utc)

    key = (r_id, h_name, u_name)
    if key in seen_keys:
        last_dt = seen_keys[key]
        diff_seconds = abs((ts_dt - last_dt).total_seconds())
        if diff_seconds <= 60:
            # Duplicate within window, skip
            continue
    
    seen_keys[key] = ts_dt
    deduped_alerts.append(alert)

after_dedup_count = len(deduped_alerts)

# 5. Sort descending by priority_score, tie-break by event_summary.timestamp ascending
def sort_key(item):
    p_score = item.get("priority_score", 0.0)
    ts = item.get("event_summary", {}).get("timestamp", "")
    return (-p_score, ts)

sorted_alerts = sorted(deduped_alerts, key=sort_key)

# Write alert_queue.json
with open(output_alerts_path, 'w', encoding='utf-8') as f:
    json.dump(sorted_alerts, f, indent=2)

# Write alert_queue_schema.json
schema_definition = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "MedDefense Alert Queue Schema",
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "alert_id": {"type": "string", "format": "uuid"},
            "generated_at": {"type": "string", "format": "date-time"},
            "rule_id": {"type": "string"},
            "rule_title": {"type": "string"},
            "rule_level": {"type": "string"},
            "priority_score": {"type": "number"},
            "event_ref": {"type": "string"},
            "event_summary": {
                "type": "object",
                "properties": {
                    "timestamp": {"type": "string"},
                    "hostname": {"type": "string"},
                    "user": {"type": "string"},
                    "src_ip": {"type": ["string", "null"]},
                    "dst_ip": {"type": ["string", "null"]},
                    "process_name": {"type": ["string", "null"]},
                    "canonical_label": {"type": "string"},
                    "event_category": {"type": "string"}
                },
                "required": ["timestamp", "hostname", "user", "canonical_label", "event_category"]
            },
            "asset_context": {"type": "object"},
            "attack_techniques": {"type": "array", "items": {"type": "string"}},
            "status": {"type": "string", "enum": ["new"]},
            "evidence_hash": {"type": "string", "pattern": "^[a-fA-F0-9]{64}$"}
        },
        "required": [
            "alert_id", "generated_at", "rule_id", "rule_title", "rule_level",
            "priority_score", "event_ref", "event_summary", "asset_context",
            "attack_techniques", "status", "evidence_hash"
        ]
    }
}

with open(output_schema_path, 'w', encoding='utf-8') as f:
    json.dump(schema_definition, f, indent=2)

# Print execution summary matching expected format
print(f"rules executed            : {rules_executed}")
print(f"raw matches               : {raw_matches_count}")
print(f"after deduplication       : {after_dedup_count}")
print("top 5 alerts")

for idx, alert in enumerate(sorted_alerts[:5], 1):
    p_score = alert["priority_score"]
    level = alert["rule_level"]
    # Extract short rule name from title or filename
    r_title = alert["rule_title"]
    # find matching rule filename if possible or format title
    hostname = alert["event_summary"]["hostname"]
    # Find rule short number/name
    short_name = r_title.lower().replace(' ', '_')
    print(f" {idx:1d}  {p_score:4.1f}  {level:<8} {short_name:<30} {hostname}")

print(f"alert_queue.json        : {after_dedup_count} alerts")
print(f"alert_queue_schema.json : written")
PY
