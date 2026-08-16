#!/bin/bash
set -euo pipefail

PCAP_PATH="${1:-/home/analyst/MedDefense_Lab/PCAPs/mixed_traffic.pcap}"
CONFIG_FILE="suricata.yaml"
TMP_DIR="/tmp/suricata-analysis"
OUTPUT_FILE="suricata_alerts.json"
CAT_FILE="signature_categories.json"

echo "[*] Starting Suricata analysis on PCAP: $PCAP_PATH"
STARTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

suricata -c "$CONFIG_FILE" -r "$PCAP_PATH" -l "$TMP_DIR"

FINISHED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
EVE_JSON="$TMP_DIR/eve.json"

if [ ! -f "$EVE_JSON" ]; then
    echo "Error: eve.json not found in $TMP_DIR"
    exit 1
fi

python3 - <<EOF
import json
import os
from collections import Counter

pcap_path = "$PCAP_PATH"
started_at = "$STARTED_AT"
finished_at = "$FINISHED_AT"
eve_file = "$EVE_JSON"
cat_file = "$CAT_FILE"
output_file = "$OUTPUT_FILE"

sig_categories = {}
if os.path.exists(cat_file):
    try:
        with open(cat_file, 'r') as f:
            sig_categories = json.load(f)
    except Exception:
        pass

alerts = []
total_alerts = 0
severity_dist = Counter()
by_category = Counter()
src_counts = Counter()
dst_counts = Counter()
sig_counts = Counter()

if os.path.exists(eve_file):
    with open(eve_file, 'r') as f:
        for line in f:
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                if record.get("event_type") == "alert":
                    total_alerts += 1
                    alert_info = record.get("alert", {})
                    
                    timestamp = record.get("timestamp")
                    src_ip = record.get("src_ip")
                    src_port = record.get("src_port")
                    dst_ip = record.get("dst_ip")
                    dst_port = record.get("dst_port")
                    proto = record.get("proto")
                    
                    sig = alert_info.get("signature")
                    sig_id = alert_info.get("signature_id")
                    category = alert_info.get("category")
                    severity = alert_info.get("severity")
                    
                    mapped_category = sig_categories.get(str(sig_id), sig_categories.get(sig, "other"))
                    if not mapped_category:
                        mapped_category = "other"
                        
                    severity_dist[str(severity)] += 1
                    by_category[mapped_category] += 1
                    if src_ip:
                        src_counts[src_ip] += 1
                    if dst_ip:
                        dst_counts[dst_ip] += 1
                    if sig:
                        sig_counts[sig] += 1
                        
                    alerts.append({
                        "timestamp": timestamp,
                        "src_ip": src_ip,
                        "src_port": src_port,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "proto": proto,
                        "signature": sig,
                        "signature_id": sig_id,
                        "category": category,
                        "severity": severity,
                        "mapped_category": mapped_category
                    })
            except json.JSONDecodeError:
                continue

unique_signatures = len(sig_counts)

output_data = {
    "pcap": pcap_path,
    "started_at": started_at,
    "finished_at": finished_at,
    "total_alerts": total_alerts,
    "unique_signatures": unique_signatures,
    "severity_distribution": dict(severity_dist),
    "by_category": dict(by_category),
    "top_sources": dict(src_counts.most_common(10)),
    "top_destinations": dict(dst_counts.most_common(10)),
    "by_signature": dict(sig_counts),
    "alerts": alerts
}

with open(output_file, 'w') as f:
    json.dump(output_data, f, indent=2)

print(f"[*] Analysis complete. Saved output to {output_file}. Total alerts: {total_alerts}")
EOF
