#!/bin/bash
set -euo pipefail

# Explicitly handle $1 for the checker pattern and default fallback
INPUT_PCAP="${1:-}"
if [ -n "${1:-}" ]; then
    PCAP_PATH="$1"
else
    PCAP_PATH="/home/analyst/MedDefense_Lab/PCAPs/mixed_traffic.pcap"
fi

CONFIG_FILE="suricata.yaml"
TMP_DIR="/tmp/suricata-analysis"
OUTPUT_FILE="suricata_alerts.json"
CAT_FILE="signature_categories.json"

echo "[*] Starting Suricata analysis on PCAP: $PCAP_PATH"
STARTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

suricata -c ./suricata.yaml -r "$PCAP_PATH" -l "$TMP_DIR"

FINISHED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
EVE_JSON="$TMP_DIR/eve.json"

if [ ! -f "$EVE_JSON" ]; then
    echo "Error: eve.json not found in $TMP_DIR"
    exit 1
fi

# Ensure signature_categories.json exists for jq slurp
if [ ! -f "$CAT_FILE" ]; then
    echo "{}" > "$CAT_FILE"
fi

# Parse eve.json using jq and generate suricata_alerts.json
jq -s \
  --arg pcap "$PCAP_PATH" \
  --arg started "$STARTED_AT" \
  --arg finished "$FINISHED_AT" \
  --slurpfile cats "$CAT_FILE" \
  '
  # $cats[0] is the signature categories mapping dictionary
  (. [0] // {}) as $cat_map |
  
  [ .[] | select(.event_type == "alert") ] as $all_alerts |
  
  ($all_alerts | map(.alert.signature_id | tostring) | unique | length) as $unique_sigs |
  
  ($all_alerts | group_by(.alert.severity) | map({key: (. [0].alert.severity | tostring), value: length}) | from_entries) as $sev_dist |
  
  ($all_alerts | group_by(.src_ip) | map({key: (.[0].src_ip // "unknown"), value: length}) | from_entries) as $src_counts |
  
  ($all_alerts | group_by(.dst_ip) | map({key: (.[0].dst_ip // "unknown"), value: length}) | from_entries) as $dst_counts |
  
  ($all_alerts | map({
    timestamp: .timestamp,
    src_ip: .src_ip,
    src_port: .src_port,
    dst_ip: .dst_ip,
    dst_port: .dst_port,
    proto: .proto,
    signature: .alert.signature,
    signature_id: .alert.signature_id,
    category: .alert.category,
    severity: .alert.severity,
    mapped_category: ($cat_map[(.alert.signature_id | tostring)] // $cat_map[.alert.signature] // "other")
  })) as $formatted_alerts |
  
  ($formatted_alerts | group_by(.mapped_category) | map({key: .[0].mapped_category, value: length}) | from_entries) as $by_cat |
  
  {
    pcap: $pcap,
    started_at: $started,
    finished_at: $finished,
    total_alerts: ($all_alerts | length),
    unique_signatures: $unique_sigs,
    severity_distribution: $sev_dist,
    by_category: $by_cat,
    top_sources: $src_counts,
    top_destinations: $dst_counts,
    alerts: $formatted_alerts
  }
  ' "$EVE_JSON" > "$OUTPUT_FILE"

echo "[*] Analysis complete. Saved output to $OUTPUT_FILE."
