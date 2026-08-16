#!/bin/bash
set -euo pipefail

RULES_FILE="meddefense.rules"
LAB_DIR="/home/analyst/MedDefense_Lab/PCAPs/labels"
OUTPUT_JSON="rule_validation.json"
PASSED=0
FAILED=0
TOTAL=0

if [ ! -f "$RULES_FILE" ]; then
    echo "Error: $RULES_FILE not found."
    exit 1
fi

RULE_COUNT=$(grep -c "^alert" "$RULES_FILE")
echo "[*] Loading $RULES_FILE...          $RULE_COUNT rules"
echo "[*] Running validation against labeled PCAPs..."

declare -A TARGETS=(
    ["9000001"]="meddev_egress.pcap"
    ["9000002"]="guest_smb.pcap"
    ["9000003"]="large_outbound.pcap"
    ["9000004"]="dns_tunnel.pcap"
    ["9000005"]="clinical_wrong_db.pcap"
    ["9000006"]="telnet_meddev.pcap"
)

declare -A NAMES=(
    ["9000001"]="MEDDEV to Internet"
    ["9000002"]="Guest to SMB"
    ["9000003"]="Large Outbound From Server"
    ["9000004"]="DNS Tunneling Long Label"
    ["9000005"]="Clinical to Unauthorized DB"
    ["9000006"]="Telnet to MEDDEV"
)

RESULTS="[]"

for sid in 9000001 9000002 9000003 9000004 9000005 9000006; do
    TOTAL=$((TOTAL + 1))
    pcap_name="${TARGETS[$sid]}"
    pcap_path="$LAB_DIR/$pcap_name"
    rule_name="${NAMES[$sid]}"
    
    tmp_dir=$(mktemp -d)
    
    # Run suricata offline against target PCAP using custom rules
    suricata -c ./suricata.yaml -s "$RULES_FILE" -r "$pcap_path" -l "$tmp_dir" > /dev/null 2>&1 || true
    
    eve_file="$tmp_dir/eve.json"
    hits=0
    if [ -f "$eve_file" ]; then
        hits=$(jq --argjson s "$sid" '[.[] | select(.event_type == "alert" and .alert.signature_id == $s)] | length' "$eve_file" 2>/dev/null || echo "0")
    fi
    
    rm -rf "$tmp_dir"
    
    status="FAIL"
    if [ "$hits" -gt 0 ]; then
        status="PASS"
        PASSED=$((PASSED + 1))
    else
        FAILED=$((FAILED + 1))
    fi
    
    echo -n "sid $sid $rule_name"
    echo -n "  target: $pcap_name"
    echo -n "  expected: fire"
    
    if [ "$status" == "PASS" ]; then
        echo "  observed: fire ($hits hits)                PASS"
    else
        echo "  observed: NO FIRE                         FAIL"
    fi
    
    # Append result to JSON array
    RESULTS=$(jq -n --argjson arr "$RESULTS" --arg sid "$sid" --arg name "$rule_name" --arg target "$pcap_name" --argjson hits "$hits" --arg status "$status" '$arr + [{sid: $sid, name: $name, target: $target, expected: "fire", observed_hits: $hits, status: $status}]')
done

echo "Rules:  $TOTAL"
echo "Passed: $PASSED"
echo "Failed: $FAILED"

# Write validation results to rule_validation.json
jq -n --argjson rules "$RESULTS" --argjson total "$TOTAL" --argjson passed "$PASSED" --argjson failed "$FAILED" \
   '{total_rules: $total, passed: $passed, failed: $failed, results: $rules}' > "$OUTPUT_JSON"

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
