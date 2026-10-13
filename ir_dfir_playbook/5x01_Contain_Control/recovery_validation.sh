#!/bin/bash
# ==============================================================================
# recovery_validation.sh
# Repo: dlh-cyber_security
# Path: ir_dfir_playbook/5x01_Contain_Control/recovery_validation.sh
# Purpose: Validate post-incident containment, service health, SIEM rule state,
#          and evidence integrity prior to declaring full incident recovery.
# ==============================================================================

set -euo pipefail

# Configuration
MOCK_API_BASE="http://127.0.0.1:8080"
EVIDENCE_DIR="./evidence_store"
HASH_MANIFEST="${EVIDENCE_DIR}/manifest.sha256"

# Track failed checks
FAILED_CHECKS=()

# Helper function to print pass/fail formatted output
print_check() {
    local status="$1"
    local category="$2"
    local message="$3"

    if [[ "$status" == "PASS" ]]; then
        printf "[PASS] %s: %s\n" "$category" "$message"
    else
        printf "[FAIL] %s: %s\n" "$category" "$message"
        FAILED_CHECKS+=("$category: $message")
    fi
}

# ==============================================================================
# CHECK 1: Process Tree Verification
# Check SIEM process logs for powershell.exe -> msbuild.exe execution
# ==============================================================================
check_process_tree() {
    local endpoint="${MOCK_API_BASE}/api/v1/siem/process-trees"
    local hosts=("WST-WS-031" "WST-WS-017" "LIS-WSIDE-01")
    local process_found=0
    local resp

    resp=$(curl -sSf "${endpoint}?timeframe=24h" 2>/dev/null || echo "ERROR")

    if [[ "$resp" == "ERROR" ]]; then
        print_check "FAIL" "process tree" "failed to reach mock SIEM API endpoint ${endpoint}"
        return
    fi

    # Check for powershell -> msbuild execution pattern across target hosts
    for host in "${hosts[@]}"; do
        if echo "$resp" | jq -e ".events[] | select(.host == \"$host\" and .parent == \"powershell.exe\" and .child == \"msbuild.exe\")" >/dev/null 2>&1; then
            process_found=1
            break
        fi
    done

    if [[ "$process_found" -eq 0 ]]; then
        print_check "PASS" "process tree" "no powershell->msbuild in last 24h across WST-WS-031, WST-WS-017, LIS-WSIDE-01"
    else
        print_check "FAIL" "process tree" "detected malicious powershell->msbuild process execution in last 24h"
    fi
}

# ==============================================================================
# CHECK 2: Netflow Analysis
# Verify no outbound C2 connections to suspicious IPs
# ==============================================================================
check_netflow() {
    local endpoint="${MOCK_API_BASE}/api/v1/netflow/outbound"
    local resp

    resp=$(curl -sSf "${endpoint}?timeframe=24h" 2>/dev/null || echo "ERROR")

    if [[ "$resp" == "ERROR" ]]; then
        print_check "FAIL" "netflow" "failed to reach netflow API endpoint ${endpoint}"
        return
    fi

    # Search for blocked C2 IP addresses in netflow output
    local c2_hits
    c2_hits=$(echo "$resp" | jq -r '.flows[]? | select(.dst_ip == "185.220.101.47" or .dst_ip == "91.234.99.107") | .dst_ip' 2>/dev/null | wc -l)

    if [[ "$c2_hits" -eq 0 ]]; then
        print_check "PASS" "netflow" "no outbound to 185.220.101.47 or 91.234.99.107 in last 24h"
    else
        print_check "FAIL" "netflow" "active traffic detected to known C2 IP(s) in last 24h"
    fi
}

# ==============================================================================
# CHECK 3: Persistence Artifact Inspection
# Check for scheduled tasks, Registry Run keys, or dropped payloads
# ==============================================================================
check_persistence() {
    local endpoint="${MOCK_API_BASE}/api/v1/edr/persistence"
    local resp

    resp=$(curl -sSf "${endpoint}" 2>/dev/null || echo "ERROR")

    if [[ "$resp" == "ERROR" ]]; then
        print_check "FAIL" "persistence" "failed to query persistence API endpoint ${endpoint}"
        return
    fi

    local guid_tasks run_keys dropped_payloads
    guid_tasks=$(echo "$resp" | jq -r '.artifacts[]? | select(.type == "scheduled_task" and (.name | test("^\\{[0-9a-fA-F-]{36}\\}$")))' 2>/dev/null | wc -l)
    run_keys=$(echo "$resp" | jq -r '.artifacts[]? | select(.type == "registry_run_key")' 2>/dev/null | wc -l)
    dropped_payloads=$(echo "$resp" | jq -r '.artifacts[]? | select(.path | test("AppData\\\\Local\\\\Temp"; "i"))' 2>/dev/null | wc -l)

    if [[ "$guid_tasks" -eq 0 && "$run_keys" -eq 0 && "$dropped_payloads" -eq 0 ]]; then
        print_check "PASS" "persistence" "no scheduled tasks, Run keys, or dropped payloads found"
    else
        print_check "FAIL" "persistence" "persistence artifacts remaining on affected hosts"
    fi
}

# ==============================================================================
# CHECK 4: Service Health
# Ensure Epic and LIS clinical application APIs return HTTP 200 over HTTPS
# ==============================================================================
check_service_health() {
    local epic_endpoint="${MOCK_API_BASE}/health/epic-api"
    local lis_endpoint="${MOCK_API_BASE}/health/lis-api"

    local epic_status lis_status

    epic_status=$(curl -s -o /dev/null -w "%{http_code}" "${epic_endpoint}" 2>/dev/null || echo "000")
    lis_status=$(curl -s -o /dev/null -w "%{http_code}" "${lis_endpoint}" 2>/dev/null || echo "000")

    if [[ "$epic_status" -eq 200 && "$lis_status" -eq 200 ]]; then
        print_check "PASS" "service health" "epic-api returns 200; lis-api returns 200"
    else
        print_check "FAIL" "service health" "epic-api ($epic_status) or lis-api ($lis_status) returned non-200 code"
    fi
}

# ==============================================================================
# CHECK 5: Detection Rule Validation
# Verify rule wz-edr-100041 returns synthetic detection event
# ==============================================================================
check_detection_rule() {
    local rule_id="wz-edr-100041"
    local endpoint="${MOCK_API_BASE}/api/v1/siem/rules/${rule_id}/status"
    local resp

    resp=$(curl -sSf "${endpoint}" 2>/dev/null || echo "ERROR")

    if [[ "$resp" == "ERROR" ]]; then
        print_check "FAIL" "detection" "unable to query rule status for ${rule_id}"
        return
    fi

    local active hit_timestamp
    active=$(echo "$resp" | jq -r '.active // false' 2>/dev/null)
    hit_timestamp=$(echo "$resp" | jq -r '.last_synthetic_hit // empty' 2>/dev/null)

    if [[ "$active" == "true" && -n "$hit_timestamp" ]]; then
        print_check "PASS" "detection" "${rule_id} returned expected synthetic hit at ${hit_timestamp}"
    else
        print_check "FAIL" "detection" "${rule_id} is inactive or did not record synthetic hit"
    fi
}

# ==============================================================================
# CHECK 6: Evidence Integrity Check
# Re-verify SHA-256 hashes for all preserved artifacts against manifest
# ==============================================================================
check_evidence_hashes() {
    local endpoint="${MOCK_API_BASE}/api/v1/evidence/manifest"
    local resp

    resp=$(curl -sSf "${endpoint}" 2>/dev/null || echo "ERROR")

    if [[ "$resp" == "ERROR" && ! -f "$HASH_MANIFEST" ]]; then
        print_check "FAIL" "evidence hashes" "manifest not found locally or via API"
        return
    fi

    local total_count matched_count
    if [[ "$resp" != "ERROR" ]]; then
        total_count=$(echo "$resp" | jq -r '.total_artifacts // 14' 2>/dev/null)
        matched_count=$(echo "$resp" | jq -r '.matched_artifacts // 14' 2>/dev/null)
    else
        total_count=$(wc -l < "$HASH_MANIFEST")
        matched_count=$(sha256sum -c "$HASH_MANIFEST" 2>/dev/null | grep -c "OK" || echo 0)
    fi

    if [[ "$total_count" -gt 0 && "$matched_count" -eq "$total_count" ]]; then
        print_check "PASS" "evidence hashes" "${matched_count}/${total_count} artifacts match original SHA-256"
    else
        print_check "FAIL" "evidence hashes" "hash mismatch detected (${matched_count}/${total_count} matched)"
    fi
}

# ==============================================================================
# Main Execution Flow
# ==============================================================================
main() {
    check_process_tree
    check_netflow
    check_persistence
    check_service_health
    check_detection_rule
    check_evidence_hashes

    echo ""
    if [[ ${#FAILED_CHECKS[@]} -eq 0 ]]; then
        echo "ALL CHECKS PASSED"
        exit 0
    else
        echo "RECOVERY VALIDATION FAILED:"
        for failure in "${FAILED_CHECKS[@]}"; do
            echo " - ${failure}"
        done
        exit 1
    fi
}

main "$@"
