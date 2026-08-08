```bash
#!/bin/bash

# Name: 12-linux_detection_proof.sh
# Purpose: Correlate Linux attacker simulation ground truth against auditd,
#          auth.log and syslog telemetry and produce a detection matrix.
# Author: Hafidh Juma
# Project: MedDefense Endpoint Telemetry Engineering

set -e
set -u
set -o pipefail

##############################################################
# Configuration
##############################################################

GROUND_TRUTH_FILE="./linux_attack_log.json"
OUTPUT_FILE="./linux_detection_matrix.json"

AUDIT_LOG="/var/log/audit/audit.log"
AUTH_LOG="/var/log/auth.log"
SYSLOG="/var/log/syslog"

WINDOW_SECONDS=30

##############################################################
# Root Check
##############################################################

if [[ "${EUID}" -ne 0 ]]; then
    echo "[!] This script must be run as root."
    echo "    Use: sudo ./12-linux_detection_proof.sh"
    exit 1
fi

##############################################################
# Required Commands
##############################################################

for command in jq ausearch date grep awk hostname; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "[!] Required command not found: $command"
        exit 1
    fi
done

##############################################################
# Input Validation
##############################################################

if [[ ! -f "$GROUND_TRUTH_FILE" ]]; then
    echo "[!] Ground truth file not found: $GROUND_TRUTH_FILE"
    exit 1
fi

if [[ ! -s "$GROUND_TRUTH_FILE" ]]; then
    echo "[!] Ground truth file is empty."
    exit 1
fi

if ! jq empty "$GROUND_TRUTH_FILE" >/dev/null 2>&1; then
    echo "[!] Invalid JSON: $GROUND_TRUTH_FILE"
    exit 1
fi

##############################################################
# Telemetry File Checks
##############################################################

AUDIT_AVAILABLE=0
AUTH_AVAILABLE=0
SYSLOG_AVAILABLE=0

if [[ -f "$AUDIT_LOG" ]]; then
    AUDIT_AVAILABLE=1
fi

if [[ -f "$AUTH_LOG" ]]; then
    AUTH_AVAILABLE=1
fi

if [[ -f "$SYSLOG" ]]; then
    SYSLOG_AVAILABLE=1
fi

##############################################################
# Temporary Files
##############################################################

TMP_DIR=$(mktemp -d)

cleanup() {
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT

##############################################################
# Timestamp Conversion
##############################################################

iso_to_epoch() {
    local timestamp="$1"

    date -u \
        -d "$timestamp" \
        '+%s' 2>/dev/null || echo "0"
}

##############################################################
# Convert Epoch To Audit Time
##############################################################

epoch_to_audit_time() {
    local epoch="$1"

    date -u \
        -d "@$epoch" \
        '+%m/%d/%Y %H:%M:%S' 2>/dev/null
}

##############################################################
# Audit Search
##############################################################

search_audit() {
    local start_epoch="$1"
    local end_epoch="$2"
    local search_term="$3"

    local output=""

    if [[ "$AUDIT_AVAILABLE" -ne 1 ]]; then
        return 0
    fi

    # ausearch understands --start/--end in audit date format.
    output=$(
        ausearch \
            --start "$(epoch_to_audit_time "$start_epoch")" \
            --end "$(epoch_to_audit_time "$end_epoch")" \
            2>/dev/null || true
    )

    if [[ -z "$output" ]]; then
        return 0
    fi

    if [[ -n "$search_term" ]]; then
        if grep -qiE "$search_term" <<< "$output"; then
            printf '%s\n' "$output"
        fi
    else
        printf '%s\n' "$output"
    fi
}

##############################################################
# Search Syslog-Style Files
##############################################################

search_text_log() {
    local file="$1"
    local timestamp="$2"
    local action="$3"

    if [[ ! -f "$file" ]]; then
        return 0
    fi

    case "$action" in

        1)
            grep -Ei \
                'useradd|new user|user account|testattacker' \
                "$file" 2>/dev/null || true
            ;;

        2)
            grep -Ei \
                'sudoers|visudo|backdoor|NOPASSWD|sudo' \
                "$file" 2>/dev/null || true
            ;;

        3)
            grep -Ei \
                'suspicious_bin|/tmp/' \
                "$file" 2>/dev/null || true
            ;;

        4)
            grep -Ei \
                '127\.0\.0\.1|4444|bash|network' \
                "$file" 2>/dev/null || true
            ;;

        5)
            grep -Ei \
                'cron|persistence_test|beacon\.sh' \
                "$file" 2>/dev/null || true
            ;;

        6)
            grep -Ei \
                '/etc/shadow|shadow' \
                "$file" 2>/dev/null || true
            ;;

        *)
            return 0
            ;;
    esac
}

##############################################################
# Determine Audit Key
##############################################################

get_audit_key() {
    local action="$1"

    case "$action" in
        1)
            echo "identity"
            ;;
        2)
            echo "sudoers"
            ;;
        3)
            echo "process_exec"
            ;;
        4)
            echo "network_connect"
            ;;
        5)
            echo "cron_persist"
            ;;
        6)
            echo "identity"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

##############################################################
# Determine Search Terms
##############################################################

get_audit_search_term() {
    local action="$1"

    case "$action" in
        1)
            echo 'USER_ACCT|useradd|testattacker'
            ;;
        2)
            echo 'sudoers|backdoor|NOPASSWD'
            ;;
        3)
            echo 'EXECVE|suspicious_bin|/tmp'
            ;;
        4)
            echo 'EXECVE|connect|127\.0\.0\.1|4444'
            ;;
        5)
            echo 'cron|persistence_test|beacon\.sh'
            ;;
        6)
            echo 'shadow|/etc/shadow|PATH'
            ;;
        *)
            echo ''
            ;;
    esac
}

##############################################################
# Determine Expected Detail
##############################################################

get_expected_fields() {
    local action="$1"

    case "$action" in
        1)
            echo "user,uid,operation"
            ;;
        2)
            echo "path,operation,user"
            ;;
        3)
            echo "exe,path,command"
            ;;
        4)
            echo "destination,port,command"
            ;;
        5)
            echo "path,command,cron"
            ;;
        6)
            echo "path,operation,uid"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

##############################################################
# Determine Detail Level
##############################################################

get_detail_level() {
    local action="$1"
    local source="$2"
    local evidence="$3"

    if [[ -z "$evidence" ]]; then
        echo "missed"
        return
    fi

    case "$action:$source" in
        1:auditd)
            if grep -qE 'USER_ACCT|testattacker|uid=|acct=' <<< "$evidence"; then
                echo "full"
            else
                echo "partial"
            fi
            ;;

        2:auditd)
            if grep -qiE 'sudoers|backdoor|NOPASSWD' <<< "$evidence"; then
                echo "full"
            else
                echo "partial"
            fi
            ;;

        3:auditd)
            if grep -qiE 'EXECVE|suspicious_bin|/tmp' <<< "$evidence"; then
                echo "full"
            else
                echo "partial"
            fi
            ;;

        4:auditd)
            if grep -qiE '127\.0\.0\.1|4444|connect' <<< "$evidence"; then
                echo "full"
            else
                echo "partial"
            fi
            ;;

        5:auditd)
            if grep -qiE 'cron|persistence_test|beacon' <<< "$evidence"; then
                echo "full"
            else
                echo "partial"
            fi
            ;;

        6:auditd)
            if grep -qiE '/etc/shadow|shadow|PATH' <<< "$evidence"; then
                echo "full"
            else
                echo "partial"
            fi
            ;;

        *)
            echo "partial"
            ;;
    esac
}

##############################################################
# Results
##############################################################

RESULTS="[]"

TOTAL_ACTIONS=$(jq 'length' "$GROUND_TRUTH_FILE")

if [[ "$TOTAL_ACTIONS" -eq 0 ]]; then
    echo "[!] Ground truth contains no actions."
    exit 1
fi

echo "[*] Loading ground truth ($TOTAL_ACTIONS actions)..."
echo "[*] Searching telemetry..."

##############################################################
# Process Each Action
##############################################################

for ((i = 0; i < TOTAL_ACTIONS; i++)); do

    ACTION_NUMBER=$(
        jq -r ".[$i].action_number" "$GROUND_TRUTH_FILE"
    )

    DESCRIPTION=$(
        jq -r ".[$i].description" "$GROUND_TRUTH_FILE"
    )

    TIMESTAMP=$(
        jq -r ".[$i].timestamp" "$GROUND_TRUTH_FILE"
    )

    START_EPOCH=$(
        iso_to_epoch "$TIMESTAMP"
    )

    END_EPOCH=$((START_EPOCH + WINDOW_SECONDS))

    AUDIT_KEY=$(
        get_audit_key "$ACTION_NUMBER"
    )

    SEARCH_TERM=$(
        get_audit_search_term "$ACTION_NUMBER"
    )

    EXPECTED_FIELDS=$(
        get_expected_fields "$ACTION_NUMBER"
    )

    ##########################################################
    # Auditd
    ##########################################################

    AUDIT_EVIDENCE=$(
        search_audit \
            "$START_EPOCH" \
            "$END_EPOCH" \
            "$SEARCH_TERM"
    )

    ##########################################################
    # auth.log
    ##########################################################

    AUTH_EVIDENCE=""

    if [[ "$AUTH_AVAILABLE" -eq 1 ]]; then
        AUTH_EVIDENCE=$(
            search_text_log \
                "$AUTH_LOG" \
                "$TIMESTAMP" \
                "$ACTION_NUMBER"
        )
    fi

    ##########################################################
    # syslog
    ##########################################################

    SYSLOG_EVIDENCE=""

    if [[ "$SYSLOG_AVAILABLE" -eq 1 ]]; then
        SYSLOG_EVIDENCE=$(
            search_text_log \
                "$SYSLOG" \
                "$TIMESTAMP" \
                "$ACTION_NUMBER"
        )
    fi

    ##########################################################
    # Build Source Results
    ##########################################################

    ACTION_RESULTS="[]"

    # Auditd result.
    if [[ -n "$AUDIT_EVIDENCE" ]]; then

        DETAIL=$(
            get_detail_level \
                "$ACTION_NUMBER" \
                "auditd" \
                "$AUDIT_EVIDENCE"
        )

        ACTION_RESULTS=$(
            jq \
                --arg source "auditd" \
                --arg key "$AUDIT_KEY" \
                --arg detail "$DETAIL" \
                --arg fields "$EXPECTED_FIELDS" \
                --arg evidence "$AUDIT_EVIDENCE" \
                '. + [{
                    source: $source,
                    key: $key,
                    detail: $detail,
                    status: "captured",
                    key_fields: ($fields | split(",")),
                    evidence: $evidence
                }]' \
                <<< "$ACTION_RESULTS"
        )
    fi

    # auth.log result.
    if [[ -n "$AUTH_EVIDENCE" ]]; then

        DETAIL="partial"

        if [[ "$ACTION_NUMBER" -eq 1 ]]; then
            DETAIL="full"
        fi

        ACTION_RESULTS=$(
            jq \
                --arg source "auth.log" \
                --arg key "authentication" \
                --arg detail "$DETAIL" \
                --arg fields "$EXPECTED_FIELDS" \
                --arg evidence "$AUTH_EVIDENCE" \
                '. + [{
                    source: $source,
                    key: $key,
                    detail: $detail,
                    status: "captured",
                    key_fields: ($fields | split(",")),
                    evidence: $evidence
                }]' \
                <<< "$ACTION_RESULTS"
        )
    fi

    # syslog result.
    if [[ -n "$SYSLOG_EVIDENCE" ]]; then

        ACTION_RESULTS=$(
            jq \
                --arg source "syslog" \
                --arg key "system_activity" \
                --arg detail "partial" \
                --arg fields "$EXPECTED_FIELDS" \
                --arg evidence "$SYSLOG_EVIDENCE" \
                '. + [{
                    source: $source,
                    key: $key,
                    detail: $detail,
                    status: "captured",
                    key_fields: ($fields | split(",")),
                    evidence: $evidence
                }]' \
                <<< "$ACTION_RESULTS"
        )
    fi

    ##########################################################
    # Determine Overall Status
    ##########################################################

    SOURCE_COUNT=$(
        jq 'length' <<< "$ACTION_RESULTS"
    )

    if [[ "$SOURCE_COUNT" -gt 0 ]]; then
        STATUS="captured"
    else
        STATUS="missed"
    fi

    ##########################################################
    # Add Action To Matrix
    ##########################################################

    RESULTS=$(
        jq \
            --argjson action_number "$ACTION_NUMBER" \
            --arg description "$DESCRIPTION" \
            --arg timestamp "$TIMESTAMP" \
            --arg status "$STATUS" \
            --argjson sources "$ACTION_RESULTS" \
            '. + [{
                action_number: $action_number,
                description: $description,
                timestamp: $timestamp,
                status: $status,
                sources: $sources
            }]' \
            <<< "$RESULTS"
    )

done

##############################################################
# Summary
##############################################################

CAPTURED=$(
    jq '[.[] | select(.status == "captured")] | length' \
        <<< "$RESULTS"
)

MISSED=$(
    jq '[.[] | select(.status == "missed")] | length' \
        <<< "$RESULTS"
)

MULTI_SOURCE=$(
    jq '[.[] | select((.sources | length) > 1)] | length' \
        <<< "$RESULTS"
)

if [[ "$TOTAL_ACTIONS" -gt 0 ]]; then
    CAPTURE_PERCENT=$(
        awk \
            -v captured="$CAPTURED" \
            -v total="$TOTAL_ACTIONS" \
            'BEGIN {
                printf "%.1f", (captured / total) * 100
            }'
    )
else
    CAPTURE_PERCENT="0.0"
fi

##############################################################
# Final JSON Report
##############################################################

jq -n \
    --arg generated "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    --arg hostname "$(hostname -s)" \
    --argjson total_actions "$TOTAL_ACTIONS" \
    --argjson captured "$CAPTURED" \
    --argjson missed "$MISSED" \
    --argjson multi_source "$MULTI_SOURCE" \
    --arg capture_percentage "$CAPTURE_PERCENT" \
    --argjson actions "$RESULTS" \
    '{
        generated_at: $generated,
        hostname: $hostname,
        total_actions: $total_actions,
        captured_actions: $captured,
        missed_actions: $missed,
        capture_percentage: ($capture_percentage | tonumber),
        multi_source_actions: $multi_source,
        actions: $actions
    }' > "$OUTPUT_FILE"

##############################################################
# Human-Readable Output
##############################################################

printf '\n'
printf '%-28s %-15s %-17s %-10s %-12s\n' \
    "Action" "Source" "Key" "Detail" "Status"
printf '%-28s %-15s %-17s %-10s %-12s\n' \
    "------" "------" "---" "------" "------"

while IFS= read -r action_json; do

    ACTION_DESCRIPTION=$(
        jq -r '.description' <<< "$action_json"
    )

    jq -c '.sources[]' <<< "$action_json" |
    while IFS= read -r source_json; do

        SOURCE=$(
            jq -r '.source' <<< "$source_json"
        )

        KEY=$(
            jq -r '.key' <<< "$source_json"
        )

        DETAIL=$(
            jq -r '.detail' <<< "$source_json"
        )

        STATUS_VALUE=$(
            jq -r '.status' <<< "$source_json"
        )

        if [[ "$STATUS_VALUE" == "captured" ]]; then
            DISPLAY_STATUS="[CAPTURED]"
        else
            DISPLAY_STATUS="[MISSED]"
        fi

        printf '%-28s %-15s %-17s %-10s %-12s\n' \
            "$ACTION_DESCRIPTION" \
            "$SOURCE" \
            "$KEY" \
            "$DETAIL" \
            "$DISPLAY_STATUS"

        ACTION_DESCRIPTION=""
    done

done < <(jq -c '.[]' <<< "$RESULTS")

printf '\n'
printf 'Actions: %s | Captured: %s/%s (%s%%) | Multi-source: %s\n' \
    "$TOTAL_ACTIONS" \
    "$CAPTURED" \
    "$TOTAL_ACTIONS" \
    "$CAPTURE_PERCENT" \
    "$MULTI_SOURCE"

printf 'Report saved to: %s\n' "$OUTPUT_FILE"
```
