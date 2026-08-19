#!/bin/bash
# Exit codes: 0 = all checks passed, 1 = one or more controls failed or errored, 2 = environment error
set -euo pipefail

TARGET_JSON="capstone/target_state.json"
REPORT_DIR="capstone/exec"
REPORT_JSON="$REPORT_DIR/validation_report.json"
LOG_PATH="$REPORT_DIR/validate_all.log"

mkdir -p "$REPORT_DIR"
> "$LOG_PATH"

echo "[*] Starting End-to-End Validation Suite (8-validate_all.sh)..." | tee -a "$LOG_PATH"

if [[ ! -f "$TARGET_JSON" ]]; then
    echo "[-] Error: Target state configuration not found at $TARGET_JSON" | tee -a "$LOG_PATH"
    exit 2
fi

# Ensure jq is available for robust JSON parsing
if ! command -v jq &> /dev/null; then
    echo "[-] Error: jq utility is required but not installed." | tee -a "$LOG_PATH"
    exit 2
fi

# Initialize summary counters and arrays
TOTAL_CONTROLS=0
PASS_COUNT=0
FAIL_COUNT=0
ERROR_COUNT=0

# Associative arrays for family aggregations
declare -A FAM_TOTAL
declare -A FAM_PASS
declare -A FAM_FAIL
declare -A FAM_ERROR

RESULTS_JSON_ARRAY="[]"

# Read controls array length from target_state.json
CONTROL_COUNT=$(jq '.controls | length' "$TARGET_JSON")

echo "[*] Evaluating $CONTROL_COUNT controls from $TARGET_JSON..." | tee -a "$LOG_PATH"

for ((i=0; i<CONTROL_COUNT; i++)); do
    CONTROL=$(jq ".controls[$i]" "$TARGET_JSON")
    CID=$(echo "$CONTROL" | jq -r '.id')
    FAMILY=$(echo "$CID" | cut -d'-' -f1)
    CHECK_TYPE=$(echo "$CONTROL" | jq -r '.check_type')
    CHECK_TARGET=$(echo "$CONTROL" | jq -r '.check_target // empty')
    EXPECTED_VAL=$(echo "$CONTROL" | jq -r '.expected_value // empty')
    FIELD=$(echo "$CONTROL" | jq -r '.field // empty')

    TOTAL_CONTROLS=$((TOTAL_CONTROLS + 1))
    FAM_TOTAL["$FAMILY"]=$(( ${FAM_TOTAL["$FAMILY"]:-0} + 1 ))

    STATUS="pass"
    EVIDENCE=""

    case "$CHECK_TYPE" in
        "file_exists")
            if [[ -f "$CHECK_TARGET" || -d "$CHECK_TARGET" ]]; then
                STATUS="pass"
                EVIDENCE="Path exists: $CHECK_TARGET"
            else
                STATUS="fail"
                EVIDENCE="Path missing: $CHECK_TARGET"
            fi
            ;;
        "json_field_equals")
            if [[ -f "$CHECK_TARGET" ]]; then
                ACTUAL_VAL=$(jq -r ".$FIELD // empty" "$CHECK_TARGET" 2>/dev/null || echo "")
                if [[ "$ACTUAL_VAL" == "$EXPECTED_VAL" ]]; then
                    STATUS="pass"
                    EVIDENCE="JSON field .$FIELD equals '$EXPECTED_VAL'"
                else
                    STATUS="fail"
                    EVIDENCE="JSON field .$FIELD value '$ACTUAL_VAL' does not match expected '$EXPECTED_VAL'"
                fi
            else
                STATUS="error"
                EVIDENCE="Target JSON file not found: $CHECK_TARGET"
            fi
            ;;
        "json_field_gte")
            if [[ -f "$CHECK_TARGET" ]]; then
                ACTUAL_VAL=$(jq -r ".$FIELD // 0" "$CHECK_TARGET" 2>/dev/null || echo "0")
                # Compare using awk for floating-point support
                IS_GTE=$(awk -v act="$ACTUAL_VAL" -v exp="$EXPECTED_VAL" 'BEGIN {print (act >= exp) ? "1" : "0"}')
                if [[ "$IS_GTE" == "1" ]]; then
                    STATUS="pass"
                    EVIDENCE="JSON field .$FIELD ($ACTUAL_VAL) >= expected ($EXPECTED_VAL)"
                else
                    STATUS="fail"
                    EVIDENCE="JSON field .$FIELD ($ACTUAL_VAL) < expected ($EXPECTED_VAL)"
                fi
            else
                STATUS="error"
                EVIDENCE="Target JSON file not found: $CHECK_TARGET"
            fi
            ;;
        "command_exit_zero")
            set +e
            eval "$CHECK_TARGET" >> "$LOG_PATH" 2>&1
            CMD_EXIT=$?
            set -e
            if [[ $CMD_EXIT -eq 0 ]]; then
                STATUS="pass"
                EVIDENCE="Command exited 0: $CHECK_TARGET"
            else
                STATUS="fail"
                EVIDENCE="Command exited non-zero ($CMD_EXIT): $CHECK_TARGET"
            fi
            ;;
        "grep_match")
            if [[ -f "$CHECK_TARGET" ]]; then
                if grep -q -E "$EXPECTED_VAL" "$CHECK_TARGET"; then
                    STATUS="pass"
                    EVIDENCE="Found regex match '$EXPECTED_VAL' in $CHECK_TARGET"
                else
                    STATUS="fail"
                    EVIDENCE="Regex match '$EXPECTED_VAL' not found in $CHECK_TARGET"
                fi
            else
                STATUS="error"
                EVIDENCE="Target file for grep not found: $CHECK_TARGET"
            fi
            ;;
        *)
            STATUS="error"
            EVIDENCE="Unknown check_type: $CHECK_TYPE"
            ;;
    esac

    # Update counters based on verdict
    case "$STATUS" in
        "pass")
            PASS_COUNT=$((PASS_COUNT + 1))
            FAM_PASS["$FAMILY"]=$(( ${FAM_PASS["$FAMILY"]:-0} + 1 ))
            ;;
        "fail")
            FAIL_COUNT=$((FAIL_COUNT + 1))
            FAM_FAIL["$FAMILY"]=$(( ${FAM_FAIL["$FAMILY"]:-0} + 1 ))
            ;;
        *)
            ERROR_COUNT=$((ERROR_COUNT + 1))
            FAM_ERROR["$FAMILY"]=$(( ${FAM_ERROR["$FAMILY"]:-0} + 1 ))
            ;;
    esac

    echo "[*] Control $CID [$CHECK_TYPE] -> $STATUS ($EVIDENCE)" | tee -a "$LOG_PATH"
done

# Calculate pass percentage
PASS_PERCENT=0
if [[ $TOTAL_CONTROLS -gt 0 ]]; then
    PASS_PERCENT=$(awk -v p="$PASS_COUNT" -v t="$TOTAL_CONTROLS" 'BEGIN {printf "%.2f", (p / t) * 100}')
fi

# Print clean table to stdout showing one row per control family with family totals
echo ""
echo "========================================================================"
echo "                   END-TO-END VALIDATION FAMILY SUMMARY                 "
echo "========================================================================"
printf "%-15s | %-10s | %-10s | %-10s | %-10s\n" "Family" "Total" "Passed" "Failed" "Errors"
echo "------------------------------------------------------------------------"

for family in "${!FAM_TOTAL[@]}"; do
    tot=${FAM_TOTAL["$family"]:-0}
    pas=${FAM_PASS["$family"]:-0}
    fai=${FAM_FAIL["$family"]:-0}
    err=${FAM_ERROR["$family"]:-0}
    printf "%-15s | %-10d | %-10d | %-10d | %-10d\n" "$family" "$tot" "$pas" "$fai" "$err"
done
echo "========================================================================"
echo " Aggregates -> Total: $TOTAL_CONTROLS | Pass: $PASS_COUNT | Fail: $FAIL_COUNT | Error: $ERROR_COUNT | Pass Rate: ${PASS_PERCENT}%"
echo "========================================================================"

# Generate machine-readable JSON report
cat <<EOF > "$REPORT_JSON"
{
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "hostname": "$(hostname)",
  "total_controls": $TOTAL_CONTROLS,
  "pass_count": $PASS_COUNT,
  "fail_count": $FAIL_COUNT,
  "error_count": $ERROR_COUNT,
  "pass_percentage": $PASS_PERCENT,
  "status": "$([[ $FAIL_COUNT -eq 0 && $ERROR_COUNT -eq 0 ]] && echo "ready" || echo "not_ready")"
}
EOF

echo "[+] Validation report persisted to $REPORT_JSON" | tee -a "$LOG_PATH"

# Exit 0 if fail_count == 0 AND error_count == 0. Otherwise exit 1.
if [[ $FAIL_COUNT -eq 0 && $ERROR_COUNT -eq 0 ]]; then
    echo "[+] Handoff Readiness Verification: READY (All controls passed)." | tee -a "$LOG_PATH"
    exit 0
else
    echo "[-] Handoff Readiness Verification: NOT READY ($FAIL_COUNT failures, $ERROR_COUNT errors detected)." | tee -a "$LOG_PATH"
    exit 1
fi
