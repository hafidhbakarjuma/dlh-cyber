```bash
#!/bin/bash

# Name: 15-handoff_validation.sh
# Purpose: Validate the telemetry handoff package against quality gates.
# Author: Hafidh Juma
# Project: MedDefense Endpoint Telemetry Engineering

set -euo pipefail

##############################################################
# Configuration
##############################################################

HANDOFF_DIR="telemetry_handoff"

WINDOWS_EVENTS="${HANDOFF_DIR}/windows_events.json"
LINUX_EVENTS="${HANDOFF_DIR}/linux_events.json"
GROUND_TRUTH="${HANDOFF_DIR}/attack_ground_truth.json"

WINDOWS_MATRIX="windows_detection_matrix.json"
LINUX_MATRIX="linux_detection_matrix.json"

OUTPUT_FILE="handoff_validation.json"

MIN_WINDOWS_EVENTS=1000
MIN_LINUX_EVENTS=500
MIN_GROUND_TRUTH=10

##############################################################
# Counters
##############################################################

TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0

RESULTS="[]"

##############################################################
# Required Commands
##############################################################

if ! command -v jq >/dev/null 2>&1; then
    echo "[FAIL] Required command not found: jq"
    exit 1
fi

##############################################################
# Result Helpers
##############################################################

record_result() {
    local category="$1"
    local check="$2"
    local status="$3"
    local message="$4"

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    if [[ "$status" == "PASS" ]]; then
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    RESULTS="$(
        jq -c \
            --arg category "$category" \
            --arg check "$check" \
            --arg status "$status" \
            --arg message "$message" \
            '. + [{
                category: $category,
                check: $check,
                status: $status,
                message: $message
            }]' <<< "$RESULTS"
    )"

    echo "[$status] $message"
}

##############################################################
# File Helpers
##############################################################

file_size() {
    local file="$1"

    if stat -c '%s' "$file" >/dev/null 2>&1; then
        stat -c '%s' "$file"
    else
        stat -f '%z' "$file"
    fi
}

human_size() {
    local bytes="$1"

    if command -v numfmt >/dev/null 2>&1; then
        numfmt --to=iec --suffix=B "$bytes"
    else
        echo "${bytes} bytes"
    fi
}

check_file_exists() {
    local file="$1"
    local name="$2"

    if [[ -f "$file" ]]; then
        local size
        local formatted

        size="$(file_size "$file")"
        formatted="$(human_size "$size")"

        record_result \
            "File Existence" \
            "$name" \
            "PASS" \
            "${name} exists (${formatted})"
    else
        record_result \
            "File Existence" \
            "$name" \
            "FAIL" \
            "${name} is missing"
    fi
}

##############################################################
# JSON Helpers
##############################################################

json_is_valid() {
    local file="$1"

    jq empty "$file" >/dev/null 2>&1
}

get_events() {
    local file="$1"

    jq -c '
        if type == "array" then .
        elif (.events | type) == "array" then .events
        else []
        end
    ' "$file"
}

get_actions() {
    local file="$1"

    jq -c '
        if type == "array" then .
        elif (.actions | type) == "array" then .actions
        else []
        end
    ' "$file"
}

##############################################################
# Start
##############################################################

echo "[*] Validating telemetry_handoff/ ..."

##############################################################
# 1. File Existence
##############################################################

echo "=== File Existence ==="

check_file_exists "$WINDOWS_EVENTS" "windows_events.json"
check_file_exists "$LINUX_EVENTS" "linux_events.json"
check_file_exists "$GROUND_TRUTH" "attack_ground_truth.json"

##############################################################
# 2. JSON Validity
##############################################################

echo "=== JSON Validity ==="

JSON_FILES=(
    "$WINDOWS_EVENTS"
    "$LINUX_EVENTS"
    "$GROUND_TRUTH"
)

for file in "${JSON_FILES[@]}"; do
    name="$(basename "$file")"

    if [[ ! -f "$file" ]]; then
        record_result \
            "JSON Validity" \
            "$name" \
            "FAIL" \
            "${name}: file missing"
        continue
    fi

    if json_is_valid "$file"; then

        if [[ "$file" == "$GROUND_TRUTH" ]]; then
            count="$(get_actions "$file" | jq 'length')"
        else
            count="$(get_events "$file" | jq 'length')"
        fi

        record_result \
            "JSON Validity" \
            "$name" \
            "PASS" \
            "${name}: valid JSON, ${count} objects"
    else
        record_result \
            "JSON Validity" \
            "$name" \
            "FAIL" \
            "${name}: invalid JSON"
    fi
done

##############################################################
# Stop Data Processing If Required Files Are Missing/Invalid
##############################################################

if [[ ! -f "$WINDOWS_EVENTS" ||
      ! -f "$LINUX_EVENTS" ||
      ! -f "$GROUND_TRUTH" ]]; then

    echo "[!] Required handoff files are missing."
else

    if ! json_is_valid "$WINDOWS_EVENTS" ||
       ! json_is_valid "$LINUX_EVENTS" ||
       ! json_is_valid "$GROUND_TRUTH"; then

        echo "[!] One or more handoff files contain invalid JSON."
    fi
fi

##############################################################
# 3. Required Fields
##############################################################

echo "=== Required Fields ==="

REQUIRED_FIELDS_RESULT="$(
    jq -s '
        {
            windows: (
                .[0]
                | if type == "array" then .
                  elif (.events | type) == "array" then .events
                  else []
                  end
            ),
            linux: (
                .[1]
                | if type == "array" then .
                  elif (.events | type) == "array" then .events
                  else []
                  end
            )
        }
        |
        {
            windows_missing: [
                .windows[]
                | select(
                    (.timestamp? == null)
                    or (.hostname? == null)
                    or (.source_type? == null)
                    or (.event_category? == null)
                )
            ],
            linux_missing: [
                .linux[]
                | select(
                    (.timestamp? == null)
                    or (.hostname? == null)
                    or (.source_type? == null)
                    or (.event_category? == null)
                )
            ]
        }
    '
    "$WINDOWS_EVENTS" "$LINUX_EVENTS"
)"

WINDOWS_MISSING_FIELDS="$(
    jq '.windows_missing | length' <<< "$REQUIRED_FIELDS_RESULT"
)"

LINUX_MISSING_FIELDS="$(
    jq '.linux_missing | length' <<< "$REQUIRED_FIELDS_RESULT"
)"

TOTAL_MISSING_FIELDS=$(
    printf '%s\n' "$WINDOWS_MISSING_FIELDS" "$LINUX_MISSING_FIELDS" |
    awk '{sum += $1} END {print sum}'
)

if [[ "$TOTAL_MISSING_FIELDS" -eq 0 ]]; then
    record_result \
        "Required Fields" \
        "Event fields" \
        "PASS" \
        "All events have timestamp, hostname, source_type, event_category"
else
    record_result \
        "Required Fields" \
        "Event fields" \
        "FAIL" \
        "${TOTAL_MISSING_FIELDS} events are missing one or more required fields"
fi

##############################################################
# 4. Minimum Event Counts
##############################################################

echo "=== Minimum Event Counts ==="

WINDOWS_COUNT="$(
    get_events "$WINDOWS_EVENTS" | jq 'length'
)"

LINUX_COUNT="$(
    get_events "$LINUX_EVENTS" | jq 'length'
)"

GROUND_TRUTH_COUNT="$(
    get_actions "$GROUND_TRUTH" | jq 'length'
)"

if (( WINDOWS_COUNT >= MIN_WINDOWS_EVENTS )); then
    record_result \
        "Minimum Event Counts" \
        "Windows" \
        "PASS" \
        "Windows: ${WINDOWS_COUNT} >= ${MIN_WINDOWS_EVENTS}"
else
    record_result \
        "Minimum Event Counts" \
        "Windows" \
        "FAIL" \
        "Windows: ${WINDOWS_COUNT} < ${MIN_WINDOWS_EVENTS}"
fi

if (( LINUX_COUNT >= MIN_LINUX_EVENTS )); then
    record_result \
        "Minimum Event Counts" \
        "Linux" \
        "PASS" \
        "Linux: ${LINUX_COUNT} >= ${MIN_LINUX_EVENTS}"
else
    record_result \
        "Minimum Event Counts" \
        "Linux" \
        "FAIL" \
        "Linux: ${LINUX_COUNT} < ${MIN_LINUX_EVENTS}"
fi

if (( GROUND_TRUTH_COUNT >= MIN_GROUND_TRUTH )); then
    record_result \
        "Minimum Event Counts" \
        "Ground truth" \
        "PASS" \
        "Ground truth: ${GROUND_TRUTH_COUNT} >= ${MIN_GROUND_TRUTH}"
else
    record_result \
        "Minimum Event Counts" \
        "Ground truth" \
        "FAIL" \
        "Ground truth: ${GROUND_TRUTH_COUNT} < ${MIN_GROUND_TRUTH}"
fi

##############################################################
# 5. Timestamp Validation
##############################################################

echo "=== Timestamp Consistency ==="

CURRENT_EPOCH="$(date -u +%s)"

validate_timestamps() {
    local file="$1"
    local data_type="$2"

    jq -r --arg type "$data_type" '
        if $type == "events" then
            if type == "array" then .
            else (.events // [])
            end
            | .[]
            | .timestamp // empty
        else
            if type == "array" then .
            else (.actions // [])
            end
            | .[]
            | .timestamp // empty
        end
    ' "$file"
}

WINDOWS_TIMESTAMPS="$(validate_timestamps "$WINDOWS_EVENTS" "events")"
LINUX_TIMESTAMPS="$(validate_timestamps "$LINUX_EVENTS" "events")"
GROUND_TRUTH_TIMESTAMPS="$(validate_timestamps "$GROUND_TRUTH" "actions")"

TIMESTAMP_FAILURES=0
FUTURE_FAILURES=0

check_timestamp_stream() {
    local stream="$1"

    while IFS= read -r timestamp; do
        [[ -z "$timestamp" ]] && continue

        if ! parsed="$(date -u -d "$timestamp" +%s 2>/dev/null)"; then
            TIMESTAMP_FAILURES=$((TIMESTAMP_FAILURES + 1))
            continue
        fi

        if (( parsed > CURRENT_EPOCH )); then
            FUTURE_FAILURES=$((FUTURE_FAILURES + 1))
        fi
    done <<< "$stream"
}

check_timestamp_stream "$WINDOWS_TIMESTAMPS"
check_timestamp_stream "$LINUX_TIMESTAMPS"
check_timestamp_stream "$GROUND_TRUTH_TIMESTAMPS"

if (( TIMESTAMP_FAILURES == 0 )); then
    record_result \
        "Timestamp Consistency" \
        "ISO 8601 timestamps" \
        "PASS" \
        "All timestamps valid ISO 8601"
else
    record_result \
        "Timestamp Consistency" \
        "ISO 8601 timestamps" \
        "FAIL" \
        "${TIMESTAMP_FAILURES} timestamps are invalid"
fi

if (( FUTURE_FAILURES == 0 )); then
    record_result \
        "Timestamp Consistency" \
        "Future timestamps" \
        "PASS" \
        "No future timestamps"
else
    record_result \
        "Timestamp Consistency" \
        "Future timestamps" \
        "FAIL" \
        "${FUTURE_FAILURES} timestamps are in the future"
fi

##############################################################
# Timestamp Range Helpers
##############################################################

get_min_timestamp() {
    local stream="$1"

    if [[ -z "$stream" ]]; then
        echo ""
        return
    fi

    printf '%s\n' "$stream" |
        while IFS= read -r timestamp; do
            date -u -d "$timestamp" +%s 2>/dev/null || true
        done |
        sort -n |
        head -n 1
}

get_max_timestamp() {
    local stream="$1"

    if [[ -z "$stream" ]]; then
        echo ""
        return
    fi

    printf '%s\n' "$stream" |
        while IFS= read -r timestamp; do
            date -u -d "$timestamp" +%s 2>/dev/null || true
        done |
        sort -n |
        tail -n 1
}

WINDOWS_MIN_EPOCH="$(get_min_timestamp "$WINDOWS_TIMESTAMPS")"
WINDOWS_MAX_EPOCH="$(get_max_timestamp "$WINDOWS_TIMESTAMPS")"

LINUX_MIN_EPOCH="$(get_min_timestamp "$LINUX_TIMESTAMPS")"
LINUX_MAX_EPOCH="$(get_max_timestamp "$LINUX_TIMESTAMPS")"

if [[ -n "$WINDOWS_MIN_EPOCH" && -n "$WINDOWS_MAX_EPOCH" ]]; then
    WINDOWS_MIN_ISO="$(date -u -d "@${WINDOWS_MIN_EPOCH}" '+%Y-%m-%dT%H:%M:%SZ')"
    WINDOWS_MAX_ISO="$(date -u -d "@${WINDOWS_MAX_EPOCH}" '+%Y-%m-%dT%H:%M:%SZ')"

    record_result \
        "Timestamp Consistency" \
        "Windows range" \
        "PASS" \
        "Windows range: ${WINDOWS_MIN_ISO} to ${WINDOWS_MAX_ISO}"
else
    WINDOWS_MIN_ISO=""
    WINDOWS_MAX_ISO=""

    record_result \
        "Timestamp Consistency" \
        "Windows range" \
        "FAIL" \
        "Unable to determine Windows timestamp range"
fi

if [[ -n "$LINUX_MIN_EPOCH" && -n "$LINUX_MAX_EPOCH" ]]; then
    LINUX_MIN_ISO="$(date -u -d "@${LINUX_MIN_EPOCH}" '+%Y-%m-%dT%H:%M:%SZ')"
    LINUX_MAX_ISO="$(date -u -d "@${LINUX_MAX_EPOCH}" '+%Y-%m-%dT%H:%M:%SZ')"

    record_result \
        "Timestamp Consistency" \
        "Linux range" \
        "PASS" \
        "Linux range: ${LINUX_MIN_ISO} to ${LINUX_MAX_ISO}"
else
    LINUX_MIN_ISO=""
    LINUX_MAX_ISO=""

    record_result \
        "Timestamp Consistency" \
        "Linux range" \
        "FAIL" \
        "Unable to determine Linux timestamp range"
fi

##############################################################
# 6. Cross-Platform Alignment
##############################################################

echo "=== Cross-Platform Alignment ==="

if [[ -n "$WINDOWS_MIN_EPOCH" &&
      -n "$WINDOWS_MAX_EPOCH" &&
      -n "$LINUX_MIN_EPOCH" &&
      -n "$LINUX_MAX_EPOCH" ]]; then

    OVERLAP_START="$WINDOWS_MIN_EPOCH"

    if (( LINUX_MIN_EPOCH > OVERLAP_START )); then
        OVERLAP_START="$LINUX_MIN_EPOCH"
    fi

    OVERLAP_END="$WINDOWS_MAX_EPOCH"

    if (( LINUX_MAX_EPOCH < OVERLAP_END )); then
        OVERLAP_END="$LINUX_MAX_EPOCH"
    fi

    if (( OVERLAP_START <= OVERLAP_END )); then
        OVERLAP_SECONDS=$((OVERLAP_END - OVERLAP_START))
        OVERLAP_HOURS="$(awk -v seconds="$OVERLAP_SECONDS" \
            'BEGIN { printf "%.1f", seconds / 3600 }')"

        record_result \
            "Cross-Platform Alignment" \
            "Timestamp range overlap" \
            "PASS" \
            "Windows and Linux time ranges overlap (${OVERLAP_HOURS} hours shared)"
    else
        record_result \
            "Cross-Platform Alignment" \
            "Timestamp range overlap" \
            "FAIL" \
            "Windows and Linux timestamp ranges do not overlap"
    fi
else
    record_result \
        "Cross-Platform Alignment" \
        "Timestamp range overlap" \
        "FAIL" \
        "Unable to compare platform timestamp ranges"
fi

##############################################################
# 7. Ground Truth Completeness
##############################################################

echo "=== Ground Truth Completeness ==="

MATRICES_AVAILABLE=true

if [[ ! -f "$WINDOWS_MATRIX" ]]; then
    MATRICES_AVAILABLE=false
fi

if [[ ! -f "$LINUX_MATRIX" ]]; then
    MATRICES_AVAILABLE=false
fi

if [[ "$MATRICES_AVAILABLE" == true ]] &&
   json_is_valid "$WINDOWS_MATRIX" &&
   json_is_valid "$LINUX_MATRIX"; then

    DETECTION_MATRIX="$(
        jq -s -c '
            map(
                if type == "array" then .
                elif (.actions | type) == "array" then .actions
                elif (.detection_matrix | type) == "array" then .detection_matrix
                elif (.results | type) == "array" then .results
                elif (.detections | type) == "array" then .detections
                else []
                end
            )
            | add
        ' "$WINDOWS_MATRIX" "$LINUX_MATRIX"
    )"

    MATRIX_ENTRY_COUNT="$(jq 'length' <<< "$DETECTION_MATRIX")"

    GROUND_TRUTH_ACTIONS="$(
        get_actions "$GROUND_TRUTH"
    )"

    MATCHED_ACTIONS=0

    while IFS= read -r action; do
        [[ -z "$action" ]] && continue

        ACTION_ID="$(
            jq -r '
                .id
                // .action_id
                // .action
                // .technique
                // .mitre_attack_technique
                // empty
            ' <<< "$action"
        )"

        ACTION_TECHNIQUE="$(
            jq -r '
                .mitre_attack_technique
                // .mitre_technique
                // .technique
                // empty
            ' <<< "$action"
        )"

        MATCH_FOUND="$(
            jq --arg id "$ACTION_ID" \
               --arg technique "$ACTION_TECHNIQUE" '
                [
                    .[]
                    | select(
                        (
                            ($id != "")
                            and
                            (
                                (.id? | tostring) == $id
                                or (.action_id? | tostring) == $id
                                or (.action? | tostring) == $id
                            )
                        )
                        or
                        (
                            ($technique != "")
                            and
                            (
                                (.mitre_attack_technique? | tostring) == $technique
                                or (.mitre_technique? | tostring) == $technique
                                or (.technique? | tostring) == $technique
                            )
                        )
                    )
                ]
                | length
            ' <<< "$DETECTION_MATRIX"
        )"

        if (( MATCH_FOUND > 0 )); then
            MATCHED_ACTIONS=$((MATCHED_ACTIONS + 1))
        fi

    done < <(jq -c '.[]' <<< "$GROUND_TRUTH_ACTIONS")

    if (( MATCHED_ACTIONS == GROUND_TRUTH_COUNT )); then
        record_result \
            "Ground Truth Completeness" \
            "Detection matrix coverage" \
            "PASS" \
            "${MATCHED_ACTIONS}/${GROUND_TRUTH_COUNT} actions have detection matrix entries"
    else
        record_result \
            "Ground Truth Completeness" \
            "Detection matrix coverage" \
            "FAIL" \
            "${MATCHED_ACTIONS}/${GROUND_TRUTH_COUNT} actions have detection matrix entries"
    fi

else
    record_result \
        "Ground Truth Completeness" \
        "Detection matrix coverage" \
        "FAIL" \
        "Detection matrices are missing or invalid"
fi

##############################################################
# Final Verdict
##############################################################

if (( FAILED_CHECKS == 0 )); then
    VERDICT="PASS"
    VERDICT_MESSAGE="Handoff package is ready for Module 3."
else
    VERDICT="FAIL"
    VERDICT_MESSAGE="Handoff package requires remediation before Module 3."
fi

##############################################################
# Build Validation Report
##############################################################

jq -n \
    --arg generated_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    --arg verdict "$VERDICT" \
    --arg verdict_message "$VERDICT_MESSAGE" \
    --argjson total_checks "$TOTAL_CHECKS" \
    --argjson passed_checks "$PASSED_CHECKS" \
    --argjson failed_checks "$FAILED_CHECKS" \
    --argjson results "$RESULTS" \
    --argjson windows_count "$WINDOWS_COUNT" \
    --argjson linux_count "$LINUX_COUNT" \
    --argjson ground_truth_count "$GROUND_TRUTH_COUNT" \
    --arg windows_min "$WINDOWS_MIN_ISO" \
    --arg windows_max "$WINDOWS_MAX_ISO" \
    --arg linux_min "$LINUX_MIN_ISO" \
    --arg linux_max "$LINUX_MAX_ISO" \
    '
    {
        generated_at: $generated_at,

        validation_type: "Telemetry Handoff Package Validation",

        verdict: $verdict,

        summary: {
            total_checks: $total_checks,
            passed_checks: $passed_checks,
            failed_checks: $failed_checks
        },

        handoff_package: {
            directory: "telemetry_handoff",

            event_counts: {
                windows: $windows_count,
                linux: $linux_count,
                ground_truth_actions: $ground_truth_count
            },

            timestamp_ranges: {
                windows: {
                    earliest: $windows_min,
                    latest: $windows_max
                },
                linux: {
                    earliest: $linux_min,
                    latest: $linux_max
                }
            }
        },

        checks: $results,

        final_message: $verdict_message
    }
    ' > "$OUTPUT_FILE"

##############################################################
# Validate Output
##############################################################

if ! jq empty "$OUTPUT_FILE" >/dev/null 2>&1; then
    echo "[FAIL] Failed to create valid ${OUTPUT_FILE}"
    exit 1
fi

##############################################################
# Final Output
##############################################################

echo "VERDICT: ${VERDICT} (${PASSED_CHECKS}/${TOTAL_CHECKS} checks)"

echo "${VERDICT_MESSAGE}"

echo "Report saved to: ${OUTPUT_FILE}"

if (( FAILED_CHECKS > 0 )); then
    exit 1
fi

exit 0
```
