```bash
#!/bin/bash

# Name: 14-coverage_assessment.sh
# Purpose: Produce a cross-platform Linux and Windows telemetry coverage assessment.
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

WINDOWS_QUALITY="windows_telemetry_quality.json"
LINUX_QUALITY="linux_telemetry_quality.json"

SYSMON_MATRIX="sysmon_coverage_matrix.json"

OUTPUT_FILE="telemetry_coverage_assessment.json"

##############################################################
# Required Commands
##############################################################

for command in jq; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "[!] Required command not found: $command"
        exit 1
    fi
done

##############################################################
# Required Files
##############################################################

check_file() {
    local file="$1"

    if [[ ! -f "$file" ]]; then
        echo "[!] Required file not found: $file"
        exit 1
    fi

    if [[ ! -s "$file" ]]; then
        echo "[!] Required file is empty: $file"
        exit 1
    fi

    if ! jq empty "$file" >/dev/null 2>&1; then
        echo "[!] Invalid JSON: $file"
        exit 1
    fi
}

echo "[*] Loading telemetry handoff package..."

for file in \
    "$WINDOWS_EVENTS" \
    "$LINUX_EVENTS" \
    "$GROUND_TRUTH" \
    "$WINDOWS_MATRIX" \
    "$LINUX_MATRIX" \
    "$WINDOWS_QUALITY" \
    "$LINUX_QUALITY" \
    "$SYSMON_MATRIX"; do

    check_file "$file"
done

##############################################################
# Event Counts
##############################################################

WINDOWS_COUNT="$(jq 'length' "$WINDOWS_EVENTS")"
LINUX_COUNT="$(jq 'length' "$LINUX_EVENTS")"
GROUND_TRUTH_COUNT="$(jq 'length' "$GROUND_TRUTH")"

TOTAL_EVENTS=$((WINDOWS_COUNT + LINUX_COUNT))

echo "Windows events: ${WINDOWS_COUNT}"
echo "Linux events: ${LINUX_COUNT}"
echo "Ground truth actions: ${GROUND_TRUTH_COUNT}"

##############################################################
# Source Type Distribution
##############################################################

WINDOWS_SOURCE_COUNTS="$(
    jq '
        group_by(.source_type // "unknown")
        | map({
            source_type: (.[0].source_type // "unknown"),
            count: length
        })
    ' "$WINDOWS_EVENTS"
)"

LINUX_SOURCE_COUNTS="$(
    jq '
        group_by(.source_type // "unknown")
        | map({
            source_type: (.[0].source_type // "unknown"),
            count: length
        })
    ' "$LINUX_EVENTS"
)"

##############################################################
# Event Category Distribution
##############################################################

WINDOWS_CATEGORY_COUNTS="$(
    jq '
        group_by(.event_category // "unknown")
        | map({
            event_category: (.[0].event_category // "unknown"),
            count: length
        })
    ' "$WINDOWS_EVENTS"
)"

LINUX_CATEGORY_COUNTS="$(
    jq '
        group_by(.event_category // "unknown")
        | map({
            event_category: (.[0].event_category // "unknown"),
            count: length
        })
    ' "$LINUX_EVENTS"
)"

##############################################################
# Detection Matrix Helpers
##############################################################

get_matrix_total() {
    local file="$1"

    jq '
        if type == "array" then
            length
        elif .actions then
            (.actions | length)
        elif .detection_matrix then
            (.detection_matrix | length)
        else
            0
        end
    ' "$file"
}

get_captured_count() {
    local file="$1"

    jq '
        if type == "array" then
            [
                .[] |
                select(
                    (.status // "" | ascii_downcase) == "captured"
                    or
                    (.detected // false) == true
                )
            ] | length

        elif .actions then
            [
                .actions[] |
                select(
                    (.status // "" | ascii_downcase) == "captured"
                    or
                    (.detected // false) == true
                )
            ] | length

        elif .detection_matrix then
            [
                .detection_matrix[] |
                select(
                    (.status // "" | ascii_downcase) == "captured"
                    or
                    (.detected // false) == true
                )
            ] | length

        else
            0
        end
    ' "$file"
}

get_missed_count() {
    local file="$1"

    jq '
        if type == "array" then
            [
                .[] |
                select(
                    (.status // "" | ascii_downcase) == "missed"
                    or
                    (.detected // true) == false
                )
            ] | length

        elif .actions then
            [
                .actions[] |
                select(
                    (.status // "" | ascii_downcase) == "missed"
                    or
                    (.detected // true) == false
                )
            ] | length

        elif .detection_matrix then
            [
                .detection_matrix[] |
                select(
                    (.status // "" | ascii_downcase) == "missed"
                    or
                    (.detected // true) == false
                )
            ] | length

        else
            0
        end
    ' "$file"
}

get_multisource_count() {
    local file="$1"

    jq '
        if type == "array" then
            [
                .[] |
                select(
                    ((.source_count // 0) > 1)
                    or
                    ((.sources // []) | length > 1)
                )
            ] | length

        elif .actions then
            [
                .actions[] |
                select(
                    ((.source_count // 0) > 1)
                    or
                    ((.sources // []) | length > 1)
                )
            ] | length

        elif .detection_matrix then
            [
                .detection_matrix[] |
                select(
                    ((.source_count // 0) > 1)
                    or
                    ((.sources // []) | length > 1)
                )
            ] | length

        else
            0
        end
    ' "$file"
}

##############################################################
# Windows Detection Summary
##############################################################

WINDOWS_DETECTION_TOTAL="$(get_matrix_total "$WINDOWS_MATRIX")"
WINDOWS_CAPTURED="$(get_captured_count "$WINDOWS_MATRIX")"
WINDOWS_MISSED="$(get_missed_count "$WINDOWS_MATRIX")"
WINDOWS_MULTI="$(get_multisource_count "$WINDOWS_MATRIX")"

##############################################################
# Linux Detection Summary
##############################################################

LINUX_DETECTION_TOTAL="$(get_matrix_total "$LINUX_MATRIX")"
LINUX_CAPTURED="$(get_captured_count "$LINUX_MATRIX")"
LINUX_MISSED="$(get_missed_count "$LINUX_MATRIX")"
LINUX_MULTI="$(get_multisource_count "$LINUX_MATRIX")"

DETECTION_TOTAL=$((WINDOWS_DETECTION_TOTAL + LINUX_DETECTION_TOTAL))
CAPTURED_TOTAL=$((WINDOWS_CAPTURED + LINUX_CAPTURED))
MISSED_TOTAL=$((WINDOWS_MISSED + LINUX_MISSED))
MULTISOURCE_TOTAL=$((WINDOWS_MULTI + LINUX_MULTI))

echo "Detection matrix: ${CAPTURED_TOTAL}/${DETECTION_TOTAL} captured"

##############################################################
# ATT&CK Coverage
##############################################################

COVERED_TECHNIQUES="$(
    jq -s '
        [
            .[] |
            if type == "array" then .[]
            elif .actions then .actions[]
            elif .detection_matrix then .detection_matrix[]
            else empty
            end
        ]
        |
        map(
            select(
                (.status // "" | ascii_downcase) == "captured"
                or
                (.detected // false) == true
            )
            |
            .mitre_attack_technique
            // .mitre_technique
            // .technique
            // empty
        )
        |
        unique
    ' "$WINDOWS_MATRIX" "$LINUX_MATRIX"
)"

PARTIAL_TECHNIQUES="$(
    jq -s '
        [
            .[] |
            if type == "array" then .[]
            elif .actions then .actions[]
            elif .detection_matrix then .detection_matrix[]
            else empty
            end
        ]
        |
        map(
            select(
                ((.detail // "" | ascii_downcase) == "partial")
                or
                ((.status // "" | ascii_downcase) == "partial")
            )
            |
            .mitre_attack_technique
            // .mitre_technique
            // .technique
            // empty
        )
        |
        unique
    ' "$WINDOWS_MATRIX" "$LINUX_MATRIX"
)"

BLIND_TECHNIQUES="$(
    jq -s '
        [
            .[] |
            if type == "array" then .[]
            elif .actions then .actions[]
            elif .detection_matrix then .detection_matrix[]
            else empty
            end
        ]
        |
        map(
            select(
                ((.status // "" | ascii_downcase) == "missed")
                or
                ((.detected // true) == false)
            )
            |
            .mitre_attack_technique
            // .mitre_technique
            // .technique
            // empty
        )
        |
        unique
    ' "$WINDOWS_MATRIX" "$LINUX_MATRIX"
)"

COVERED_COUNT="$(jq 'length' <<< "$COVERED_TECHNIQUES")"
PARTIAL_COUNT="$(jq 'length' <<< "$PARTIAL_TECHNIQUES")"
BLIND_COUNT="$(jq 'length' <<< "$BLIND_TECHNIQUES")"

echo "ATT&CK covered: ${COVERED_COUNT}"
echo "ATT&CK partial: ${PARTIAL_COUNT}"
echo "ATT&CK blind: ${BLIND_COUNT}"

##############################################################
# Quality Scores
##############################################################

get_quality_score() {
    local file="$1"

    jq -r '
        .quality_score
        // .score
        // .quality.score
        // .overall_score
        // 0
    ' "$file"
}

WINDOWS_SCORE="$(get_quality_score "$WINDOWS_QUALITY")"
LINUX_SCORE="$(get_quality_score "$LINUX_QUALITY")"

echo "Windows quality: ${WINDOWS_SCORE}"
echo "Linux quality: ${LINUX_SCORE}"

##############################################################
# Final Confidence
##############################################################

FINAL_SCORE="$(
    awk -v win="$WINDOWS_SCORE" -v linux="$LINUX_SCORE" '
        BEGIN {
            printf "%.2f", (win + linux) / 2
        }
    '
)"

if awk -v score="$FINAL_SCORE" 'BEGIN { exit !(score >= 90) }'; then
    if [[ "$MISSED_TOTAL" -eq 0 ]]; then
        CONFIDENCE="good"
    else
        CONFIDENCE="acceptable"
    fi
elif awk -v score="$FINAL_SCORE" 'BEGIN { exit !(score >= 75) }'; then
    CONFIDENCE="acceptable"
else
    CONFIDENCE="poor"
fi

echo "Confidence: ${CONFIDENCE}"

##############################################################
# Known Gaps
##############################################################

KNOWN_GAPS="$(
    jq -n \
        --argjson blind "$BLIND_TECHNIQUES" \
        --argjson partial "$PARTIAL_TECHNIQUES" '
        [
            $blind[] |
            {
                description: "No telemetry source captured this simulated technique.",
                impacted_platform: "Cross-platform",
                impacted_technique: .,
                reason: "Detection matrix recorded the action as missed.",
                recommended_instrumentation_improvement:
                    "Add or refine endpoint telemetry rules and validate the event with a controlled simulation."
            }
        ]
        +
        [
            $partial[] |
            {
                description: "Telemetry captured the technique but lacked complete detail.",
                impacted_platform: "Cross-platform",
                impacted_technique: .,
                reason: "Detection matrix recorded partial visibility.",
                recommended_instrumentation_improvement:
                    "Improve event field collection and correlation for this ATT&CK technique."
            }
        ]
    '
)"

##############################################################
# Build Final Assessment
##############################################################

jq -n \
    --arg generated_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    --argjson windows_events "$WINDOWS_COUNT" \
    --argjson linux_events "$LINUX_COUNT" \
    --argjson total_events "$TOTAL_EVENTS" \
    --argjson ground_truth "$GROUND_TRUTH_COUNT" \
    --argjson windows_sources "$WINDOWS_SOURCE_COUNTS" \
    --argjson linux_sources "$LINUX_SOURCE_COUNTS" \
    --argjson windows_categories "$WINDOWS_CATEGORY_COUNTS" \
    --argjson linux_categories "$LINUX_CATEGORY_COUNTS" \
    --argjson detection_total "$DETECTION_TOTAL" \
    --argjson captured "$CAPTURED_TOTAL" \
    --argjson missed "$MISSED_TOTAL" \
    --argjson multisource "$MULTISOURCE_TOTAL" \
    --argjson covered "$COVERED_TECHNIQUES" \
    --argjson partial "$PARTIAL_TECHNIQUES" \
    --argjson blind "$BLIND_TECHNIQUES" \
    --argjson gaps "$KNOWN_GAPS" \
    --argjson windows_score "$WINDOWS_SCORE" \
    --argjson linux_score "$LINUX_SCORE" \
    --argjson final_score "$FINAL_SCORE" \
    --arg confidence "$CONFIDENCE" '
    {
        metadata: {
            generated_at: $generated_at,
            assessment: "Cross-Platform Telemetry Coverage Assessment",
            project: "MedDefense Endpoint Telemetry Engineering"
        },

        total_events: {
            windows: $windows_events,
            linux: $linux_events,
            total: $total_events
        },

        source_type_distribution: {
            windows: $windows_sources,
            linux: $linux_sources
        },

        event_category_distribution: {
            windows: $windows_categories,
            linux: $linux_categories
        },

        detection_matrix_summary: {
            total_simulated_actions: $detection_total,
            captured_actions: $captured,
            missed_actions: $missed,
            multi_source_detections: $multisource,
            capture_rate: (
                if $detection_total > 0
                then (($captured * 10000 / $detection_total) | round / 100)
                else 0
                end
            )
        },

        attack_technique_coverage: {
            covered: $covered,
            partially_covered: $partial,
            blind: $blind,
            covered_count: ($covered | length),
            partial_count: ($partial | length),
            blind_count: ($blind | length)
        },

        known_gaps: $gaps,

        quality_summary: {
            windows_score: $windows_score,
            linux_score: $linux_score,
            average_score: $final_score,
            final_handoff_confidence: $confidence
        },

        handoff_summary: {
            ground_truth_actions: $ground_truth,
            platforms: 2,
            telemetry_ready: true
        }
    }
    ' > "$OUTPUT_FILE"

##############################################################
# Final Validation
##############################################################

if ! jq empty "$OUTPUT_FILE" >/dev/null 2>&1; then
    echo "[!] Failed to create valid JSON assessment."
    exit 1
fi

##############################################################
# Final Output
##############################################################

echo
echo "Cross-platform telemetry coverage assessment complete."
echo "Report saved to: ${OUTPUT_FILE}"
echo
echo "Summary:"
echo "  Total events:       ${TOTAL_EVENTS}"
echo "  Captured actions:   ${CAPTURED_TOTAL}/${DETECTION_TOTAL}"
echo "  Missed actions:     ${MISSED_TOTAL}"
echo "  Multi-source:       ${MULTISOURCE_TOTAL}"
echo "  ATT&CK covered:     ${COVERED_COUNT}"
echo "  ATT&CK partial:     ${PARTIAL_COUNT}"
echo "  ATT&CK blind:       ${BLIND_COUNT}"
echo "  Windows quality:    ${WINDOWS_SCORE}"
echo "  Linux quality:      ${LINUX_SCORE}"
echo "  Confidence:         ${CONFIDENCE}"
```
