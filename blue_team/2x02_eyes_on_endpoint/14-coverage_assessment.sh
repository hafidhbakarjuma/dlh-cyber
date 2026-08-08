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

# Required telemetry handoff files
WINDOWS_EVENTS="telemetry_handoff/windows_events.json"
LINUX_EVENTS="telemetry_handoff/linux_events.json"
GROUND_TRUTH="telemetry_handoff/attack_ground_truth.json"

# Required detection and quality reports
WINDOWS_MATRIX="windows_detection_matrix.json"
LINUX_MATRIX="linux_detection_matrix.json"
WINDOWS_QUALITY="windows_telemetry_quality.json"
LINUX_QUALITY="linux_telemetry_quality.json"
SYSMON_MATRIX="sysmon_coverage_matrix.json"

OUTPUT_FILE="telemetry_coverage_assessment.json"

##############################################################
# Required Commands
##############################################################

if ! command -v jq >/dev/null 2>&1; then
    echo "[!] Required command not found: jq"
    exit 1
fi

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

check_file "telemetry_handoff/windows_events.json"
check_file "telemetry_handoff/linux_events.json"
check_file "telemetry_handoff/attack_ground_truth.json"
check_file "windows_detection_matrix.json"
check_file "linux_detection_matrix.json"
check_file "windows_telemetry_quality.json"
check_file "linux_telemetry_quality.json"
check_file "sysmon_coverage_matrix.json"

##############################################################
# Event Counts
##############################################################

WINDOWS_COUNT="$(jq 'if type == "array" then length else (.events // []) | length end' \
    "telemetry_handoff/windows_events.json")"

LINUX_COUNT="$(jq 'if type == "array" then length else (.events // []) | length end' \
    "telemetry_handoff/linux_events.json")"

GROUND_TRUTH_COUNT="$(jq 'if type == "array" then length else (.actions // []) | length end' \
    "telemetry_handoff/attack_ground_truth.json")"

TOTAL_EVENTS=$((WINDOWS_COUNT + LINUX_COUNT))

echo "Windows events: ${WINDOWS_COUNT}"
echo "Linux events: ${LINUX_COUNT}"
echo "Ground truth actions: ${GROUND_TRUTH_COUNT}"

##############################################################
# Event Distribution
##############################################################

WINDOWS_SOURCE_COUNTS="$(
    jq '
        if type == "array" then .
        else (.events // [])
        end
        | group_by(.source_type // "unknown")
        | map({
            source_type: (.[0].source_type // "unknown"),
            count: length
        })
    ' "telemetry_handoff/windows_events.json"
)"

LINUX_SOURCE_COUNTS="$(
    jq '
        if type == "array" then .
        else (.events // [])
        end
        | group_by(.source_type // "unknown")
        | map({
            source_type: (.[0].source_type // "unknown"),
            count: length
        })
    ' "telemetry_handoff/linux_events.json"
)"

WINDOWS_CATEGORY_COUNTS="$(
    jq '
        if type == "array" then .
        else (.events // [])
        end
        | group_by(.event_category // "unknown")
        | map({
            event_category: (.[0].event_category // "unknown"),
            count: length
        })
    ' "telemetry_handoff/windows_events.json"
)"

LINUX_CATEGORY_COUNTS="$(
    jq '
        if type == "array" then .
        else (.events // [])
        end
        | group_by(.event_category // "unknown")
        | map({
            event_category: (.[0].event_category // "unknown"),
            count: length
        })
    ' "telemetry_handoff/linux_events.json"
)"

##############################################################
# Detection Matrix Summary
#
# Summarize simulated actions, captured actions, missed actions,
# and multi-source detections across Windows and Linux.
##############################################################

get_matrix_array() {
    local file="$1"

    jq '
        if type == "array" then .
        elif .actions then .actions
        elif .detection_matrix then .detection_matrix
        elif .results then .results
        elif .detections then .detections
        else []
        end
    ' "$file"
}

get_matrix_total() {
    local file="$1"

    get_matrix_array "$file" | jq 'length'
}

get_matrix_captured() {
    local file="$1"

    get_matrix_array "$file" |
        jq '
            [
                .[]
                | select(
                    (.status // "" | ascii_upcase) == "CAPTURED"
                    or
                    (.detected // false) == true
                    or
                    (.captured // false) == true
                )
            ]
            | length
        '
}

get_matrix_multisource() {
    local file="$1"

    get_matrix_array "$file" |
        jq '
            [
                .[]
                | select(
                    ((.sources // []) | length) > 1
                    or
                    ((.detections // []) | length) > 1
                    or
                    ((.source // "") | tostring | contains(","))
                )
            ]
            | length
        '
}

WINDOWS_MATRIX_TOTAL="$(get_matrix_total "$WINDOWS_MATRIX")"
LINUX_MATRIX_TOTAL="$(get_matrix_total "$LINUX_MATRIX")"

WINDOWS_CAPTURED="$(get_matrix_captured "$WINDOWS_MATRIX")"
LINUX_CAPTURED="$(get_matrix_captured "$LINUX_MATRIX")"

WINDOWS_MULTI="$(get_matrix_multisource "$WINDOWS_MATRIX")"
LINUX_MULTI="$(get_matrix_multisource "$LINUX_MATRIX")"

SIMULATED_ACTIONS=$((WINDOWS_MATRIX_TOTAL + LINUX_MATRIX_TOTAL))
CAPTURED_ACTIONS=$((WINDOWS_CAPTURED + LINUX_CAPTURED))
MISSED_ACTIONS=$((SIMULATED_ACTIONS - CAPTURED_ACTIONS))
MULTI_SOURCE_DETECTIONS=$((WINDOWS_MULTI + LINUX_MULTI))

echo "Detection matrix: ${CAPTURED_ACTIONS}/${SIMULATED_ACTIONS} captured"

##############################################################
# ATT&CK Coverage
##############################################################

ATTACK_MATRIX="$(
    jq -s '
        map(
            if type == "array" then .
            elif .actions then .actions
            elif .detection_matrix then .detection_matrix
            elif .results then .results
            elif .detections then .detections
            else []
            end
        )
        | add
    ' "$WINDOWS_MATRIX" "$LINUX_MATRIX"
)"

COVERED_TECHNIQUES="$(
    jq '
        [
            .[]
            | select(
                (.status // "" | ascii_upcase) == "CAPTURED"
                or
                (.detected // false) == true
                or
                (.captured // false) == true
            )
            | (
                .mitre_attack_technique
                // .mitre_technique
                // .technique
                // "Unknown"
            )
        ]
        | unique
    ' <<< "$ATTACK_MATRIX"
)"

PARTIAL_TECHNIQUES="$(
    jq '
        [
            .[]
            | select(
                (.detail // "" | ascii_downcase) == "partial"
                or
                (.status // "" | ascii_upcase) == "PARTIAL"
            )
            | (
                .mitre_attack_technique
                // .mitre_technique
                // .technique
                // "Unknown"
            )
        ]
        | unique
    ' <<< "$ATTACK_MATRIX"
)"

BLIND_TECHNIQUES="$(
    jq '
        [
            .[]
            | select(
                (.status // "" | ascii_upcase) == "MISSED"
                or
                (.detected // true) == false
                or
                (.captured // true) == false
            )
            | (
                .mitre_attack_technique
                // .mitre_technique
                // .technique
                // "Unknown"
            )
        ]
        | unique
    ' <<< "$ATTACK_MATRIX"
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

WINDOWS_SCORE="$(
    jq -r '
        .quality_score
        // .score
        // .overall_score
        // .quality.score
        // 0
    ' "$WINDOWS_QUALITY"
)"

LINUX_SCORE="$(
    jq -r '
        .quality_score
        // .score
        // .overall_score
        // .quality.score
        // 0
    ' "$LINUX_QUALITY"
)"

# Remove percentage sign if present.
WINDOWS_SCORE="${WINDOWS_SCORE%\%}"
LINUX_SCORE="${LINUX_SCORE%\%}"

##############################################################
# Confidence Rating
##############################################################

CONFIDENCE="$(
    awk \
        -v ws="$WINDOWS_SCORE" \
        -v ls="$LINUX_SCORE" \
        -v captured="$DETECTION_CAPTURED" \
        -v total="$DETECTION_TOTAL" '
        BEGIN {
            if (total > 0)
                detection = (captured / total) * 100
            else
                detection = 0

            average = (ws + ls) / 2

            if (average >= 90 && detection >= 95)
                print "good"
            else if (average >= 80 && detection >= 80)
                print "acceptable"
            else
                print "poor"
        }
    '
)"

echo "Windows quality: ${WINDOWS_SCORE}"
echo "Linux quality: ${LINUX_SCORE}"
echo "Confidence: ${CONFIDENCE}"

##############################################################
# Known Gaps
##############################################################

KNOWN_GAPS="$(
    jq -n \
        --argjson blind "$BLIND_TECHNIQUES" \
        --argjson partial "$PARTIAL_TECHNIQUES" \
        '
        [
            ($blind[] |
                {
                    description:
                        "No telemetry evidence captured for simulated ATT&CK technique.",
                    impacted_platform:
                        "Windows/Linux",
                    impacted_technique:
                        .,
                    reason:
                        "Detection matrix contains a missed action.",
                    recommendation:
                        "Add or refine endpoint telemetry rules and validate with another controlled simulation."
                }
            ),

            ($partial[] |
                {
                    description:
                        "Telemetry captured the technique but did not provide complete detail.",
                    impacted_platform:
                        "Windows/Linux",
                    impacted_technique:
                        .,
                    reason:
                        "Detection matrix reports partial visibility.",
                    recommendation:
                        "Increase logging detail and ensure the relevant key fields are collected."
                }
            )
        ]
        | unique_by(.impacted_technique)
    '
)"

##############################################################
# Source Responsible for ATT&CK Coverage
##############################################################

ATTACK_COVERAGE="$(
    jq '
        [
            .[]
            | {
                technique:
                    (
                        .mitre_attack_technique
                        // .mitre_technique
                        // .technique
                        // "Unknown"
                    ),
                source:
                    (
                        .source
                        // .expected_detection_source
                        // (
                            if (.sources | type) == "array"
                            then (.sources | join(", "))
                            else (.sources // "Unknown")
                            end
                        )
                        // "Unknown"
                    ),
                status:
                    (
                        .status
                        // (
                            if (.detected // false) == true
                            then "CAPTURED"
                            else "MISSED"
                            end
                        )
                    )
            }
        ]
        | unique_by(.technique + "|" + .source)
    ' <<< "$ATTACK_MATRIX"
)"

##############################################################
# Build Final JSON
##############################################################

jq -n \
    --argjson windows_count "$WINDOWS_COUNT" \
    --argjson linux_count "$LINUX_COUNT" \
    --argjson total_events "$TOTAL_EVENTS" \
    --argjson ground_truth_count "$GROUND_TRUTH_COUNT" \
    --argjson windows_sources "$WINDOWS_SOURCE_COUNTS" \
    --argjson linux_sources "$LINUX_SOURCE_COUNTS" \
    --argjson windows_categories "$WINDOWS_CATEGORY_COUNTS" \
    --argjson linux_categories "$LINUX_CATEGORY_COUNTS" \
    --argjson detection_total "$DETECTION_TOTAL" \
    --argjson detection_captured "$DETECTION_CAPTURED" \
    --argjson detection_missed "$DETECTION_MISSED" \
    --argjson multi_source "$MULTI_SOURCE" \
    --argjson covered "$COVERED_TECHNIQUES" \
    --argjson partial "$PARTIAL_TECHNIQUES" \
    --argjson blind "$BLIND_TECHNIQUES" \
    --argjson attack_coverage "$ATTACK_COVERAGE" \
    --argjson known_gaps "$KNOWN_GAPS" \
    --argjson windows_score "$WINDOWS_SCORE" \
    --argjson linux_score "$LINUX_SCORE" \
    --arg confidence "$CONFIDENCE" \
    '
    {
        generated_at: (now | todateiso8601),
        assessment_type: "Cross-Platform Telemetry Coverage Assessment",

        total_events: {
            windows: $windows_count,
            linux: $linux_count,
            total: $total_events
        },

        event_distribution: {
            by_platform: {
                windows: $windows_count,
                linux: $linux_count
            },

            by_source_type: {
                windows: $windows_sources,
                linux: $linux_sources
            },

            by_event_category: {
                windows: $windows_categories,
                linux: $linux_categories
            }
        },

             detection_matrix_summary: {
            "total simulated actions": $simulated_actions,
            "captured actions": $captured_actions,
            "missed actions": $missed_actions,
            "multi-source detections": $multi_source_detections,
        
            capture_percentage:
                (
                    if $simulated_actions > 0
                    then (($captured_actions * 10000 / $simulated_actions) | round / 100)
                    else 0
                    end
                )
            },

        attack_coverage: {
            covered_techniques: $covered,
            partially_covered_techniques: $partial,
            blind_techniques: $blind,
            source_responsible_for_coverage: $attack_coverage
        },

        known_gaps: $known_gaps,

        quality_summary: {
            windows_score: $windows_score,
            linux_score: $linux_score,
            average_score:
                ((($windows_score + $linux_score) / 2) * 100 | round) / 100,
            final_handoff_confidence: $confidence
        }
    }
    ' > "$OUTPUT_FILE"

##############################################################
# Final Validation
##############################################################

if ! jq empty "$OUTPUT_FILE" >/dev/null 2>&1; then
    echo "[!] Failed to create valid JSON report."
    exit 1
fi

echo "Report saved to: ${OUTPUT_FILE}"
```
