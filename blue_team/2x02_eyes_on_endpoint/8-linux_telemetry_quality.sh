#!/bin/bash

# Name: 8-linux_telemetry_quality.sh
# Purpose: Assess Linux telemetry quality and generate a JSON quality report.
# Author: Hafidh Juma
# Project: MedDefense Endpoint Telemetry Engineering

set -euo pipefail

##############################################################
# Configuration
##############################################################

INPUT_FILE="./telemetry/linux_events_export.json"
OUTPUT_FILE="./telemetry/linux_telemetry_quality.json"

##############################################################
# Root Check
##############################################################

if [[ "${EUID}" -ne 0 ]]; then
    echo "[!] This script must be run as root."
    echo "    Use: sudo ./8-linux_telemetry_quality.sh"
    exit 1
fi

##############################################################
# Required Commands
##############################################################

for command in jq date awk; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "[!] Required command not found: $command"
        exit 1
    fi
done

##############################################################
# Input Validation
##############################################################

if [[ ! -f "$INPUT_FILE" ]]; then
    echo "[!] Input file not found: $INPUT_FILE"
    exit 1
fi

if [[ ! -s "$INPUT_FILE" ]]; then
    echo "[!] Input file is empty: $INPUT_FILE"
    exit 1
fi

if ! jq empty "$INPUT_FILE" >/dev/null 2>&1; then
    echo "[!] Invalid JSON/JSONL input: $INPUT_FILE"
    exit 1
fi

mkdir -p "$(dirname "$OUTPUT_FILE")"

echo "[*] Analyzing linux_events_export.json..."

##############################################################
# Normalize JSON / JSON Lines
##############################################################

# The previous task exports one JSON event per line.
# Convert JSON Lines into a single JSON array for analysis.

EVENTS_JSON=$(jq -s '.' "$INPUT_FILE")

TOTAL_EVENTS=$(jq 'length' <<< "$EVENTS_JSON")

if [[ "$TOTAL_EVENTS" -eq 0 ]]; then
    echo "[!] No events found in input."
    exit 1
fi

##############################################################
# Event Distribution
##############################################################

CATEGORY_JSON=$(
    jq '
        group_by(.event_category // "unknown")
        | map({
            category: (.[0].event_category // "unknown"),
            count: length,
            percentage: ((length * 10000 / ($TOTAL | tonumber)) | round / 100)
        })
    ' --arg TOTAL "$TOTAL_EVENTS" <<< "$EVENTS_JSON"
)

SOURCE_JSON=$(
    jq '
        group_by(.source_type // "unknown")
        | map({
            source_type: (.[0].source_type // "unknown"),
            count: length,
            percentage: ((length * 10000 / ($TOTAL | tonumber)) | round / 100)
        })
    ' --arg TOTAL "$TOTAL_EVENTS" <<< "$EVENTS_JSON"
)

##############################################################
# Time Coverage
##############################################################

HOUR_COUNTS=$(
    jq -r '
        .[]
        | select(.timestamp != null)
        | .timestamp
        | fromdateiso8601
        | (. / 3600 | floor)
    ' <<< "$EVENTS_JSON" |
    sort -n |
    uniq -c
)

HOURS_WITH_EVENTS=$(awk 'NF { count++ } END { print count + 0 }' <<< "$HOUR_COUNTS")

if [[ "$HOURS_WITH_EVENTS" -gt 24 ]]; then
    HOURS_WITH_EVENTS=24
fi

HOURS_WITHOUT_EVENTS=$((24 - HOURS_WITH_EVENTS))

EVENTS_PER_HOUR=$(
    awk -v total="$TOTAL_EVENTS" -v hours="$HOURS_WITH_EVENTS" '
        BEGIN {
            if (hours > 0)
                printf "%.2f", total / hours
            else
                print "0.00"
        }
    '
)

##############################################################
# Timestamp Coverage
##############################################################

TIMESTAMP_COMPLETE=$(
    jq '[.[] | select(.timestamp != null and .timestamp != "")] | length' \
        <<< "$EVENTS_JSON"
)

HOSTNAME_COMPLETE=$(
    jq '[.[] | select(.hostname != null and .hostname != "")] | length' \
        <<< "$EVENTS_JSON"
)

SOURCE_TYPE_COMPLETE=$(
    jq '[.[] | select(.source_type != null and .source_type != "")] | length' \
        <<< "$EVENTS_JSON"
)

CATEGORY_COMPLETE=$(
    jq '[.[] | select(.event_category != null and .event_category != "")] | length' \
        <<< "$EVENTS_JSON"
)

##############################################################
# Conditional Field Completeness
##############################################################

EXECVE_TOTAL=$(
    jq '[.[] | select(.event_category == "execve")] | length' \
        <<< "$EVENTS_JSON"
)

EXECVE_COMPLETE=$(
    jq '[.[] | select(.event_category == "execve")
        | select(.command_line != null and .command_line != "")] | length' \
        <<< "$EVENTS_JSON"
)

SSH_TOTAL=$(
    jq '[.[] | select(.event_category == "ssh")] | length' \
        <<< "$EVENTS_JSON"
)

SSH_SOURCE_IP_COMPLETE=$(
    jq '[.[] | select(.event_category == "ssh")
        | select(.source_ip != null and .source_ip != "")] | length' \
        <<< "$EVENTS_JSON"
)

SSH_USER_COMPLETE=$(
    jq '[.[] | select(.event_category == "ssh")
        | select(.user != null and .user != "")] | length' \
        <<< "$EVENTS_JSON"
)

AUDIT_FILE_TOTAL=$(
    jq '[.[] | select(
        .event_category == "file_access"
        or .event_category == "auditd_file"
    )] | length' <<< "$EVENTS_JSON"
)

AUDIT_PATH_COMPLETE=$(
    jq '[.[] | select(
        .event_category == "file_access"
        or .event_category == "auditd_file"
    )
    | select(.path != null and .path != "")] | length' \
        <<< "$EVENTS_JSON"
)

AUDIT_OPERATION_COMPLETE=$(
    jq '[.[] | select(
        .event_category == "file_access"
        or .event_category == "auditd_file"
    )
    | select(
        .operation != null and .operation != ""
        or .key != null and .key != ""
    )] | length' <<< "$EVENTS_JSON"
)

##############################################################
# Percentage Helper
##############################################################

percentage() {
    local complete="$1"
    local total="$2"

    if [[ "$total" -eq 0 ]]; then
        echo "100.00"
    else
        awk -v c="$complete" -v t="$total" \
            'BEGIN { printf "%.2f", (c / t) * 100 }'
    fi
}

TIMESTAMP_PERCENT=$(percentage "$TIMESTAMP_COMPLETE" "$TOTAL_EVENTS")
HOSTNAME_PERCENT=$(percentage "$HOSTNAME_COMPLETE" "$TOTAL_EVENTS")
SOURCE_TYPE_PERCENT=$(percentage "$SOURCE_TYPE_COMPLETE" "$TOTAL_EVENTS")
CATEGORY_PERCENT=$(percentage "$CATEGORY_COMPLETE" "$TOTAL_EVENTS")

EXECVE_PERCENT=$(percentage "$EXECVE_COMPLETE" "$EXECVE_TOTAL")
SSH_SOURCE_IP_PERCENT=$(percentage "$SSH_SOURCE_IP_COMPLETE" "$SSH_TOTAL")
SSH_USER_PERCENT=$(percentage "$SSH_USER_COMPLETE" "$SSH_TOTAL")
AUDIT_PATH_PERCENT=$(percentage "$AUDIT_PATH_COMPLETE" "$AUDIT_FILE_TOTAL")
AUDIT_OPERATION_PERCENT=$(percentage "$AUDIT_OPERATION_COMPLETE" "$AUDIT_FILE_TOTAL")

##############################################################
# Gap Detection
##############################################################

GAP_COUNT=0
LONGEST_GAP_MINUTES=0

TIMESTAMPS=$(
    jq -r '
        .[]
        | select(.timestamp != null)
        | .timestamp
        | fromdateiso8601
    ' <<< "$EVENTS_JSON" |
    sort -n
)

PREVIOUS=""

while IFS= read -r CURRENT; do
    [[ -z "$CURRENT" ]] && continue

    if [[ -n "$PREVIOUS" ]]; then
        GAP_SECONDS=$((CURRENT - PREVIOUS))

        if [[ "$GAP_SECONDS" -gt 1800 ]]; then
            GAP_COUNT=$((GAP_COUNT + 1))

            GAP_MINUTES=$((GAP_SECONDS / 60))

            if [[ "$GAP_MINUTES" -gt "$LONGEST_GAP_MINUTES" ]]; then
                LONGEST_GAP_MINUTES="$GAP_MINUTES"
            fi
        fi
    fi

    PREVIOUS="$CURRENT"
done <<< "$TIMESTAMPS"

if [[ "$GAP_COUNT" -eq 0 ]]; then
    GAP_ASSESSMENT="No gaps detected"
else
    GAP_ASSESSMENT="${GAP_COUNT} gap(s) longer than 30 minutes"
fi

##############################################################
# Quality Score
##############################################################

# Core field completeness contributes 50%.
# Conditional security fields contribute 30%.
# Time coverage contributes 10%.
# Gap detection contributes 10%.

CORE_SCORE=$(
    awk \
        -v timestamp="$TIMESTAMP_PERCENT" \
        -v hostname="$HOSTNAME_PERCENT" \
        -v source="$SOURCE_TYPE_PERCENT" \
        -v category="$CATEGORY_PERCENT" \
        'BEGIN {
            print (timestamp + hostname + source + category) / 4
        }'
)

CONDITIONAL_SCORE=$(
    awk \
        -v execve="$EXECVE_PERCENT" \
        -v ssh_ip="$SSH_SOURCE_IP_PERCENT" \
        -v ssh_user="$SSH_USER_PERCENT" \
        -v path="$AUDIT_PATH_PERCENT" \
        -v operation="$AUDIT_OPERATION_PERCENT" \
        'BEGIN {
            print (execve + ssh_ip + ssh_user + path + operation) / 5
        }'
)

TIME_SCORE=$(
    awk -v hours="$HOURS_WITH_EVENTS" \
        'BEGIN {
            if (hours >= 24) print 100
            else print (hours / 24) * 100
        }'
)

if [[ "$GAP_COUNT" -eq 0 ]]; then
    GAP_SCORE=100
else
    GAP_SCORE=0
fi

QUALITY_SCORE=$(
    awk \
        -v core="$CORE_SCORE" \
        -v conditional="$CONDITIONAL_SCORE" \
        -v time="$TIME_SCORE" \
        -v gaps="$GAP_SCORE" \
        'BEGIN {
            printf "%.1f", \
            (core * 0.50) + \
            (conditional * 0.30) + \
            (time * 0.10) + \
            (gaps * 0.10)
        }'
)

##############################################################
# Assessment
##############################################################

ASSESSMENT=$(
    awk -v score="$QUALITY_SCORE" '
        BEGIN {
            if (score >= 90)
                print "good"
            else if (score >= 70)
                print "acceptable"
            else
                print "poor"
        }
    '
)

##############################################################
# Build Quality Report
##############################################################

jq -n \
    --argjson total "$TOTAL_EVENTS" \
    --argjson categories "$CATEGORY_JSON" \
    --argjson sources "$SOURCE_JSON" \
    --argjson hours_with_events "$HOURS_WITH_EVENTS" \
    --argjson hours_without_events "$HOURS_WITHOUT_EVENTS" \
    --arg events_per_hour "$EVENTS_PER_HOUR" \
    --arg gap_assessment "$GAP_ASSESSMENT" \
    --argjson gap_count "$GAP_COUNT" \
    --argjson longest_gap_minutes "$LONGEST_GAP_MINUTES" \
    --argjson timestamp_complete "$TIMESTAMP_COMPLETE" \
    --argjson hostname_complete "$HOSTNAME_COMPLETE" \
    --argjson source_type_complete "$SOURCE_TYPE_COMPLETE" \
    --argjson category_complete "$CATEGORY_COMPLETE" \
    --arg timestamp_percent "$TIMESTAMP_PERCENT" \
    --arg hostname_percent "$HOSTNAME_PERCENT" \
    --arg source_type_percent "$SOURCE_TYPE_PERCENT" \
    --arg category_percent "$CATEGORY_PERCENT" \
    --arg execve_percent "$EXECVE_PERCENT" \
    --arg ssh_source_ip_percent "$SSH_SOURCE_IP_PERCENT" \
    --arg ssh_user_percent "$SSH_USER_PERCENT" \
    --arg audit_path_percent "$AUDIT_PATH_PERCENT" \
    --arg audit_operation_percent "$AUDIT_OPERATION_PERCENT" \
    --arg quality_score "$QUALITY_SCORE" \
    --arg assessment "$ASSESSMENT" \
    '{
        total_events: $total,
        event_distribution: {
            by_category: $categories,
            by_source_type: $sources
        },
        time_coverage: {
            events_per_hour: ($events_per_hour | tonumber),
            hours_with_events: $hours_with_events,
            hours_without_events: $hours_without_events
        },
        gap_detection: {
            gaps_longer_than_30_minutes: $gap_count,
            longest_gap_minutes: $longest_gap_minutes,
            assessment: $gap_assessment
        },
        field_completeness: {
            timestamp: {
                complete: $timestamp_complete,
                percentage: ($timestamp_percent | tonumber)
            },
            hostname: {
                complete: $hostname_complete,
                percentage: ($hostname_percent | tonumber)
            },
            source_type: {
                complete: $source_type_complete,
                percentage: ($source_type_percent | tonumber)
            },
            event_category: {
                complete: $category_complete,
                percentage: ($category_percent | tonumber)
            },
            execve_command_line_percentage: ($execve_percent | tonumber),
            ssh_source_ip_percentage: ($ssh_source_ip_percent | tonumber),
            ssh_user_percentage: ($ssh_user_percent | tonumber),
            auditd_file_path_percentage: ($audit_path_percent | tonumber),
            auditd_file_operation_or_key_percentage: ($audit_operation_percent | tonumber)
        },
        quality_score: ($quality_score | tonumber),
        assessment: $assessment
    }' > "$OUTPUT_FILE"

##############################################################
# Human-Readable Summary
##############################################################

echo "Total events: $TOTAL_EVENTS"
echo "Hours with events: ${HOURS_WITH_EVENTS}/24"

if [[ "$GAP_COUNT" -eq 0 ]]; then
    echo "No gaps detected"
else
    echo "$GAP_COUNT gap(s) longer than 30 minutes detected"
fi

echo "execve command_line completeness: ${EXECVE_PERCENT}%"
echo "SSH source_ip completeness: ${SSH_SOURCE_IP_PERCENT}%"
echo "auditd file path completeness: ${AUDIT_PATH_PERCENT}%"
echo "Quality score: ${QUALITY_SCORE}% (${ASSESSMENT})"
echo "Report saved to: $OUTPUT_FILE"
