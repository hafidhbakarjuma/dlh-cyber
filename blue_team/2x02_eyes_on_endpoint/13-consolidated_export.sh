```bash
#!/bin/bash

# Name: 13-consolidated_export.sh
# Purpose: Combine Windows and Linux telemetry into a normalized SOC handoff package.
# Author: Hafidh Juma
# Project: MedDefense Endpoint Telemetry Engineering

set -e
set -u
set -o pipefail

##############################################################
# Configuration
##############################################################

WINDOWS_INPUT="windows_events_export.json"
LINUX_INPUT="linux_events_export.json"

WINDOWS_GROUND_TRUTH="windows_attack_log.json"
LINUX_GROUND_TRUTH="linux_attack_log.json"

OUTPUT_DIR="telemetry_handoff"
WINDOWS_OUTPUT="${OUTPUT_DIR}/windows_events.json"
LINUX_OUTPUT="${OUTPUT_DIR}/linux_events.json"
GROUND_TRUTH_OUTPUT="${OUTPUT_DIR}/attack_ground_truth.json"

REQUIRED_FIELDS=(
    "timestamp"
    "hostname"
    "source_type"
    "event_category"
)

##############################################################
# Required Commands
##############################################################

for command in jq date; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "[!] Required command not found: $command"
        exit 1
    fi
done

##############################################################
# Input Validation
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
}

check_file "$WINDOWS_INPUT"
check_file "$LINUX_INPUT"
check_file "$WINDOWS_GROUND_TRUTH"
check_file "$LINUX_GROUND_TRUTH"

##############################################################
# JSON / JSONL Loader
##############################################################

load_events() {
    local file="$1"

    # Accept both:
    #   1. JSON array: [{...}, {...}]
    #   2. JSON Lines: {"..."}\n{"..."}

    if jq -e 'type == "array"' "$file" >/dev/null 2>&1; then
        jq '.' "$file"
    else
        jq -s '.' "$file"
    fi
}

##############################################################
# Timestamp Normalization
##############################################################

normalize_events() {
    local file="$1"

    load_events "$file" |
        jq '
            map(
                .timestamp =
                    (
                        try (
                            (.timestamp | fromdateiso8601) |
                            todateiso8601
                        )
                        catch
                            .timestamp
                    )
            )
        '
}

##############################################################
# Required Field Validation
##############################################################

validate_required_fields() {
    local file="$1"
    local platform="$2"

    local missing_count

    missing_count="$(
        jq --argjson fields "$(printf '%s\n' "${REQUIRED_FIELDS[@]}" |
            jq -R . |
            jq -s .)" '
            [
                .[] |
                select(
                    any($fields[]; (. [.] == null or .[.] == ""))
                )
            ] |
            length
        ' "$file"
    )"

    if [[ "$missing_count" -ne 0 ]]; then
        echo "[!] ${platform}: ${missing_count} event(s) missing required fields."
        return 1
    fi

    return 0
}

##############################################################
# Header
##############################################################

echo "[*] Loading Windows events..."

WINDOWS_EVENTS="$(normalize_events "$WINDOWS_INPUT")"
WINDOWS_COUNT="$(jq 'length' <<< "$WINDOWS_EVENTS")"

echo "    Windows events: ${WINDOWS_COUNT}"

echo "[*] Loading Linux events..."

LINUX_EVENTS="$(normalize_events "$LINUX_INPUT")"
LINUX_COUNT="$(jq 'length' <<< "$LINUX_EVENTS")"

echo "    Linux events: ${LINUX_COUNT}"

##############################################################
# Timestamp Validation
##############################################################

echo "[*] Normalizing timestamps to UTC..."

WINDOWS_EVENTS="$(
    jq '
        map(
            if (.timestamp | type) == "string" then
                .timestamp |= (
                    try (
                        fromdateiso8601 |
                        todateiso8601
                    )
                    catch .
                )
            else
                .
            end
        )
    ' <<< "$WINDOWS_EVENTS"
)"

LINUX_EVENTS="$(
    jq '
        map(
            if (.timestamp | type) == "string" then
                .timestamp |= (
                    try (
                        fromdateiso8601 |
                        todateiso8601
                    )
                    catch .
                )
            else
                .
            end
        )
    ' <<< "$LINUX_EVENTS"
)"

WINDOWS_NORMALIZED="$(jq 'length' <<< "$WINDOWS_EVENTS")"
LINUX_NORMALIZED="$(jq 'length' <<< "$LINUX_EVENTS")"

echo "    Windows: ${WINDOWS_NORMALIZED} events normalized"
echo "    Linux: ${LINUX_NORMALIZED} events normalized"

##############################################################
# Required Field Verification
##############################################################

echo "[*] Verifying field consistency..."

TEMP_WINDOWS="$(mktemp)"
TEMP_LINUX="$(mktemp)"

cleanup_temp() {
    rm -f "$TEMP_WINDOWS" "$TEMP_LINUX"
}

trap cleanup_temp EXIT

printf '%s\n' "$WINDOWS_EVENTS" > "$TEMP_WINDOWS"
printf '%s\n' "$LINUX_EVENTS" > "$TEMP_LINUX"

if ! validate_required_fields "$TEMP_WINDOWS" "Windows"; then
    exit 1
fi

if ! validate_required_fields "$TEMP_LINUX" "Linux"; then
    exit 1
fi

echo "    Required fields present in all events    [OK]"

##############################################################
# Prepare Output Directory
##############################################################

echo "[*] Building handoff directory..."

mkdir -p "$OUTPUT_DIR"

##############################################################
# Save Normalized Telemetry
##############################################################

jq '.' <<< "$WINDOWS_EVENTS" > "$WINDOWS_OUTPUT"
jq '.' <<< "$LINUX_EVENTS" > "$LINUX_OUTPUT"

##############################################################
# Ground Truth Loading
##############################################################

echo "[*] Combining ground truth..."

if ! jq -e 'type == "array"' "$WINDOWS_GROUND_TRUTH" >/dev/null 2>&1; then
    WINDOWS_GROUND_TRUTH_JSON="$(jq -s '.' "$WINDOWS_GROUND_TRUTH")"
else
    WINDOWS_GROUND_TRUTH_JSON="$(jq '.' "$WINDOWS_GROUND_TRUTH")"
fi

if ! jq -e 'type == "array"' "$LINUX_GROUND_TRUTH" >/dev/null 2>&1; then
    LINUX_GROUND_TRUTH_JSON="$(jq -s '.' "$LINUX_GROUND_TRUTH")"
else
    LINUX_GROUND_TRUTH_JSON="$(jq '.' "$LINUX_GROUND_TRUTH")"
fi

WINDOWS_ACTIONS="$(jq 'length' <<< "$WINDOWS_GROUND_TRUTH_JSON")"
LINUX_ACTIONS="$(jq 'length' <<< "$LINUX_GROUND_TRUTH_JSON")"
TOTAL_ACTIONS=$((WINDOWS_ACTIONS + LINUX_ACTIONS))

##############################################################
# Add Platform Information
##############################################################

COMBINED_GROUND_TRUTH="$(
    jq -n \
        --argjson windows "$WINDOWS_GROUND_TRUTH_JSON" \
        --argjson linux "$LINUX_GROUND_TRUTH_JSON" '
        {
            windows: (
                $windows |
                map(. + {platform: "Windows"})
            ),
            linux: (
                $linux |
                map(. + {platform: "Linux"})
            )
        }
        | .windows + .linux
    '
)"

jq '.' <<< "$COMBINED_GROUND_TRUTH" > "$GROUND_TRUTH_OUTPUT"

echo "    Windows actions: ${WINDOWS_ACTIONS} | Linux actions: ${LINUX_ACTIONS} | Total: ${TOTAL_ACTIONS}"

##############################################################
# Final Validation
##############################################################

if ! jq empty "$WINDOWS_OUTPUT" >/dev/null 2>&1; then
    echo "[!] Windows output validation failed."
    exit 1
fi

if ! jq empty "$LINUX_OUTPUT" >/dev/null 2>&1; then
    echo "[!] Linux output validation failed."
    exit 1
fi

if ! jq empty "$GROUND_TRUTH_OUTPUT" >/dev/null 2>&1; then
    echo "[!] Ground truth output validation failed."
    exit 1
fi

##############################################################
# Statistics
##############################################################

TOTAL_EVENTS=$((WINDOWS_COUNT + LINUX_COUNT))

WINDOWS_SIZE="$(du -h "$WINDOWS_OUTPUT" | awk '{print $1}')"
LINUX_SIZE="$(du -h "$LINUX_OUTPUT" | awk '{print $1}')"

echo "[*] Handoff package created successfully."
echo
echo "telemetry_handoff/"
echo "  windows_events.json     (${WINDOWS_COUNT} events, ${WINDOWS_SIZE})"
echo "  linux_events.json       (${LINUX_COUNT} events, ${LINUX_SIZE})"
echo "  attack_ground_truth.json (${TOTAL_ACTIONS} actions)"
echo
echo "Total: ${TOTAL_EVENTS} events across 2 platforms"
echo
echo "[+] Consolidated telemetry export complete."
```
