#!/bin/bash

# Name: 7-linux_export.sh
# Purpose: Export security-relevant Linux logs to normalized JSON Lines.
# Author: Hafidh Juma
# Project: MedDefense Endpoint Telemetry Engineering

set -e
set -u
set -o pipefail

##############################################################
# Configuration
##############################################################

LOG_DIR="/var/log"
AUTH_LOG="${LOG_DIR}/auth.log"
AUDIT_LOG="${LOG_DIR}/audit/audit.log"
SYSLOG="${LOG_DIR}/syslog"

OUTPUT_DIR="./telemetry"
OUTPUT_FILE="${OUTPUT_DIR}/linux_telemetry.jsonl"

START_TIME="${1:-$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ')}"
END_TIME="${2:-$(date -u '+%Y-%m-%dT%H:%M:%SZ')}"

HOSTNAME_VALUE="$(hostname -s)"

AUTH_COUNT=0
SSH_COUNT=0
SUDO_COUNT=0
SU_COUNT=0
PAM_COUNT=0

AUDIT_COUNT=0
EXECVE_COUNT=0
FILE_COUNT=0
NETWORK_COUNT=0
AUDIT_OTHER_COUNT=0

SYSLOG_COUNT=0
SERVICE_COUNT=0
ERROR_COUNT=0
SYSLOG_OTHER_COUNT=0

TOTAL_EVENTS=0

##############################################################
# Root Check
##############################################################

if [[ "${EUID}" -ne 0 ]]; then
    echo "[!] This script must be run as root."
    echo "    Use: sudo ./7-linux_export.sh"
    exit 1
fi

##############################################################
# Required Commands
##############################################################

for command in awk grep sed date hostname jq; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "[!] Required command not found: $command"
        exit 1
    fi
done

##############################################################
# Prepare Output
##############################################################

mkdir -p "$OUTPUT_DIR"
: > "$OUTPUT_FILE"

##############################################################
# JSON Helper
##############################################################

write_event() {
    local timestamp="$1"
    local source_type="$2"
    local category="$3"
    local message="$4"
    local user="${5:-}"
    local source_ip="${6:-}"
    local command_line="${7:-}"
    local path="${8:-}"
    local destination="${9:-}"

    jq -cn \
        --arg timestamp "$timestamp" \
        --arg hostname "$HOSTNAME_VALUE" \
        --arg source_type "$source_type" \
        --arg event_category "$category" \
        --arg message "$message" \
        --arg user "$user" \
        --arg source_ip "$source_ip" \
        --arg command_line "$command_line" \
        --arg path "$path" \
        --arg destination "$destination" \
        '{
            timestamp: $timestamp,
            hostname: $hostname,
            source_type: $source_type,
            event_category: $event_category,
            message: $message
        }
        + (if $user != "" then {user: $user} else {} end)
        + (if $source_ip != "" then {source_ip: $source_ip} else {} end)
        + (if $command_line != "" then {command_line: $command_line} else {} end)
        + (if $path != "" then {path: $path} else {} end)
        + (if $destination != "" then {destination: $destination} else {} end)' \
        >> "$OUTPUT_FILE"

    TOTAL_EVENTS=$((TOTAL_EVENTS + 1))
}

##############################################################
# Timestamp Normalization
##############################################################

normalize_syslog_timestamp() {
    local raw="$1"

    date -u -d "$raw $(date +%Y)" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null ||
        date -u -d "$raw" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null ||
        date -u '+%Y-%m-%dT%H:%M:%SZ'
}

##############################################################
# Time Filtering
##############################################################

timestamp_in_range() {
    local timestamp="$1"
    local ts_epoch
    local start_epoch
    local end_epoch

    ts_epoch=$(date -u -d "$timestamp" '+%s' 2>/dev/null || echo 0)
    start_epoch=$(date -u -d "$START_TIME" '+%s' 2>/dev/null || echo 0)
    end_epoch=$(date -u -d "$END_TIME" '+%s' 2>/dev/null || echo 9999999999)

    [[ "$ts_epoch" -ge "$start_epoch" && "$ts_epoch" -le "$end_epoch" ]]
}

##############################################################
# Authentication Log
##############################################################

parse_auth_log() {

    if [[ ! -f "$AUTH_LOG" ]]; then
        echo "[!] auth.log not found: $AUTH_LOG"
        return
    fi

    while IFS= read -r line; do

        timestamp_raw=$(echo "$line" | awk '{print $1" "$2" "$3}')

        timestamp=$(normalize_syslog_timestamp "$timestamp_raw")

        if ! timestamp_in_range "$timestamp"; then
            continue
        fi

        AUTH_COUNT=$((AUTH_COUNT + 1))

        ######################################################
        # SSH Successful Login
        ######################################################

        if echo "$line" | grep -Eq 'sshd.*Accepted'; then

            user=$(echo "$line" |
                sed -n 's/.*Accepted [^ ]* for \([^ ]*\) from.*/\1/p')

            source_ip=$(echo "$line" |
                sed -n 's/.*from \([^ ]*\) port.*/\1/p')

            write_event \
                "$timestamp" \
                "auth.log" \
                "ssh_login_success" \
                "$line" \
                "$user" \
                "$source_ip"

            SSH_COUNT=$((SSH_COUNT + 1))
            continue
        fi

        ######################################################
        # SSH Failed Login
        ######################################################

        if echo "$line" | grep -Eq 'sshd.*Failed password'; then

            user=$(echo "$line" |
                sed -n 's/.*Failed password for \(invalid user \)\?\([^ ]*\) from.*/\2/p')

            source_ip=$(echo "$line" |
                sed -n 's/.*from \([^ ]*\) port.*/\1/p')

            write_event \
                "$timestamp" \
                "auth.log" \
                "ssh_login_failure" \
                "$line" \
                "$user" \
                "$source_ip"

            SSH_COUNT=$((SSH_COUNT + 1))
            continue
        fi

        ######################################################
        # sudo
        ######################################################

        if echo "$line" | grep -Eq 'sudo:.*COMMAND='; then

            user=$(echo "$line" |
                sed -n 's/.*sudo: *\([^ ]*\) : .*COMMAND=.*/\1/p')

            command_line=$(echo "$line" |
                sed -n 's/.*COMMAND=//p')

            write_event \
                "$timestamp" \
                "auth.log" \
                "sudo" \
                "$line" \
                "$user" \
                "" \
                "$command_line"

            SUDO_COUNT=$((SUDO_COUNT + 1))
            continue
        fi

        ######################################################
        # su
        ######################################################

        if echo "$line" | grep -Eq 'su:.*session'; then

            user=$(echo "$line" |
                sed -n 's/.*su:.*session .* for user \([^ ]*\).*/\1/p')

            write_event \
                "$timestamp" \
                "auth.log" \
                "su" \
                "$line" \
                "$user"

            SU_COUNT=$((SU_COUNT + 1))
            continue
        fi

        ######################################################
        # PAM
        ######################################################

        if echo "$line" | grep -Eq 'pam_|PAM'; then

            write_event \
                "$timestamp" \
                "auth.log" \
                "pam" \
                "$line"

            PAM_COUNT=$((PAM_COUNT + 1))
            continue
        fi

    done < "$AUTH_LOG"
}

##############################################################
# auditd Log
##############################################################

parse_audit_log() {

    if [[ ! -f "$AUDIT_LOG" ]]; then
        echo "[!] audit.log not found: $AUDIT_LOG"
        return
    fi

    while IFS= read -r line; do

        if ! echo "$line" | grep -q 'type='; then
            continue
        fi

        ######################################################
        # Extract audit timestamp
        ######################################################

        audit_epoch=$(echo "$line" |
            sed -n 's/.*audit(\([0-9]*\)\.[0-9]*:.*/\1/p')

        if [[ -z "$audit_epoch" ]]; then
            continue
        fi

        timestamp=$(date -u -d "@${audit_epoch}" '+%Y-%m-%dT%H:%M:%SZ')

        if ! timestamp_in_range "$timestamp"; then
            continue
        fi

        AUDIT_COUNT=$((AUDIT_COUNT + 1))

        ######################################################
        # execve
        ######################################################

        if echo "$line" | grep -Eq 'type=EXECVE|type=SYSCALL.*syscall=59'; then

            command_line=$(echo "$line" |
                sed -n 's/.*a0="\([^"]*\)".*/\1/p')

            write_event \
                "$timestamp" \
                "auditd" \
                "execve" \
                "$line" \
                "" \
                "" \
                "$command_line"

            EXECVE_COUNT=$((EXECVE_COUNT + 1))
            continue
        fi

        ######################################################
        # File Access
        ######################################################

        if echo "$line" | grep -Eq 'type=PATH|type=OPEN|type=CREAT'; then

            path=$(echo "$line" |
                sed -n 's/.*name="\([^"]*\)".*/\1/p')

            write_event \
                "$timestamp" \
                "auditd" \
                "file_access" \
                "$line" \
                "" \
                "" \
                "" \
                "$path"

            FILE_COUNT=$((FILE_COUNT + 1))
            continue
        fi

        ######################################################
        # Network
        ######################################################

        if echo "$line" | grep -Eq 'socket|connect|SOCKETCALL'; then

            destination=$(echo "$line" |
                sed -n 's/.*dest=\([^ ]*\).*/\1/p')

            write_event \
                "$timestamp" \
                "auditd" \
                "network" \
                "$line" \
                "" \
                "" \
                "" \
                "" \
                "$destination"

            NETWORK_COUNT=$((NETWORK_COUNT + 1))
            continue
        fi

        ######################################################
        # Other audit event
        ######################################################

        write_event \
            "$timestamp" \
            "auditd" \
            "other" \
            "$line"

        AUDIT_OTHER_COUNT=$((AUDIT_OTHER_COUNT + 1))

    done < "$AUDIT_LOG"
}

##############################################################
# Syslog
##############################################################

parse_syslog() {

    if [[ ! -f "$SYSLOG" ]]; then
        echo "[!] syslog not found: $SYSLOG"
        return
    fi

    while IFS= read -r line; do

        timestamp_raw=$(echo "$line" | awk '{print $1" "$2" "$3}')

        timestamp=$(normalize_syslog_timestamp "$timestamp_raw")

        if ! timestamp_in_range "$timestamp"; then
            continue
        fi

        SYSLOG_COUNT=$((SYSLOG_COUNT + 1))

        ######################################################
        # Service events
        ######################################################

        if echo "$line" | grep -Eiq \
            '(started|starting|stopped|stopping|service .*start|service .*stop)'; then

            write_event \
                "$timestamp" \
                "syslog" \
                "service" \
                "$line"

            SERVICE_COUNT=$((SERVICE_COUNT + 1))
            continue
        fi

        ######################################################
        # Errors
        ######################################################

        if echo "$line" | grep -Eiq \
            '(error|failed|failure|critical|crit|emergency|emerg)'; then

            write_event \
                "$timestamp" \
                "syslog" \
                "error" \
                "$line"

            ERROR_COUNT=$((ERROR_COUNT + 1))
            continue
        fi

        ######################################################
        # Other
        ######################################################

        write_event \
            "$timestamp" \
            "syslog" \
            "other" \
            "$line"

        SYSLOG_OTHER_COUNT=$((SYSLOG_OTHER_COUNT + 1))

    done < "$SYSLOG"
}

##############################################################
# Execute Parsers
##############################################################

echo "[*] Parsing auth.log..."

parse_auth_log

echo "    SSH logins: $SSH_COUNT | sudo: $SUDO_COUNT | su: $SU_COUNT | PAM: $PAM_COUNT"

echo "[*] Parsing audit.log..."

parse_audit_log

echo "    execve: $EXECVE_COUNT | file_access: $FILE_COUNT | network: $NETWORK_COUNT | other: $AUDIT_OTHER_COUNT"

echo "[*] Parsing syslog..."

parse_syslog

echo "    service: $SERVICE_COUNT | error: $ERROR_COUNT | other: $SYSLOG_OTHER_COUNT"

##############################################################
# Final Summary
##############################################################

echo ""
echo "Total events: $TOTAL_EVENTS"
echo "Time range: $START_TIME to $END_TIME"
echo "Output: $OUTPUT_FILE"

##############################################################
# JSON Validation
##############################################################

if [[ -s "$OUTPUT_FILE" ]]; then

    if jq -e . "$OUTPUT_FILE" >/dev/null 2>&1; then
        echo "[+] JSON validation: PASS"
    else
        echo "[!] JSON validation: FAILED"
        exit 1
    fi

else
    echo "[!] No events exported."
fi

exit 0
