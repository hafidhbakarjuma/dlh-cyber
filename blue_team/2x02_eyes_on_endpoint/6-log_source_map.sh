#!/bin/bash

# Name: 6-log_source_map.sh
# Purpose: Discovers active Linux log sources and maps their format,
#          rotation policy, size, estimated event rate and security relevance.
# Author: Hafidh Juma
# Project: MedDefense Endpoint Telemetry Engineering

set -e
set -u
set -o pipefail

##############################################################
# Configuration
##############################################################

LOG_DIR="/var/log"
LOGROTATE_DIR="/etc/logrotate.d"

##############################################################
# Root Check
##############################################################

if [[ "${EUID}" -ne 0 ]]; then
    echo "[!] This script must be run as root."
    echo "    Use: sudo ./6-log_source_map.sh"
    exit 1
fi

##############################################################
# Required Commands
##############################################################

for command in find stat awk grep sed date; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "[!] Required command not found: $command"
        exit 1
    fi
done

##############################################################
# Helper Functions
##############################################################

get_size() {
    local file="$1"

    if [[ -f "$file" ]]; then
        stat -c '%s' "$file"
    else
        echo "0"
    fi
}

format_size() {
    local bytes="$1"

    if (( bytes >= 1048576 )); then
        awk -v size="$bytes" 'BEGIN { printf "%.1f MB", size / 1048576 }'
    elif (( bytes >= 1024 )); then
        awk -v size="$bytes" 'BEGIN { printf "%.1f KB", size / 1024 }'
    else
        printf "%s B" "$bytes"
    fi
}

##############################################################
# Rotation Policy
##############################################################

get_rotation() {
    local file="$1"
    local base
    local policy_file

    base=$(basename "$file")
    policy_file=""

    # Search logrotate configurations for the log filename.
    if [[ -d "$LOGROTATE_DIR" ]]; then
        while IFS= read -r candidate; do
            if grep -qF "$base" "$candidate" 2>/dev/null; then
                policy_file="$candidate"
                break
            fi
        done < <(find "$LOGROTATE_DIR" -type f -print 2>/dev/null)
    fi

    if [[ -z "$policy_file" ]]; then
        echo "unknown"
        return
    fi

    # Determine configured rotation frequency.
    if grep -Eq '^[[:space:]]*daily' "$policy_file"; then
        echo "daily"
    elif grep -Eq '^[[:space:]]*weekly' "$policy_file"; then
        echo "weekly"
    elif grep -Eq '^[[:space:]]*monthly' "$policy_file"; then
        echo "monthly"
    else
        echo "configured"
    fi
}

##############################################################
# Event Rate
##############################################################

get_events_per_hour() {
    local file="$1"
    local now
    local hour_ago
    local count

    if [[ ! -f "$file" ]]; then
        echo "0"
        return
    fi

    now=$(date '+%b %e %H')
    hour_ago=$(date -d '1 hour ago' '+%b %e %H' 2>/dev/null || true)

    if [[ -z "$hour_ago" ]]; then
        echo "0"
        return
    fi

    count=$(awk -v now="$now" -v old="$hour_ago" '
        index($0, now) || index($0, old) { count++ }
        END { print count + 0 }
    ' "$file" 2>/dev/null || echo "0")

    echo "$count"
}

##############################################################
# Relevance
##############################################################

get_relevance() {
    local source="$1"

    case "$source" in
        auth.log|audit.log)
            echo "critical"
            ;;
        apache2-access|apache2-error|syslog)
            echo "high"
            ;;
        kern.log|dpkg.log)
            echo "medium"
            ;;
        *)
            echo "low"
            ;;
    esac
}

##############################################################
# Format Detection
##############################################################

get_format() {
    local source="$1"

    case "$source" in
        audit.log)
            echo "audit"
            ;;
        auth.log|syslog|kern.log)
            echo "syslog"
            ;;
        apache2-access)
            echo "combined"
            ;;
        apache2-error|dpkg.log)
            echo "custom"
            ;;
        *)
            echo "custom"
            ;;
    esac
}

##############################################################
# Source Mapping
##############################################################

declare -a SOURCES=()
declare -a PATHS=()
declare -a FORMATS=()
declare -a ROTATIONS=()
declare -a SIZES=()
declare -a RATES=()
declare -a RELEVANCE=()

add_source() {
    local source="$1"
    local path="$2"

    if [[ ! -f "$path" ]]; then
        return
    fi

    SOURCES+=("$source")
    PATHS+=("$path")
    FORMATS+=("$(get_format "$source")")
    ROTATIONS+=("$(get_rotation "$path")")
    SIZES+=("$(format_size "$(get_size "$path")")")
    RATES+=("$(get_events_per_hour "$path")")
    RELEVANCE+=("$(get_relevance "$source")")
}

##############################################################
# Discovery
##############################################################

echo "[*] Discovering log sources..."

# Standard Debian/Ubuntu/Kali logs.
add_source "auth.log" "$LOG_DIR/auth.log"
add_source "syslog" "$LOG_DIR/syslog"
add_source "audit.log" "$LOG_DIR/audit/audit.log"
add_source "kern.log" "$LOG_DIR/kern.log"
add_source "dpkg.log" "$LOG_DIR/dpkg.log"

# Apache access/error logs.
if [[ -d "$LOG_DIR/apache2" ]]; then
    for file in "$LOG_DIR"/apache2/*access*.log; do
        if [[ -f "$file" ]]; then
            add_source "apache2-access" "$file"
            break
        fi
    done

    for file in "$LOG_DIR"/apache2/*error*.log; do
        if [[ -f "$file" ]]; then
            add_source "apache2-error" "$file"
            break
        fi
    done
fi

##############################################################
# Additional Security-Relevant Sources
##############################################################

# UFW firewall log.
add_source "ufw.log" "$LOG_DIR/ufw.log"

# Fail2ban log.
add_source "fail2ban.log" "$LOG_DIR/fail2ban.log"

# Samba logs.
if [[ -d "$LOG_DIR/samba" ]]; then
    for file in "$LOG_DIR"/samba/*.log; do
        if [[ -f "$file" ]]; then
            add_source "samba" "$file"
        fi
    done
fi

##############################################################
# Output
##############################################################

printf "\n"
printf "%-20s %-38s %-10s %-12s %-12s %-10s\n" \
    "Source" "Path" "Format" "Rotation" "events/hr" "Relevance"

printf "%-20s %-38s %-10s %-12s %-12s %-10s\n" \
    "------" "----" "------" "--------" "---------" "---------"

for (( i=0; i<${#SOURCES[@]}; i++ )); do
    printf "%-20s %-38s %-10s %-12s %-12s %-10s\n" \
        "${SOURCES[$i]}" \
        "${PATHS[$i]}" \
        "${FORMATS[$i]}" \
        "${ROTATIONS[$i]}" \
        "${RATES[$i]}" \
        "${RELEVANCE[$i]}"
done

##############################################################
# Expected Source Validation
##############################################################

MISSING=0

check_expected() {
    local name="$1"
    local path="$2"

    if [[ ! -f "$path" ]]; then
        echo "[!] Missing expected source: $name ($path)"
        MISSING=$((MISSING + 1))
    elif [[ ! -s "$path" ]]; then
        echo "[!] Expected source exists but is empty: $name ($path)"
    fi
}

check_expected "auth.log" "$LOG_DIR/auth.log"
check_expected "audit.log" "$LOG_DIR/audit/audit.log"

##############################################################
# Summary
##############################################################

FOUND=${#SOURCES[@]}

echo ""
echo "Sources found: $FOUND | Missing: $MISSING"

if [[ "$MISSING" -eq 0 ]]; then
    echo "[+] All expected security log sources are present."
    exit 0
else
    echo "[!] One or more expected log sources are missing."
    exit 1
fi
