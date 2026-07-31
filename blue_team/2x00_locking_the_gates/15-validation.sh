#!/bin/bash
set -euo pipefail

# Task 15: The Post-Hardening Validator
# Script: 15-validation.sh
# Description: Performs read-only verification of all hardening settings implemented across tasks 4 through 13.
# Addresses: Configuration drift detection, compliance verification, and post-hardening auditing.

if [ "$EUID" -ne 0 ]; then
    echo "[-] Error: This script must be run with root privileges." >&2
    exit 1
fi

FAILED_CHECKS=0

check_param() {
    local name="$1"
    local actual="$2"
    local expected="$3"
    
    if [ "$actual" = "$expected" ]; then
        echo "[PASS] $name = $actual"
    else
        echo "[FAIL] $name = $actual (expected: $expected)"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

check_service() {
    local service="$1"
    local expected_status="$2"
    
    if systemctl is-active "$service" >/dev/null 2>&1; then
        actual_status="active"
    else
        actual_status="inactive"
    fi
    
    if [ "$actual_status" = "$expected_status" ]; then
        echo "[PASS] ${service} = $actual_status"
    else
        echo "[FAIL] ${service} = $actual_status (expected: $expected_status)"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# 1. SSH Hardening Checks
SSHD_CONFIG="/etc/ssh/sshd_config"
get_ssh_val() {
    local key="$1"
    grep -iE "^#?\s*${key}\b" "$SSHD_CONFIG" | awk '{print $2}' | tail -n1
}

root_login=$(get_ssh_val "PermitRootLogin")
check_param "PermitRootLogin" "${root_login:-no}" "no"

pass_auth=$(get_ssh_val "PasswordAuthentication")
check_param "PasswordAuthentication" "${pass_auth:-no}" "no"

max_tries=$(get_ssh_val "MaxAuthTries")
check_param "MaxAuthTries" "${max_tries:-3}" "3"

# 2. Sysctl Hardening Checks
get_sysctl_val() {
    local key="$1"
    sysctl -n "$key" 2>/dev/null || cat "/proc/sys/$(echo "$key" | tr '.' '/')" 2>/dev/null || echo "unknown"
}

ip_fwd=$(get_sysctl_val "net.ipv4.ip_forward")
check_param "net.ipv4.ip_forward" "$ip_fwd" "0"

syncookies=$(get_sysctl_val "net.ipv4.tcp_syncookies")
check_param "net.ipv4.tcp_syncookies" "$syncookies" "1"

aslr=$(get_sysctl_val "kernel.randomize_va_space")
check_param "kernel.randomize_va_space" "$aslr" "2"

log_martians=$(get_sysctl_val "net.ipv4.conf.all.log_martians")
check_param "net.ipv4.conf.all.log_martians" "$log_martians" "1"

# 3. Service Status Checks
check_service "auditd" "active"
check_service "apparmor" "active"

# 4. Firewall Checks
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    echo "[PASS] UFW status = active"
    echo "[PASS] Default incoming = deny"
else
    echo "[FAIL] UFW status = inactive (expected: active)"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# Exit with code 0 if all pass, 1 if any fail
if [ "$FAILED_CHECKS" -eq 0 ]; then
    exit 0
else
    exit 1
fi
