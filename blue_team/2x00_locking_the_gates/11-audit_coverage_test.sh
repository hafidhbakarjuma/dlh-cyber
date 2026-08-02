#!/bin/bash
set -euo pipefail

# Task 11: Audit Telemetry Coverage Test
# Script: 11-audit_coverage_test.sh
# Description: Executes controlled test events against auditd rules, validates
#              telemetry capture, cleans up artifacts, and generates
#              audit_validation.json.
# Addresses: Compliance validation, ensuring audit hooks are fully operational.

if [ "$EUID" -ne 0 ]; then
    echo "[-] Error: This script must be run with root privileges." >&2
    exit 1
fi

REPORT="audit_validation.json"
TFILE="/tmp/meddefense_audit_test.txt"

RESULTS=()
CAPTURED=0
TOTAL=6

cleanup() {
    rm -f "$TFILE"
    auditctl -W "$TFILE" -k audit_test_file 2>/dev/null || true
    auditctl -W /etc/crontab -k audit_test_cron 2>/dev/null || true
}
trap cleanup EXIT

# Search recent audit events for a given key, count matching SYSCALL records
chk() {
    sleep 1
    ausearch -ts recent -k "$1" 2>/dev/null | grep -c "^type=SYSCALL" || true
}

# Record a test result as a JSON object and print progress line
rec() {
    local idx="$1" name="$2" key="$3" cmd="$4" status="$5" count="$6"
    RESULTS+=("{\"test\":\"${name}\",\"audit_key\":\"${key}\",\"command\":\"${cmd}\",\"timestamp\":\"$(date -Iseconds)\",\"status\":\"${status}\",\"event_count\":${count}}")
    printf '[%d/%d] %-38s [%s]\n' "$idx" "$TOTAL" "$name" "$status"
}

echo "[*] Running audit telemetry coverage tests..."

# 1. Privileged command execution through sudo
sudo whoami >/dev/null 2>&1 || true
c=$(chk priv_esc)
[[ $c -gt 0 ]] && s=CAPTURED && CAPTURED=$((CAPTURED+1)) || s=MISSED
rec 1 "sudo execution" priv_esc "sudo whoami" "$s" "$c"

# 2. Attempted access to /etc/shadow
sudo cat /etc/shadow >/dev/null 2>&1 || true
c=$(chk identity)
[[ $c -gt 0 ]] && s=CAPTURED && CAPTURED=$((CAPTURED+1)) || s=MISSED
rec 2 "shadow access" identity "cat /etc/shadow" "$s" "$c"

# 3. Execution of wget/curl
wget --version >/dev/null 2>&1 || curl --version >/dev/null 2>&1 || true
c=$(chk suspicious_download)
[[ $c -gt 0 ]] && s=CAPTURED && CAPTURED=$((CAPTURED+1)) || s=MISSED
rec 3 "suspicious download tool" suspicious_download "wget --version" "$s" "$c"

# 4. Read/metadata check of /etc/ssh/sshd_config
cat /etc/ssh/sshd_config >/dev/null 2>&1 || true
c=$(chk sshd_config)
[[ $c -gt 0 ]] && s=CAPTURED && CAPTURED=$((CAPTURED+1)) || s=MISSED
rec 4 "sshd config read" sshd_config "cat sshd_config" "$s" "$c"

# 5. Controlled write to a monitored temporary test file
auditctl -w "$TFILE" -p wa -k audit_test_file 2>/dev/null || true
echo "test" > "$TFILE"
c=$(chk audit_test_file)
[[ $c -gt 0 ]] && s=CAPTURED && CAPTURED=$((CAPTURED+1)) || s=MISSED
rec 5 "monitored test file write" audit_test_file "echo > $TFILE" "$s" "$c"

# 6. Cron configuration inspection
auditctl -w /etc/crontab -p r -k audit_test_cron 2>/dev/null || true
cat /etc/crontab >/dev/null 2>&1 || true
c=$(chk audit_test_cron)
[[ $c -gt 0 ]] && s=CAPTURED && CAPTURED=$((CAPTURED+1)) || s=MISSED
rec 6 "cron configuration check" audit_test_cron "cat /etc/crontab" "$s" "$c"

echo "[*] Cleaning test artifacts..."
cleanup
trap - EXIT

{
    echo "{\"tests\":["
    for i in "${!RESULTS[@]}"; do
        sep=","
        [[ $i -eq $((${#RESULTS[@]}-1)) ]] && sep=""
        echo "  ${RESULTS[$i]}${sep}"
    done
    echo "],\"tests_executed\":${TOTAL},\"captured\":${CAPTURED},\"missed\":$((TOTAL-CAPTURED))}"
} > "$REPORT"

echo "Tests executed: $TOTAL"
echo "Captured: $CAPTURED"
echo "Missed: $((TOTAL-CAPTURED))"
echo "Report saved to: $REPORT"
