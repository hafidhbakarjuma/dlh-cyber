```bash
#!/bin/bash

# Name: 5-auditd_refine.sh
# Purpose: Adds detection-focused auditd rules for process execution,
#          network connections, SSH keys, cron persistence and sudoers.
#          Validates that each rule generates audit telemetry.
# Author: Hafidh Juma
# Project: MedDefense Endpoint Telemetry Engineering

set -euo pipefail

##############################################################
# Configuration
##############################################################

RULE_FILE="/etc/audit/rules.d/meddefense.rules"

PROCESS_RULE='-a always,exit -F arch=b64 -S execve -k process_exec'
NETWORK_RULE='-a always,exit -F arch=b64 -S socket -S connect -k network_connect'
SSH_RULE='-w /home/*/.ssh/ -p rwa -k ssh_keys'
CRON_RULE_1='-w /etc/cron.d/ -p wa -k cron_persist'
CRON_RULE_2='-w /var/spool/cron/ -p wa -k cron_persist'
SUDOERS_RULE='-w /etc/sudoers.d/ -p wa -k sudoers'

##############################################################
# Root Check
##############################################################

if [[ "${EUID}" -ne 0 ]]; then
    echo "[!] This script must be run as root."
    echo "    Use: sudo ./5-auditd_refine.sh"
    exit 1
fi

##############################################################
# auditd Check
##############################################################

if ! command -v auditctl >/dev/null 2>&1; then
    echo "[!] auditctl is not installed."
    exit 1
fi

if ! command -v ausearch >/dev/null 2>&1; then
    echo "[!] ausearch is not installed."
    exit 1
fi

if ! command -v augenrules >/dev/null 2>&1; then
    echo "[!] augenrules is not installed."
    exit 1
fi

##############################################################
# Rule File Check
##############################################################

if [[ ! -f "$RULE_FILE" ]]; then
    echo "[!] Rule file does not exist: $RULE_FILE"
    echo "[*] Creating $RULE_FILE..."
    touch "$RULE_FILE"
    chmod 640 "$RULE_FILE"
fi

##############################################################
# Current Rule Count
##############################################################

CURRENT_RULES=$(auditctl -l 2>/dev/null | grep -c -- "-a\|-w" || true)

echo "[*] Current auditd rules: $CURRENT_RULES"

##############################################################
# Helper Function
##############################################################

add_rule() {
    local rule="$1"
    local description="$2"

    if grep -Fqx -- "$rule" "$RULE_FILE"; then
        echo "    $description [EXISTS]"
    else
        echo "$rule" >> "$RULE_FILE"
        echo "    $description [ADDED]"
    fi
}

##############################################################
# Add Detection-Focused Rules
##############################################################

echo "[*] Adding detection-focused rules..."

add_rule \
    "$PROCESS_RULE" \
    "execve syscall tracking"

add_rule \
    "$NETWORK_RULE" \
    "socket/connect syscall tracking"

add_rule \
    "$SSH_RULE" \
    "SSH key file monitoring"

add_rule \
    "$CRON_RULE_1" \
    "Cron directory monitoring"

add_rule \
    "$CRON_RULE_2" \
    "Cron spool monitoring"

add_rule \
    "$SUDOERS_RULE" \
    "sudoers.d monitoring"

##############################################################
# Load Updated Rules
##############################################################

echo "[*] Loading rules... augenrules --load"

if augenrules --load >/dev/null 2>&1; then
    echo "    augenrules --load: OK"
else
    echo "    augenrules --load: FAILED"
    exit 1
fi

##############################################################
# Verify Rules Loaded
##############################################################

LOADED_RULES=$(auditctl -l 2>/dev/null | grep -c -- "-a\|-w" || true)

echo "[*] Total rules: $LOADED_RULES"

##############################################################
# Validation Preparation
##############################################################

echo "[*] Validating new rules..."

VALIDATION_PASS=0
VALIDATION_TOTAL=5

##############################################################
# Test 1 - Process Execution / execve
##############################################################

echo -n "    execve: ran /usr/bin/id -> ausearch -k process_exec    "

/usr/bin/id >/dev/null 2>&1

sleep 1

if ausearch -k process_exec -ts recent --raw 2>/dev/null |
    grep -q "process_exec"; then
    echo "[CAPTURED]"
    VALIDATION_PASS=$((VALIDATION_PASS + 1))
else
    echo "[MISSED]"
fi

##############################################################
# Test 2 - Network Socket / connect
##############################################################

echo -n "    socket: curl localhost -> ausearch -k network_connect  "

if command -v curl >/dev/null 2>&1; then
    curl -s --connect-timeout 2 http://127.0.0.1:80 >/dev/null 2>&1 || true
else
    # Python creates a socket and attempts a local connection.
    python3 - <<'PY' >/dev/null 2>&1 || true
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.connect(("127.0.0.1", 80))
except Exception:
    pass
finally:
    s.close()
PY
fi

sleep 1

if ausearch -k network_connect -ts recent --raw 2>/dev/null |
    grep -q "network_connect"; then
    echo "[CAPTURED]"
    VALIDATION_PASS=$((VALIDATION_PASS + 1))
else
    echo "[MISSED]"
fi

##############################################################
# Test 3 - SSH Key Monitoring
##############################################################

SSH_TEST_DIR="${HOME}/.ssh"
SSH_TEST_FILE="${SSH_TEST_DIR}/meddefense_audit_test"

echo -n "    ssh_keys: touch ~/.ssh/test -> ausearch -k ssh_keys    "

if [[ -d "$SSH_TEST_DIR" ]]; then
    touch "$SSH_TEST_FILE"
    rm -f "$SSH_TEST_FILE"

    sleep 1

    if ausearch -k ssh_keys -ts recent --raw 2>/dev/null |
        grep -q "ssh_keys"; then
        echo "[CAPTURED]"
        VALIDATION_PASS=$((VALIDATION_PASS + 1))
    else
        echo "[MISSED]"
    fi
else
    echo "[MISSED - ~/.ssh does not exist]"
fi

##############################################################
# Test 4 - Cron Persistence Monitoring
##############################################################

CRON_TEST_FILE="/etc/cron.d/meddefense_audit_test"

echo -n "    cron: touch /etc/cron.d/test -> ausearch -k cron_persist "

touch "$CRON_TEST_FILE"
rm -f "$CRON_TEST_FILE"

sleep 1

if ausearch -k cron_persist -ts recent --raw 2>/dev/null |
    grep -q "cron_persist"; then
    echo "[CAPTURED]"
    VALIDATION_PASS=$((VALIDATION_PASS + 1))
else
    echo "[MISSED]"
fi

##############################################################
# Test 5 - sudoers.d Monitoring
##############################################################

SUDOERS_TEST_FILE="/etc/sudoers.d/meddefense_audit_test"

echo -n "    sudoers: touch /etc/sudoers.d/test -> ausearch -k sudoers "

touch "$SUDOERS_TEST_FILE"
rm -f "$SUDOERS_TEST_FILE"

sleep 1

if ausearch -k sudoers -ts recent --raw 2>/dev/null |
    grep -q "sudoers"; then
    echo "[CAPTURED]"
    VALIDATION_PASS=$((VALIDATION_PASS + 1))
else
    echo "[MISSED]"
fi

##############################################################
# Validation Summary
##############################################################

echo ""
echo "Rules added: 5 | Validation: ${VALIDATION_PASS}/${VALIDATION_TOTAL} PASS"

if [[ "$VALIDATION_PASS" -eq "$VALIDATION_TOTAL" ]]; then
    echo "[+] All detection-focused auditd rules validated successfully."
    exit 0
else
    echo "[!] One or more auditd validation tests failed."
    exit 1
fi
```
