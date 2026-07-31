#!/bin/bash
set -euo pipefail

# Task 4: The SSH Lockdown
# Script: 4-ssh_hardening.sh
# Description: Hardens SSH configuration to eliminate password authentication, prevent root login, and restrict access.
# Addresses: Finding 009 (SSH password auth) and Crimson Tide Phase 3 (SSH lateral movement).

SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP_CONFIG="/etc/ssh/sshd_config.bak"
ISSUE_NET="/etc/issue.net"
SETTINGS_COUNT=11

# Ensure script is run with root privileges
if [ "$EUID" -ne 0 ]; then
    echo "[-] Error: This script must be run with root privileges." >&2
    exit 1
fi

echo "[*] Backing up $SSHD_CONFIG to $BACKUP_CONFIG"
cp -f "$SSHD_CONFIG" "$BACKUP_CONFIG"

echo "[*] Applying SSH hardening settings..."

# Helper function to set or replace configuration directives
set_sshd_param() {
    local key="$1"
    local value="$2"
    if grep -qE "^#?\s*${key}\b" "$SSHD_CONFIG"; then
        sed -i -E "s/^#?\s*(${key}\b).*/\1 ${value}/" "$SSHD_CONFIG"
    else
        echo "${key} ${value}" >> "$SSHD_CONFIG"
    fi
    echo "    $key $value"
}

# Explicit configuration parameters required by test suite
set_sshd_param "PermitRootLogin" "no"
set_sshd_param "PasswordAuthentication" "no"
set_sshd_param "PermitEmptyPasswords" "no"
set_sshd_param "X11Forwarding" "no"
set_sshd_param "MaxAuthTries" "3"
set_sshd_param "ClientAliveInterval" "300"
set_sshd_param "ClientAliveCountMax" "2"
set_sshd_param "AllowUsers" "medadmin sysadmin"
set_sshd_param "Protocol" "2"
set_sshd_param "LoginGraceTime" "60"
set_sshd_param "Banner" "$ISSUE_NET"

# Create /etc/issue.net banner file warning unauthorized users
echo "[*] Creating authorized access banner at $ISSUE_NET"
cat << 'BANNER_EOF' > "$ISSUE_NET"
***************************************************************************
                         AUTHORIZED ACCESS ONLY
    Unauthorized access to this system is prohibited and subject to 
    criminal prosecution. All activities are monitored and logged.
***************************************************************************
BANNER_EOF

echo "[*] Validating SSH configuration..."
if sshd -t; then
    echo "    sshd -t: OK"
else
    echo "[-] Error: sshd configuration test failed! Restoring backup..." >&2
    cp -f "$BACKUP_CONFIG" "$SSHD_CONFIG"
    exit 1
fi

echo "[*] Restarting SSH service..."
if systemctl restart ssh || systemctl restart sshd; then
    SSH_STATUS=$(systemctl is-active ssh 2>/dev/null || systemctl is-active sshd 2>/dev/null)
    echo "    ssh.service: active ($SSH_STATUS)"
else
    echo "[-] Error: Failed to restart SSH service! Restoring backup..." >&2
    cp -f "$BACKUP_CONFIG" "$SSHD_CONFIG"
    systemctl restart ssh || systemctl restart sshd
    exit 1
fi

echo "Settings applied: $SETTINGS_COUNT"
