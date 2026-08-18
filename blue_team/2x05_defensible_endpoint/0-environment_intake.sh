#!/bin/bash
# Exit codes: 0 = success, 1 = check failed, 2 = environment error
# Capstone environment intake script for Linux endpoint (hawthorne-app-01)
set -euo pipefail

OUTPUT_FILE="/var/log/meddefense_intake_linux.json"

if [[ $EUID -ne 0 ]]; then
    echo "[-] Error: This script must be run as root." >&2
    exit 2
fi

# Capture core system attributes
HOSTNAME=$(hostname)
KERNEL=$(uname -r)
DISTRO=$(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')
PKG_COUNT=$(dpkg-query -W -f='${Package}\n' | wc -l)
LISTENING_SOCKETS=$(ss -tulnpH | wc -l)
ACTIVE_SERVICES=$(systemctl list-units --type=service --state=running --no-legend | wc -l)
SUID_COUNT=$(find / -perm /6000 -type f 2>/dev/null | wc -l)
WORLD_WRITABLE=$(find / -perm -0002 -type f ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | wc -l)
NFT_RULES=$(nft list ruleset 2>/dev/null | wc -l)

# Telemetry presence checks (explicitly verifying auditd, rsyslog, and Sysmon)
AUDITD_RUNNING=$(systemctl is-active auditd 2>/dev/null || echo "inactive")
RSYSLOG_RUNNING=$(systemctl is-active rsyslog 2>/dev/null || echo "inactive")
SYSMON_PRESENT=$(systemctl is-active sysmonlinux 2>/dev/null || echo "not_installed")

# Capture current sshd_config as a key-value record safely
SSHD_CONFIG_JSON="{}"
if [[ -f /etc/ssh/sshd_config ]]; then
    SSHD_CONFIG_JSON=$(grep -E '^\s*[a-zA-Z0-9]+' /etc/ssh/sshd_config | awk '{print "\"" $1 "\": \"" $2 "\""}' | jq -s 'from_entries' 2>/dev/null || echo "{}")
else
    echo "[-] Warning: /etc/ssh/sshd_config not found." >&2
    exit 1
fi

# Capture current sysctl security parameters including net.ipv4.ip_forward and kernel.randomize_va_space explicitly
SYSCTL_JSON="{}"
if command -v sysctl &> /dev/null; then
    IP_FORWARD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "0")
    RAND_VA_SPACE=$(sysctl -n kernel.randomize_va_space 2>/dev/null || echo "2")
    
    SYSCTL_JSON=$(sysctl -a 2>/dev/null | sed 's/[[:space:]]*=[[:space:]]*/:/' | awk -F: '{print "\"" $1 "\": \"" $2 "\""}' | jq -s --arg ipf "$IP_FORWARD" --arg rvas "$RAND_VA_SPACE" 'from_entries + {"net.ipv4.ip_forward": $ipf, "kernel.randomize_va_space": $rvas}' 2>/dev/null || echo "{}")
else
    echo "[-] Error: sysctl command not found." >&2
    exit 1
fi

# Explicit validation check to ensure config extraction succeeded and return exit 1 on check failure
if [[ "$SSHD_CONFIG_JSON" == "{}" ]] || [[ "$SYSCTL_JSON" == "{}" ]]; then
    echo "[-] Check failed: Failed to parse sshd_config or sysctl parameters." >&2
    exit 1
fi

cat <<EOF > "$OUTPUT_FILE"
{
  "capstone_project": "meddefense_hawthorne_endpoint",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "hostname": "$HOSTNAME",
  "kernel": "$KERNEL",
  "distribution": "$DISTRO",
  "package_count": $PKG_COUNT,
  "listening_sockets": $LISTENING_SOCKETS,
  "active_services": $ACTIVE_SERVICES,
  "suid_sgid_count": $SUID_COUNT,
  "world_writable_count": $WORLD_WRITABLE,
  "nft_rules_count": $NFT_RULES,
  "sshd_config": $SSHD_CONFIG_JSON,
  "sysctl_parameters": $SYSCTL_JSON,
  "telemetry": {
    "auditd": "$AUDITD_RUNNING",
    "rsyslog": "$RSYSLOG_RUNNING",
    "sysmon": "$SYSMON_PRESENT"
  }
}
EOF

echo "[+] Linux intake record successfully written to $OUTPUT_FILE"
exit 0
