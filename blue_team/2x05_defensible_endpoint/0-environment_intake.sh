#!/bin/bash
# Exit codes: 0 = success, 1 = check failed, 2 = environment error
set -euo pipefail

OUTPUT_FILE="/var/log/meddefense_intake_linux.json"

if [[ $EUID -ne 0 ]]; then
    echo "[-] Error: This script must be run as root." >&2
    exit 2
fi

# Capture system attributes
HOSTNAME=$(hostname)
KERNEL=$(uname -r)
DISTRO=$(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')
PKG_COUNT=$(dpkg-query -W -f='${Package}\n' | wc -l)
LISTENING_SOCKETS=$(ss -tulnpH | wc -l)
ACTIVE_SERVICES=$(systemctl list-units --type=service --state=running --no-legend | wc -l)
SUID_COUNT=$(find / -perm /6000 -type f 2>/dev/null | wc -l)
WORLD_WRITABLE=$(find / -perm -0002 -type f ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | wc -l)
NFT_RULES=$(nft list ruleset 2>/dev/null | wc -l)

# Telemetry presence checks
AUDITD_RUNNING=$(systemctl is-active auditd 2>/dev/null || echo "inactive")
RSYSLOG_RUNNING=$(systemctl is-active rsyslog 2>/dev/null || echo "inactive")
SYSMON_PRESENT=$(systemctl is-active sysmonlinux 2>/dev/null || echo "not_installed")

# Format sshd_config as key-value JSON entries (ignoring comments/blanks)
SSHD_CONFIG_JSON="{}"
if [[ -f /etc/ssh/sshd_config ]]; then
    SSHD_CONFIG_JSON=$(grep -E '^\s*[a-zA-Z0-9]+' /etc/ssh/sshd_config | awk '{print "\"" $1 "\": \"" $2 "\""}' | jq -s '.' 2>/dev/null || echo "{}")
fi

# Format sysctl parameters as key-value JSON entries
SYSCTL_JSON="{}"
if command -v sysctl &> /dev/null; then
    SYSCTL_JSON=$(sysctl -a 2>/dev/null | sed 's/[[:space:]]*=[[:space:]]*/:/' | awk -F: '{print "\"" $1 "\": \"" $2 "\""}' | jq -s 'from_entries' 2>/dev/null || echo "{}")
fi

cat <<EOF > "$OUTPUT_FILE"
{
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
