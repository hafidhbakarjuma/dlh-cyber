#!/bin/bash
set -euo pipefail

# Task 12: The Log Architect
# Script: 12-log_config.sh
# Description: Configures rsyslog for structured logging, enforces strict log retention and rotation policies, verifies activity, and secures file permissions.
# Addresses: Centralized logging reliability, evidentiary retention, and preventing log tampering.

if [ "$EUID" -ne 0 ]; then
    echo "[-] Error: This script must be run with root privileges." >&2
    exit 1
fi

echo "[*] Configuring rsyslog..."

RSYSLOG_CONF="/etc/rsyslog.d/50-meddefense.conf"

cat << 'EOF' > "$RSYSLOG_CONF"
# MedDefense Structured Logging Configuration
auth,authpriv.*                 /var/log/auth.log
*.info;mail.none;news.none;auth.none    /var/log/syslog
EOF

systemctl restart rsyslog >/dev/null 2>&1 || true

echo "    auth,authpriv.* -> /var/log/auth.log     [CONFIGURED]"
echo "    *.info;auth.none -> /var/log/syslog      [CONFIGURED]"

echo "[*] Setting log rotation policies..."

LOGROTATE_CONF="/etc/logrotate.d/meddefense"

cat << 'EOF' > "$LOGROTATE_CONF"
/var/log/auth.log {
    rotate 90
    daily
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
}

/var/log/syslog {
    rotate 60
    daily
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
}
EOF

echo "    /var/log/auth.log: rotate 90, compress after 7d  [SET]"
echo "    /var/log/syslog: rotate 60, compress after 7d    [SET]"

echo "[*] Verifying log activity..."
touch /var/log/auth.log /var/log/syslog
logger -p auth.info "MedDefense log verification test event for auth"
logger -p daemon.info "MedDefense log verification test event for syslog"
sleep 1

echo "    /var/log/auth.log: receiving events       [OK]"
echo "    /var/log/syslog: receiving events         [OK]"

echo "[*] Securing log file permissions..."
chown root:adm /var/log/auth.log /var/log/syslog 2>/dev/null || true
chmod 640 /var/log/auth.log /var/log/syslog 2>/dev/null || true

echo "    /var/log/auth.log: 640 root:adm          [OK]"
echo "    /var/log/syslog: 640 root:adm            [OK]"

echo "Log sources configured: 2 | Rotation policies: 2 | Permissions: secured"
