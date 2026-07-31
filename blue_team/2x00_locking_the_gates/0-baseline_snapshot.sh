#!/bin/bash

# Task 0: The Baseline Snapshot
# Script: 0-baseline_snapshot.sh
# Description: Captures the complete security baseline of a Linux system into structured JSON and standard output.
# Addresses: MedDefense Infrastructure Hardening - Initial Baseline Assessment

OUTPUT_JSON="baseline_report.json"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Ensure script is run with root privileges for complete visibility
if [ "$EUID" -ne 0 ]; then
    echo "[-] Warning: Running without root privileges. Some security parameters, SUID files, and system states may be omitted." >&2
fi

# Gather System Identification
HOSTNAME=$(hostname)
OS_VERSION=$(grep -oP '(?<=PRETTY_NAME=")[^"]*' /etc/os-release 2>/dev/null || uname -o)
KERNEL_VERSION=$(uname -r)
UPTIME=$(uptime -p)

# Gather Running Services
RUNNING_SERVICES_COUNT=$(systemctl list-units --type=service --state=running --no-legend 2>/dev/null | wc -l)

# Gather Open Ports & Listening Sockets
if command -v ss &> /dev/null; then
    OPEN_PORTS_COUNT=$(ss -tuln 2>/dev/null | tail -n +2 | wc -l)
else
    OPEN_PORTS_COUNT=$(netstat -tuln 2>/dev/null | tail -n +3 | wc -l)
fi

# Gather SUID and SGID Binaries
SUID_COUNT=$(find / -xdev -type f -perm -4000 2>/dev/null | wc -l)
SGID_COUNT=$(find / -xdev -type f -perm -2000 2>/dev/null | wc -l)

# Gather World-Writable Files (excluding /proc, /sys, /dev)
WORLD_WRITABLE_COUNT=$(find / -xdev -type f -perm -0002 ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" 2>/dev/null | wc -l)

# Print Summary to STDOUT as requested by the expected output format
echo "Hostname: $HOSTNAME"
echo "OS: $OS_VERSION"
echo "Running services: $RUNNING_SERVICES_COUNT"
echo "Open ports: $OPEN_PORTS_COUNT"
echo "SUID binaries: $SUID_COUNT"
echo "SGID binaries: $SGID_COUNT"
echo "World-writable files: $WORLD_WRITABLE_COUNT"

# Generate structured JSON output for automated tracking and delta comparisons
cat << EOF > "$OUTPUT_JSON"
{
  "timestamp": "$TIMESTAMP",
  "system_identification": {
    "hostname": "$HOSTNAME",
    "os_version": "$OS_VERSION",
    "kernel_version": "$KERNEL_VERSION",
    "uptime": "$UPTIME"
  },
  "metrics": {
    "running_services": $RUNNING_SERVICES_COUNT,
    "open_ports": $OPEN_PORTS_COUNT,
    "suid_binaries": $SUID_COUNT,
    "sgid_binaries": $SGID_COUNT,
    "world_writable_files": $WORLD_WRITABLE_COUNT
  }
}
EOF

echo "[+] Baseline snapshot saved to $OUTPUT_JSON"
