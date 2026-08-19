#!/bin/bash
# Exit codes: 0 = success, 1 = check failed, 2 = environment error
set -euo pipefail

TARGET_STATE_FILE="capstone/target_state.json"
CAPSTONE_DIR="capstone"

FORCE=false
if [[ "${1:-}" == "--force" ]]; then
    FORCE=true
fi

mkdir -p "$CAPSTONE_DIR"

if [[ -f "$TARGET_STATE_FILE" ]] && [[ "$FORCE" == "false" ]]; then
    echo "[-] Error: $TARGET_STATE_FILE already exists. Use --force to overwrite." >&2
    exit 1
fi

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

cat << EOF > "$TARGET_STATE_FILE"
{
  "schema_version": "1.0.0",
  "generated_at": "$TIMESTAMP",
  "controls": [
    {
      "id": "LNX-SSH-01",
      "platform": "linux",
      "family": "hardening",
      "description": "SSH must refuse root login",
      "check_type": "json_field_equals",
      "check_target": "sshd_config.PermitRootLogin",
      "expected_value": "no",
      "source_project": "2x00_linux_hardening",
      "severity": "critical"
    },
    {
      "id": "LNX-SSH-02",
      "platform": "linux",
      "family": "hardening",
      "description": "SSH must refuse password authentication",
      "check_type": "json_field_equals",
      "check_target": "sshd_config.PasswordAuthentication",
      "expected_value": "no",
      "source_project": "2x00_linux_hardening",
      "severity": "high"
    },
    {
      "id": "LNX-SYS-01",
      "platform": "linux",
      "family": "hardening",
      "description": "sysctl net.ipv4.ip_forward must be 0",
      "check_type": "json_field_equals",
      "check_target": "sysctl_parameters.net.ipv4.ip_forward",
      "expected_value": "0",
      "source_project": "2x00_linux_hardening",
      "severity": "high"
    },
    {
      "id": "LNX-SYS-02",
      "platform": "linux",
      "family": "hardening",
      "description": "sysctl kernel.randomize_va_space must be set to 2",
      "check_type": "json_field_equals",
      "check_target": "sysctl_parameters.kernel.randomize_va_space",
      "expected_value": "2",
      "source_project": "2x00_linux_hardening",
      "severity": "high"
    },
    {
      "id": "LNX-TEL-01",
      "platform": "linux",
      "family": "telemetry",
      "description": "auditd service active and rules loaded",
      "check_type": "command_exit_zero",
      "check_target": "systemctl is-active auditd",
      "expected_value": "active",
      "source_project": "2x02_telemetry",
      "severity": "high"
    },
    {
      "id": "LNX-APP-01",
      "platform": "linux",
      "family": "hardening",
      "description": "apparmor enforce mode enabled",
      "check_type": "command_exit_zero",
      "check_target": "aa-status --enabled",
      "expected_value": "enforce",
      "source_project": "2x00_linux_hardening",
      "severity": "medium"
    },
    {
      "id": "LNX-BAS-01",
      "platform": "linux",
      "family": "hardening",
      "description": "Lynis hardening index at least 80",
      "check_type": "json_field_gte",
      "check_target": "hardening_index",
      "expected_value": 80,
      "source_project": "2x00_linux_hardening",
      "severity": "medium"
    },
    {
      "id": "WIN-FW-01",
      "platform": "windows",
      "family": "hardening",
      "description": "Windows Firewall default-deny inbound on every profile",
      "check_type": "json_field_equals",
      "check_target": "FirewallProfiles.DefaultInboundAction",
      "expected_value": "Block",
      "source_project": "2x01_windows_hardening",
      "severity": "critical"
    },
    {
      "id": "WIN-BAS-01",
      "platform": "windows",
      "family": "hardening",
      "description": "CIS Level 1 pass rate at least 85 percent",
      "check_type": "json_field_gte",
      "check_target": "pass_rate_percent",
      "expected_value": 85.0,
      "source_project": "2x01_windows_hardening",
      "severity": "medium"
    },
    {
      "id": "WIN-TEL-01",
      "platform": "windows",
      "family": "telemetry",
      "description": "Script Block Logging enabled",
      "check_type": "json_field_equals",
      "check_target": "PowerShellLogging.ScriptBlockLogging",
      "expected_value": 1,
      "source_project": "2x02_telemetry",
      "severity": "high"
    },
    {
      "id": "WIN-TEL-02",
      "platform": "windows",
      "family": "telemetry",
      "description": "Sysmon service installed and running",
      "check_type": "json_field_equals",
      "check_target": "Sysmon.Status",
      "expected_value": "Running",
      "source_project": "2x02_telemetry",
      "severity": "high"
    },
    {
      "id": "WIN-TEL-03",
      "platform": "windows",
      "family": "telemetry",
      "description": "Windows Sysmon event count greater than zero in the last 10 minutes",
      "check_type": "json_field_gte",
      "check_target": "Sysmon.MaxChannelSize",
      "expected_value": 1,
      "source_project": "2x02_telemetry",
      "severity": "medium"
    },
    {
      "id": "WIN-TEL-04",
      "platform": "windows",
      "family": "telemetry",
      "description": "Script Block Logging event channel size greater than zero",
      "check_type": "json_field_gte",
      "check_target": "PowerShellLogging.ScriptBlockLogging",
      "expected_value": 1,
      "source_project": "2x02_telemetry",
      "severity": "medium"
    },
    {
      "id": "WIN-AUD-01",
      "platform": "windows",
      "family": "telemetry",
      "description": "audit policy covers Account Logon, Logon, Object Access and Privilege Use subcategories",
      "check_type": "file_exists",
      "check_target": "capstone/baseline/windows_baseline.log",
      "expected_value": "true",
      "source_project": "2x02_telemetry",
      "severity": "medium"
    },
    {
      "id": "LNX-AUD-01",
      "platform": "linux",
      "family": "telemetry",
      "description": "Linux auditd rules file present and loaded",
      "check_type": "file_exists",
      "check_target": "/etc/audit/rules.d/audit.rules",
      "expected_value": "true",
      "source_project": "2x02_telemetry",
      "severity": "high"
    },
    {
      "id": "LNX-EXP-01",
      "platform": "linux",
      "family": "telemetry",
      "description": "structured JSON export path exists",
      "check_type": "file_exists",
      "check_target": "/var/log/meddefense_intake_linux.json",
      "expected_value": "true",
      "source_project": "2x02_telemetry",
      "severity": "medium"
    },
    {
      "id": "PTC-INV-01",
      "platform": "both",
      "family": "patching",
      "description": "vulnerability_inventory.json present",
      "check_type": "file_exists",
      "check_target": "capstone/patching/vulnerability_inventory.json",
      "expected_value": "true",
      "source_project": "2x03_patch_management",
      "severity": "medium"
    },
    {
      "id": "PTC-PLN-01",
      "platform": "both",
      "family": "patching",
      "description": "patch_plan.json present",
      "check_type": "file_exists",
      "check_target": "capstone/patching/patch_plan.json",
      "expected_value": "true",
      "source_project": "2x03_patch_management",
      "severity": "medium"
    },
    {
      "id": "PTC-LOG-01",
      "platform": "both",
      "family": "patching",
      "description": "patch_execution_log.json present with zero entries in failed state",
      "check_type": "file_exists",
      "check_target": "capstone/patching/patch_execution_log.json",
      "expected_value": "true",
      "source_project": "2x03_patch_management",
      "severity": "high"
    },
    {
      "id": "PTC-UPG-01",
      "platform": "linux",
      "family": "patching",
      "description": "unattended-upgrades configured with the mandated blacklist",
      "check_type": "file_exists",
      "check_target": "/etc/apt/apt.conf.d/50unattended-upgrades",
      "expected_value": "true",
      "source_project": "2x03_patch_management",
      "severity": "medium"
    },
    {
      "id": "NET-NFT-01",
      "platform": "network",
      "family": "network",
      "description": "nftables ruleset loaded with default-deny inbound",
      "check_type": "grep_match",
      "check_target": "/etc/nftables.conf",
      "expected_value": "policy drop",
      "source_project": "2x04_perimeter_defense",
      "severity": "critical"
    },
    {
      "id": "NET-SEG-01",
      "platform": "network",
      "family": "network",
      "description": "segmentation_rules.json present",
      "check_type": "file_exists",
      "check_target": "capstone/network/segmentation_rules.json",
      "expected_value": "true",
      "source_project": "2x04_perimeter_defense",
      "severity": "medium"
    },
    {
      "id": "NET-SUR-01",
      "platform": "network",
      "family": "network",
      "description": "Suricata custom rule file loaded with at least six rules",
      "check_type": "file_exists",
      "check_target": "/etc/suricata/rules/custom.rules",
      "expected_value": "true",
      "source_project": "2x04_perimeter_defense",
      "severity": "high"
    },
    {
      "id": "NET-SUR-02",
      "platform": "network",
      "family": "network",
      "description": "Suricata rule validation report shows every rule fired against its target PCAP",
      "check_type": "file_exists",
      "check_target": "capstone/network/suricata_validation.json",
      "expected_value": "true",
      "source_project": "2x04_perimeter_defense",
      "severity": "medium"
    },
    {
      "id": "NET-DNS-01",
      "platform": "network",
      "family": "network",
      "description": "DNS filter active",
      "check_type": "command_exit_zero",
      "check_target": "systemctl is-active pihole || systemctl is-active bind9",
      "expected_value": "active",
      "source_project": "2x04_perimeter_defense",
      "severity": "medium"
    },
    {
      "id": "HND-CMP-01",
      "platform": "both",
      "family": "handoff",
      "description": "compliance.json present",
      "check_type": "file_exists",
      "check_target": "capstone/compliance.json",
      "expected_value": "true",
      "source_project": "2x05_defensible_endpoint",
      "severity": "high"
    },
    {
      "id": "HND-MAN-01",
      "platform": "both",
      "family": "handoff",
      "description": "manifest.json present with SHA-256 per file",
      "check_type": "file_exists",
      "check_target": "capstone/manifest.json",
      "expected_value": "true",
      "source_project": "2x05_defensible_endpoint",
      "severity": "critical"
    },
    {
      "id": "HND-PKG-01",
      "platform": "both",
      "family": "handoff",
      "description": "telemetry export package exists and is tarballed",
      "check_type": "file_exists",
      "check_target": "capstone/telemetry_export.tar.gz",
      "expected_value": "true",
      "source_project": "2x05_defensible_endpoint",
      "severity": "high"
    },
    {
      "id": "HND-RUN-01",
      "platform": "both",
      "family": "handoff",
      "description": "runbook script present and executable",
      "check_type": "file_exists",
      "check_target": "capstone/runbook.sh",
      "expected_value": "true",
      "source_project": "2x05_defensible_endpoint",
      "severity": "high"
    }
  ]
}
EOF

echo "[+] Target state contract successfully generated at capstone/target_state.json"
exit 0
exit 1
exit 2
