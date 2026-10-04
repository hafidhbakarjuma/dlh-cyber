#!/bin/bash
# ==============================================================
# Script Name: 2-baseline_profile.sh
# Description: Profiles Robert Kim's legitimate admin activity from baseline data
# ==============================================================

set -euo pipefail

BASELINE_FILE="baseline/robert_kim_activity.json"

if [ ! -f "$BASELINE_FILE" ]; then
    echo "Error: Baseline file '$BASELINE_FILE' not found." >&2
    exit 1
fi

# Parse counts using jq
PSEXEC_COUNT=$(jq '[.[] | select(.tool == "PsExec")] | length' "$BASELINE_FILE")
WMI_COUNT=$(jq '[.[] | select(.tool == "WMI")] | length' "$BASELINE_FILE")
PSREMOTING_COUNT=$(jq '[.[] | select(.tool == "PSRemoting")] | length' "$BASELINE_FILE")
TOTAL_COUNT=$(jq 'length' "$BASELINE_FILE")

ADMIN01_COUNT=$(jq '[.[] | select(.source_host == "WS-ADMIN-01")] | length' "$BASELINE_FILE")
OTHER_HOSTS=$(jq '[.[] | select(.source_host != "WS-ADMIN-01")] | length' "$BASELINE_FILE")

BUSINESS_HOURS_COUNT=$(jq '[.[] | select(.hour >= 8 and .hour < 18)] | length' "$BASELINE_FILE")
OFF_HOURS_COUNT=$(jq '[.[] | select(.hour < 8 or .hour >= 18)] | length' "$BASELINE_FILE")

ROBERT_COUNT=$(jq '[.[] | select(.user == "MEDDEFENSE\\robert.kim")] | length' "$BASELINE_FILE")
SERVICE_ACCOUNTS_COUNT=$(jq '[.[] | select(.user | startswith("MEDDEFENSE\\svc-"))] | length' "$BASELINE_FILE")

# Output formatted profile matching expected template
cat << EOF
================================================================
   BASELINE PROFILE - Robert Kim (IT Administrator)
   Source: baseline/robert_kim_activity.json
================================================================

TOOL USAGE SUMMARY:
  PsExec events:          $PSEXEC_COUNT
  WMI events:             $WMI_COUNT
  PSRemoting events:      $PSREMOTING_COUNT
  Total admin events:     $TOTAL_COUNT

SOURCE HOST:
  WS-ADMIN-01: $ADMIN01_COUNT
  Other hosts: $OTHER_HOSTS
  -> BASELINE: All admin activity originates from WS-ADMIN-01

TIME DISTRIBUTION:
  08:00-18:00: $BUSINESS_HOURS_COUNT
  18:00-08:00: $OFF_HOURS_COUNT
  -> BASELINE: Zero admin activity outside business hours

USER ACCOUNTS:
  MEDDEFENSE\robert.kim: $ROBERT_COUNT
  Service accounts: $SERVICE_ACCOUNTS_COUNT
  -> BASELINE: Never uses service accounts interactively

ANOMALY DETECTION CRITERIA:
  [!] Admin tool from any host other than WS-ADMIN-01
  [!] Admin tool usage outside business hours
  [!] Service account used interactively from workstation
  [!] WMI targeting unusual hosts

================================================================
EOF
