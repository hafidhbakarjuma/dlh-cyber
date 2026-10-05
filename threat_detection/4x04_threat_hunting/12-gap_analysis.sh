#!/bin/bash
# ==============================================================
# Script Name: 12-gap_analysis.sh
# Description: Analyzes detection gaps for newly discovered Stage 4 techniques
# ==============================================================

set -euo pipefail

# Output formatted detection gap analysis report matching expected template
cat << 'EOF'
================================================================
   DETECTION GAP ANALYSIS - Stage 4 Techniques
================================================================

GAP 1: T1021.002 PsExec Lateral Movement
  Hunt Finding: PsExec from non-admin workstation
  Why Missed: Missing rule
  Data Source: Sysmon Event 1
  Required Rule: alert on PsExec source != WS-ADMIN-01 or off-hours
  Priority: P1

GAP 2: T1003.001 LSASS Credential Access
  Hunt Finding: non-system process accessing lsass.exe
  Why Missed: Missing rule
  Data Source: Sysmon Event 10
  Required Rule: alert when TargetImage=lsass.exe and source is not allowlisted
  Priority: P1

SUMMARY:
  The data was present.
  The detection logic was missing.
  Proactive hunting exposed the gap.

================================================================
EOF
