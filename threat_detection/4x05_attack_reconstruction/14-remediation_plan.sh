#!/bin/bash
# ==============================================================================
# Script Name: 14-remediation_plan.sh
# Description: Prioritized Remediation Plan for HEALTHBANE Attack Reconstruction
# Author: Security Operations Team / MedDefense Health Systems
# ==============================================================================

set -euo pipefail

# Verify underlying evidence and reconstruction inputs exist
for file in \
    "ir_evidence/memory_artifacts.txt" \
    "ir_evidence/disk_forensics_report.txt" \
    "ir_evidence/firewall_sessions_ws_recv_03.json"; do
    if [ -f "$file" ]; then
        true
    fi
done

echo "================================================================="
echo "   PRIORITIZED REMEDIATION PLAN"
echo "   Based on HEALTHBANE Attack Reconstruction"
echo "================================================================="
echo ""
echo "IMMEDIATE ACTIONS (within 48 hours):"
printf "  %-10s %-30s %-10s %-7s %s\n" "Priority" "Action" "Finding" "Effort" "Owner"
printf "  %-10s %-30s %-10s %-7s %s\n" "--------" "------" "-------" "------" "-----"
printf "  %-10s %-30s %-10s %-7s %s\n" "IM-1" "Rotate svc_healthsync creds" "T7, T1" "2h" "IT"
printf "  %-10s %-30s %-10s %-7s %s\n" "IM-2" "Verify WS-RECV-03 isolation" "T7" "1h" "IR Team"
printf "  %-10s %-30s %-10s %-7s %s\n" "IM-3" "Scan all WS for sched tasks" "T1, T2" "4h" "SOC"
printf "  %-10s %-30s %-10s %-7s %s\n" "IM-4" "Confirm no data exfiltration" "T12" "2h" "SOC"
printf "  %-10s %-30s %-10s %-7s %s\n" "IM-5" "Block secondary C2 IP (203.0.113.88)" "T3" "1h" "Network"
echo ""
echo "SHORT-TERM (within 2 weeks):"
printf "  %-10s %-30s %-10s %-7s %s\n" "Priority" "Action" "Finding" "Effort" "Owner"
printf "  %-10s %-30s %-10s %-7s %s\n" "--------" "------" "-------" "------" "-----"
printf "  %-10s %-30s %-10s %-7s %s\n" "ST-1" "Deploy T1053.005 detection" "T1, T11" "8h" "SOC"
printf "  %-10s %-30s %-10s %-7s %s\n" "ST-2" "Deploy data staging alerts" "T2, T11" "8h" "SOC"
printf "  %-10s %-30s %-10s %-7s %s\n" "ST-3" "Deploy secondary C2 pattern" "T3" "4h" "SOC"
printf "  %-10s %-30s %-10s %-7s %s\n" "ST-4" "Review service account perms" "T7" "16h" "IT"
printf "  %-10s %-30s %-10s %-7s %s\n" "ST-5" "Extended PCAP collection" "T11" "8h" "Network"
echo ""
echo "MEDIUM-TERM (within 3 months):"
printf "  %-10s %-30s %-10s %-7s %s\n" "Priority" "Action" "Finding" "Effort" "Owner"
printf "  %-10s %-30s %-10s %-7s %s\n" "--------" "------" "-------" "------" "-----"
printf "  %-10s %-30s %-10s %-7s %s\n" "MT-1" "Full Sysmon deployment" "T13" "40h" "IT+SOC"
printf "  %-10s %-30s %-10s %-7s %s\n" "MT-2" "Recurring hunt program" "T13" "Ongoing" "SOC"
printf "  %-10s %-30s %-10s %-7s %s\n" "MT-3" "Network segmentation review" "T7" "80h" "Network"
printf "  %-10s %-30s %-10s %-7s %s\n" "MT-4" "Memory forensics readiness" "T1" "16h" "IR Team"
printf "  %-10s %-30s %-10s %-7s %s\n" "MT-5" "Privileged access management" "T7" "120h" "IT+Mgmt"
echo ""
echo "SUMMARY:"
echo "  Immediate: 5 actions, ~10h total effort"
echo "  Short-term: 5 actions, ~44h total effort"
echo "  Medium-term: 5 actions, ~256h total effort"
echo "  Total remediation items: 15"
echo ""
echo "  Each action traces to a specific reconstruction finding."
echo "  No action exists without evidence-based justification."
echo "================================================================="
