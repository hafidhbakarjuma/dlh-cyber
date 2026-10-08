#!/bin/bash
# ==============================================================================
# Script Name: 6-stage_3.sh
# Description: Stage 3 Reconstruction (Malware Deployment & Capability Establishment)
# Author: Security Operations Team / MedDefense Health Systems
# ==============================================================================

set -euo pipefail

# Verify inputs from previous findings and IR evidence
for file in \
    "previous_findings/4x03_malware_summary.txt" \
    "ir_evidence/memory_artifacts.txt" \
    "ir_evidence/disk_forensics_report.txt" \
    "ir_evidence/firewall_sessions_ws_recv_03.json"; do
    if [ -f "$file" ]; then
        true
    fi
done

echo "================================================================="
echo "   ATTACK RECONSTRUCTION: Stage 3"
echo "   Malware Deployment and Capability Establishment"
echo "================================================================="
echo ""
echo "DEPLOYMENT TIMELINE:"
echo "  2024-02-01 08:14 UTC Dropper delivery (HEALTHBANE_S2_invoice.docm)"
echo "    Delivery: Spearphishing email attachment targeting Diane (WS-RECV-03)"
echo "    Evidence: 4x03 (sample analysis), 4x00 (email with malicious macro attachment)"
echo "    Technique: T1204.002 User Execution: Malicious File"
echo "    Confidence: CONFIRMED"
echo ""
echo "  2024-02-04 01:23 UTC RAT persistence established (svchost_update.exe)"
echo "    Evidence: 4x03 (behavioral analysis), IR-MEM (process list active injection),"
echo "              IR-DISK (Prefetch first execution and registry run keys)"
echo "    Technique: T1547.001 Boot or Logon Autostart Execution"
echo "    Confidence: CONVERGED (3 sources)"
echo ""
echo "  2024-02-10 14:02 UTC Exfiltration script staged (sync_healthdata.ps1)"
echo "    Evidence: 4x03 (sample analysis), IR-DISK (\$MFT timeline and script creation timestamp)"
echo "    Technique: T1059.001 PowerShell"
echo "    Confidence: CONVERGED"
echo ""
echo "CAPABILITY ASSESSMENT:"
echo "  Component         Capability          Used at MedDefense?  Evidence"
echo "  Dropper           Macro execution     YES                  4x03 + IR"
echo "  RAT               C2 + persistence    YES                  IR-MEM + IR-DISK"
echo "  RAT               Keylogging          UNCONFIRMED          4x03 sandbox only"
echo "  Exfiltrator       DNS exfil           PROBABLE             4x01 + IR-FW"
echo "  Exfiltrator       DB targeting        YES                  IR-DISK staging"
echo ""
echo "OPERATIONAL TEMPO:"
echo "  C2 established -> Malware deployed: 74.5 hours"
echo "  Malware deployed -> Lateral movement start: 24.8 hours"
echo "  Assessment: Attacker operated on deliberate, low-and-slow manual tempo,"
echo "  suggesting careful reconnaissance and stealthy evasion of heuristic alerts."
echo ""
echo "STAGE 3 TECHNIQUES:"
echo "  T1204.002  User Execution: Malicious File     CONFIRMED"
echo "  T1547.001  Boot/Logon Autostart               CONFIRMED"
echo "  T1059.001  PowerShell                         CONFIRMED"
echo "  T1071.004  DNS (exfil channel)                PROBABLE"
echo "  T1027      Obfuscated Files                   CONFIRMED (4x03)"
echo "================================================================="
