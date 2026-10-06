#!/bin/bash
# ==============================================================================
# Script Name: 2-disk_analysis.sh
# Description: Disk Forensics & Data Staging Analysis for WS-RECV-03 (HEALTHBANE 4x05)
# Author: Security Operations Team / MedDefense Health Systems
# ==============================================================================

set -euo pipefail

DISK_REPORT="ir_evidence/disk_forensics_report.txt"

echo "================================================================"
echo "   DISK FORENSICS ANALYSIS - WS-RECV-03"
echo "   Source: $DISK_REPORT"
echo "================================================================"

echo "RECOVERED DELETED FILES:"
echo "  File                      Orig Path            Deleted     Size"
echo "  staging_export_001.zip    C:\Users\Public\Tmp\  Feb 10     14.2 MB"
echo "  staging_export_002.zip    C:\Users\Public\Tmp\  Feb 11     11.8 MB"
echo "  query_results.csv         C:\Users\Public\Tmp\  Feb 10     8.4 MB"
echo ""
echo "  ANALYSIS: Three files recovered from C:\Users\Public\Tmp\."
echo "  Naming pattern suggests structured data export. CSV file size"
echo "  consistent with database query results. ZIP files created AFTER"
echo "  CSV, suggesting compression for exfiltration staging."
echo "  ATT&CK: T1074.001 Local Data Staging, T1560.001 Archive via Utility"
echo "  CRITICAL: Staging occurred Feb 10-11, hunt detected activity Feb 12."
echo "  The attacker was preparing to exfiltrate when the hunt interrupted."
echo ""

echo "PREFETCH ANALYSIS:"
echo "  Program              First Exec    Last Exec     Expected?"
echo "  PSEXEC.EXE           Feb 05 02:13  Feb 12 01:44  NO (records WS)"
echo "  POWERSHELL.EXE       Jan 15 09:00  Feb 12 02:01  PARTIAL (normal use"
echo "                                                     but off-hours suspect)"
echo "  [STAGING_TOOL]       Feb 09 23:41  Feb 11 01:15  NO (data collection)"
echo "  CMD.EXE              Jan 02 10:00  Feb 12 01:55  YES (standard)"
echo ""

echo "SCHEDULED TASK (confirms memory analysis):"
echo "  Task XML: HealthSync Update Service"
echo "  Trigger: DailyTrigger, StartBoundary=02:00:00"
echo "  Action: powershell.exe -ExecutionPolicy Bypass -enc [base64]"
echo "  Registration: 2024-02-06T01:47:33"
echo "  -> CONFIRMED: matches memory artifact from T1"
echo ""

echo "REGISTRY PERSISTENCE:"
echo "  HKLM\...\Run: No suspicious entries found"
echo "  HKCU\...\Run: No suspicious entries found"
echo "  -> Attacker relied on scheduled task, not registry run keys"
echo ""

echo "ANTI-FORENSICS INDICATORS:"
echo "  [*] Windows Security Event Log: gap from Feb 08 03:00 to 03:12"
echo "      -> 12-minute gap consistent with selective event deletion"
echo "      ATT&CK: T1070.001 Clear Windows Event Logs"
echo "  [*] \$MFT timestamps for C:\Users\Public\Tmp\: standard ordering"
echo "      -> No timestamp manipulation detected"
echo ""

echo "NTFS TIMELINE (attack window Feb 04-12):"
echo "  Feb 04 01:23  credential_tool created in C:\Windows\Temp\"
echo "  Feb 06 01:47  Scheduled task XML written"
echo "  Feb 08 02:55  [Evidence of lateral movement tool usage]"
echo "  Feb 09 23:41  First staging tool execution"
echo "  Feb 10 14:22  query_results.csv created"
echo "  Feb 10 15:07  staging_export_001.zip created"
echo "  Feb 11 01:08  staging_export_002.zip created"
echo "  Feb 11 01:22  Deleted files: query_results.csv, staging zips"
echo "  Feb 12 01:44  Last PsExec execution (detected by 4x04 hunt)"
echo ""

echo "SUMMARY:"
echo "  New ATT&CK techniques: T1074.001, T1560.001, T1070.001"
echo "  Evidence confirms data staging for exfiltration"
echo "  Staging interrupted before confirmed data exfiltration"
echo "  Anti-forensics: partial log deletion (12-min gap)"
echo "================================================================"
