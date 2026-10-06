#!/bin/bash
# ==============================================================================
# Script Name: 4-correlation_matrix.sh
# Description: Cross-Evidence Correlation & Synthesis Matrix for HEALTHBANE 4x05
# Author: Security Operations Team / MedDefense Health Systems
# ==============================================================================

set -euo pipefail

echo "================================================================="
echo "   CROSS-EVIDENCE CORRELATION MATRIX"
echo "   Sources: 4x00 through 4x05-IR (11 evidence files)"
echo "================================================================="
echo ""

echo "IOC CORRELATION:"
echo "  IOC                    4x00  4x01  4x02  4x03  4x04  IR    Status"
echo "  meddefense-secure.com  YES   ---   YES   ---   ---   ---   CONVERGED"
echo "  198.51.100.45 (C2_IP)  ---   YES   YES   YES   ---   YES   CONVERGED"
echo "  203.0.113.88 (Sec C2)  ---   ---   ---   ---   ---   YES   SINGLE-SOURCE"
echo "  svchostupdate.exe      ---   ---   YES   YES   ---   YES   CONVERGED"
echo "  svc_healthsync (User)  ---   ---   ---   ---   YES   YES   CONVERGED"
echo "  staging_export_001.zip ---   ---   ---   ---   ---   YES   SINGLE-SOURCE"
echo ""
echo "  Summary: 4 CONVERGED, 2 SINGLE-SOURCE, 0 CONFLICTED"
echo "  New IOCs from IR: 2 (203.0.113.88, staging_export_*.zip)"
echo ""

echo "TIMELINE CORRELATION:"
echo "  Event                  Sources              Confidence  Notes"
echo "  Phishing delivery      4x00                 HIGH        Primary evidence"
echo "  Credential theft       4x00,4x01            CONVERGED   Timestamps match"
echo "  C2 establishment       4x01,IR-FW           CONVERGED   4s clock skew"
echo "  Malware deployment     4x03,IR-MEM          CONVERGED   Process confirmed"
echo "  Persistence install    IR-MEM,IR-DISK       CONVERGED   Feb 06 01:47"
echo "  Lateral mvmt start     4x04,IR-FW           CONVERGED   Feb 05"
echo "  Data staging           IR-DISK              SINGLE      Feb 10-11"
echo ""
echo "  CONTRADICTION RESOLVED:"
echo "  -> 4x01 network timeline shows C2 beacon start at 01:14:20"
echo "  -> IR firewall shows first C2 session at 01:14:16"
echo "  -> Resolution: Firewall records TCP SYN (connection start),"
echo "     PCAP captured mid-session. 4s difference is consistent"
echo "     with normal collection point variance. Firewall timestamp"
echo "     adopted as authoritative for connection initiation."
echo ""

echo "TECHNIQUE CORRELATION:"
echo "  Technique              4x02    4x04    IR      Update"
echo "  T1566.001 Phishing     CONF    ---     ---     No change"
echo "  T1071.001 Web Proto    CONF    ---     CONF    Confidence +"
echo "  T1021.002 PsExec       INFER   CONF    CONF    UPGRADED"
echo "  T1053.005 Sched Task   ---     ---     CONF    NEW"
echo "  T1074.001 Data Staging ---     ---     CONF    NEW"
echo "  T1070.001 Log Clear    ---     ---     PROB    NEW"
echo ""
echo "  Techniques UPGRADED from INFERRED to CONFIRMED: 1 (T1021.002 PsExec)"
echo "  Techniques newly identified from IR evidence: 3 (T1053.005, T1074.001, T1070.001)"
echo "  Techniques CORRECTED (4x02 inference was wrong): 0"
echo "================================================================="
