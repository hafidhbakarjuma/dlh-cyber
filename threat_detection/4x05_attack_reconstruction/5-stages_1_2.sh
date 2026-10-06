#!/bin/bash
# ==============================================================================
# Script Name: 5-stages_1_2.sh
# Description: Attack Reconstruction Stages 1-2 (Initial Access & C2 Establishment)
# Author: Security Operations Team / MedDefense Health Systems
# ==============================================================================

set -euo pipefail

echo "================================================================"
echo "   ATTACK RECONSTRUCTION: Stages 1-2"
echo "   Initial Access through C2 Establishment"
echo "================================================================"

echo "STAGE 1: INITIAL ACCESS (Phishing Campaign)"
echo "  Timeline: Week 11 (campaign active: Feb 01 - Feb 03, 2024)"
echo ""
echo "  [2024-02-01T08:14:22Z] Campaign emails delivered to MedDefense staff"
echo "    Evidence: 4x00 email batch analysis (8 emails, 3 malicious)"
echo "    Technique: T1566.001 Spearphishing Link"
echo "    Confidence: CONFIRMED (primary email evidence)"
echo ""
echo "  [2024-02-01T09:22:15Z] Diane (WS-RECV-03) clicks credential harvesting link"
echo "    Evidence: 4x00 investigation (URL analysis, domain registration)"
echo "    Technique: T1566.001 -> credential input on lookalike portal"
echo "    Confidence: CONFIRMED (user report + browser history)"
echo ""
echo "  [2024-02-01T09:23:40Z] Credentials submitted to attacker-controlled domain"
echo "    Evidence: 4x00 (domain analysis), 4x01 (POST request in PCAP)"
echo "    Technique: T1078 Valid Accounts (obtained via phishing)"
echo "    Confidence: CONVERGED (2 independent sources)"

echo ""
echo "STAGE 2: C2 ESTABLISHMENT"
echo "  Timeline: Feb 01, 2024 (approximately 1.5 hours after credential theft)"
echo ""
echo "  [2024-02-01T10:55:12Z] First C2 beacon from WS-RECV-03"
echo "    Evidence: 4x01 (PCAP beacon analysis), IR-FW (session log)"
echo "    Technique: T1071.001 Application Layer Protocol: Web"
echo "    Confidence: CONVERGED (PCAP + firewall, 4s clock skew resolved)"
echo ""
echo "  [2024-02-01T11:00:00Z] C2 channel established: HTTPS to 198.51.100.45:443"
echo "    Evidence: 4x01 (5-min beacon interval), IR-FW (session pattern)"
echo "    Pattern: 300-second interval beacon, ~4,200 bytes per session"
echo "    Confidence: CONFIRMED"
echo ""
echo "  [2024-02-06T02:12:00Z] Secondary C2 channel to 203.0.113.88:8443"
echo "    Evidence: IR-FW only (first session: Feb 06 02:12)"
echo "    Note: NOT visible in 4x01 PCAPs (collection ended before Feb 06)"
echo "    Technique: T1071.001 (secondary channel)"
echo "    Confidence: PROBABLE (single source, but pattern consistent)"

echo ""
echo "STAGE 1-2 SUMMARY:"
echo "  Duration: ~2.7 hours from initial phishing click to established C2"
echo "  Techniques mapped: T1566.001, T1078, T1071.001, T1573.001"
echo "  IOCs: 4 (converged: 3, single-source: 1)"
echo "  Key finding: Secondary C2 at 203.0.113.88 was NOT operational"
echo "  during Stage 2. First appeared Feb 06, suggesting attacker"
echo "  deployed backup infrastructure after establishing persistence."
echo "================================================================"
