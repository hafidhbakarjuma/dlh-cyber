#!/bin/bash
# ==============================================================================
# Script Name: 8-evidence_crosscheck.sh
# Description: Correlates every PCAP finding with the expected investigation story 
#              to separate confirmed packet facts from analytical inference.
# Usage: ./8-evidence_crosscheck.sh
# ==============================================================================

set -euo pipefail

cat << 'EOF'
================================================================
   EVIDENCE CROSS-CHECK - PCAP VISIBILITY
================================================================

Phase | Attack Action         | PCAP Evidence? | Verdict
------|-----------------------|----------------|------------------
  1   | Phishing delivery     | No             | 4x00 CONTEXT
  2   | Credential harvest    | Yes            | STRONG INFERENCE
  3   | C2 beaconing          | Yes            | CONFIRMED
  4   | VPN pivot             | Yes            | STRONG INFERENCE
  5   | RDP lateral movement  | Yes            | CONFIRMED
  6   | SMB discovery         | Yes            | CONFIRMED
  7   | DNS exfiltration      | Yes            | CONFIRMED

=== CONFIRMED FROM PCAP ===
- DNS query for meddefense-portal.com
- TLS connection to 91.234.99.107
- Repeated 300-second HTTPS beaconing pattern
- VPN connection from 154.118.42.89
- RDP session from clinical host to billing server
- SMB enumeration activity
- DNS TXT tunneling pattern to data-sync.meddefense-portal.com

=== STRONG INFERENCE ===
- Credential submission through phishing page
- Use of stolen dmarsh credentials for VPN access
- Exfiltrated data content based on decoded DNS labels or tunnel structure

=== CANNOT CONFIRM FROM PCAP ALONE ===
- Exact password entered
- Whether endpoint malware executed
- Whether a SIEM alert fired
- Whether the user intentionally approved login prompts
- Whether all data records were successfully received by attacker

=== ADDITIONAL EVIDENCE NEEDED ===
- Endpoint process logs
- VPN authentication logs
- Domain controller logs
- Web server logs
- User interview
- DNS resolver logs outside the capture window

=== PACKET VISIBILITY SCORE ===
Direct PCAP evidence exists for 6 of 7 phases.
Packet visibility: 86%

KEY LESSON:
Packets show communication. They do not always show user intent,
plaintext credentials or endpoint process state. Strong investigations
separate packet facts from analytical inference.
================================================================
EOF
