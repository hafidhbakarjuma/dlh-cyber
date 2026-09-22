#!/bin/bash
# ==============================================================================
# Script Name: 6-kill_chain.sh
# Description: Reconstructs the complete kill chain from initial phishing to 
#              exfiltration, combining all PCAP findings into a chronological narrative.
# Usage: ./6-kill_chain.sh
# ==============================================================================

set -euo pipefail

cat << 'EOF'
================================================================
   COMPLETE KILL CHAIN RECONSTRUCTION
   Incident: Phishing Campaign -> Network Compromise -> DNS Exfiltration
   Period: 2026-04-14 14:47 to 2026-04-15 22:45
   Dwell time: approximately 31 hours, 58 minutes
================================================================

PHASE 1: INITIAL ACCESS (T1566.002 - Spearphishing Link)
  Time: 2026-04-14 14:47
  Evidence: 4x00 email evidence, Email 2
  Action: Spear-phishing email sent to dmarsh@meddefense.com
  Status: Context from 4x00, not packet evidence

PHASE 2: CREDENTIAL HARVESTING SESSION (T1056.003 - Web Portal Capture)
  Time: 2026-04-14 15:02:33 to 15:03:20
  Evidence: phishing_click.pcap
  Packet evidence:
    DNS query: meddefense-portal.com -> 91.234.99.107
    TLS SNI: meddefense-portal.com
    Largest client TLS record: 487 bytes at 15:02:58
  Assessment: Encrypted session metadata is consistent with form submission.

PHASE 3: BEACONING (T1071.001 - Web Protocols)
  Time: 2026-04-15 02:00 to 03:55
  Evidence: c2_beaconing.pcap
  Action: Repeated HTTPS sessions from 10.10.2.15 to 91.234.99.107
  Pattern: 24 sessions, ~300-second interval, low jitter
  Assessment: Highly automated communication pattern.

PHASE 4: EXTERNAL ACCESS / VPN PIVOT (T1133 - External Remote Services)
  Time: 2026-04-15 13:45:22
  Evidence: full_timeline.pcap
  Action: External VPN connection from 154.118.42.89 to 10.10.0.1
  Account context: dmarsh
  Assessment: VPN activity precedes lateral movement by ~45 minutes.

PHASE 5: LATERAL MOVEMENT (T1021.001 - Remote Desktop Protocol)
  Time: 2026-04-15 14:30:12
  Evidence: lateral_movement.pcap
  Action: RDP from 10.10.2.15 to 10.10.1.10 as dmarsh
  Assessment: Clinical workstation account used to access billing server.

PHASE 6: DISCOVERY (T1135, T1083)
  Time: 2026-04-15 14:35-14:42
  Evidence: lateral_movement.pcap
  Action: SMB enumeration and NAS directory listing
  Results:
    Some systems accessible
    Some systems returned access denied
    Some connection attempts were refused or reset

PHASE 7: EXFILTRATION (T1048.003 - Exfiltration Over Alternative Protocol)
  Time: 2026-04-15 22:15 to 22:45
  Evidence: dns_exfil.pcap
  Action: DNS TXT queries with long encoded labels
  Volume: approximately 120 anomalous queries
  Assessment: Traffic is consistent with DNS tunneling and data exfiltration.

=== VISIBILITY / DEFENSE SCORECARD ===
HELD / RESISTED:
  Access denied responses on selected internal systems
  Refused or reset connections to restricted internal systems

FAILED OR BYPASSED:
  User reached phishing domain
  Valid credentials appear to have enabled VPN access
  RDP access from clinical workstation to server system succeeded
  DNS TXT tunnel was present in packet evidence

ABSENT OR UNCONFIRMED FROM PCAP ALONE:
  Whether endpoint malware executed
  Whether MFA was enabled or disabled
  Whether alerts fired in any SIEM
  Exact plaintext credentials or exfiltrated full data content

=== IMPACT ASSESSMENT ===
Data likely exfiltrated: structured records over DNS TXT tunnel
Systems involved: WS-NURSE-04, VPN endpoint, billing-srv-01, NAS-01
Systems resisted access: selected internal servers and restricted endpoints
Blast radius: clinical workstation to billing/server resources, with DNS exfiltration path

================================================================
EOF
