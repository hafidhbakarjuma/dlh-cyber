#!/bin/bash
# ==============================================================================
# Script Name: 7-detection_rules.sh
# Description: Creates detection logic and pseudocode for each identified gap 
#              to transform forensic findings into operational defenses.
# Usage: ./7-detection_rules.sh
# ==============================================================================

set -euo pipefail

cat << 'EOF'
================================================================
   DETECTION ENGINEERING PLAN
================================================================

[*] Detection 1: C2 Beaconing
    Type: Frequency-based behavioral detection
    Logic:
      If same src_ip -> same dst_ip > 10 times in 3600 seconds
      AND interval_stddev < interval_mean * 0.15
      THEN alert: Possible C2 beaconing

    Data source:
      PCAP-derived session logs, Zeek conn.log, NetFlow or proxy logs

    Test scenario:
      10.10.2.15 connects to 91.234.99.107 every 300 seconds
      for 24 sessions.

    Would detect:
      Phase 3 beaconing in c2_beaconing.pcap

    False positive considerations:
      Software update clients, monitoring agents and backup tools may be regular.
      Baseline comparison is required.

[*] Detection 2: DNS Query Length Anomaly
    Logic:
      If left-most DNS label length > 40
      AND query type is TXT
      AND repeated queries target the same base domain
      THEN alert: Possible DNS tunneling

    Would detect:
      Phase 7 DNS exfiltration in dns_exfil.pcap

[*] Detection 3: VPN Geo-Anomaly
    Logic:
      If VPN source country or ASN is not expected
      AND account has no history from that geography
      THEN alert: Suspicious VPN login

    Would detect:
      Phase 4 VPN connection from 154.118.42.89

[*] Detection 4: Cross-Role RDP
    Logic:
      If account role is clinical
      AND destination is server subnet
      AND protocol is RDP
      THEN alert: Possible lateral movement

    Would detect:
      Phase 5 RDP to billing-srv-01

[*] Detection 5: DNS Tunneling TXT Query Pattern
    Logic:
      Count TXT queries per source per base domain.
      If count > 10 in 120 seconds and encoded labels are present,
      alert as DNS tunneling.

    Would detect:
      Phase 7 DNS exfiltration.

[*] Detection 6: TLS to Campaign Lookalike Domain
    Logic:
      If TLS SNI matches known phishing IOC or recently observed lookalike
      domain, alert and enrich with campaign context.

    Would detect:
      Phase 2 phishing-click TLS session.

=== DETECTION COVERAGE UPDATE ===
Before packet analysis:
  campaign visible only as email IOCs

After packet analysis:
  detections cover phishing click, beaconing, VPN pivot, lateral movement
  and DNS exfiltration.

Remaining gaps:
  endpoint execution confirmation requires endpoint logs
  exact credential content cannot be recovered from encrypted TLS
================================================================
EOF
