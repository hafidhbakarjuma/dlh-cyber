#!/bin/bash
# ==============================================================================
# Script Name: 11-network_forensics_report.sh
# Description: Generates the comprehensive Network Forensics Investigation Report 
#              synthesizing all PCAP findings and analysis phases into Markdown format.
# Usage: ./11-network_forensics_report.sh
# ==============================================================================

set -euo pipefail

REPORT_FILE="11-network_forensics_report.md"

echo "Generating $REPORT_FILE..."

cat << 'EOF' > "$REPORT_FILE"
# Network Forensics Investigation Report

## Executive Summary
Between April 14 and April 15, 2026, an external threat actor compromised the MedDefense network via a spearphishing link targeting a clinical user account (`dmarsh@meddefense.com`). After harvesting user credentials through a lookalike portal, the attacker established persistent C2 beaconing and executed an unauthorized external VPN login from an overseas IP address. They subsequently performed lateral movement via RDP from a clinical workstation to the billing server, enumerated network shares, and exfiltrated structured records using a covert DNS TXT tunneling protocol. Critical internal systems and strict endpoint segmentation successfully blocked unauthorized access attempts to restricted subnets, preventing a total network-wide breach.

## Investigation Scope
* **PCAPs Analyzed:** `phishing_click.pcap`, `c2_beaconing.pcap`, `full_timeline.pcap`, `lateral_movement.pcap`, `dns_exfil.pcap`
* **Time Period Covered:** 2026-04-14 14:47 to 2026-04-15 22:45
* **Tools Used:** Wireshark, Tshark, Bash, custom forensic analysis scripts
* **Evidence Sources Not Used:** Host endpoint logs (EDR/Sysmon), Domain Controller security event logs, direct user interviews, web gateway proxy logs

## Methodology
* **Baseline Establishment:** Comparing observed cross-subnet traffic and protocol activity against standard medical network operational baselines.
* **Known-IOC Search:** Filtering packet captures for indicators of compromise established during the initial 4x00 threat assessment.
* **DNS Analysis:** Evaluating query lengths, record types (TXT), and resolution patterns to identify tunneling or command-and-control communication.
* **TLS Metadata Analysis:** Inspecting Server Name Indication (SNI) values, record sizes, and handshake patterns for form submissions and beaconing regularities.
* **Timing Analysis:** Measuring intervals, standard deviations, and session durations to identify automated beaconing and cross-phase dwell time gaps.
* **Behavioral Analysis:** Tracing unexpected protocol usage (e.g., clinical hosts talking to servers via RDP) and administrative share discovery.
* **Cross-PCAP Correlation:** Assembling isolated capture slices into a unified chronological sequence representing the end-to-end cyber kill chain.

## Findings by Attack Phase
1. **Initial Access (T1566.002)**
   * *Narrative:* Spearphishing email delivered containing a link to a credential harvesting site.
   * *Evidence:* 4x00 email evidence, Email 2 (Context-based).
   * *Confidence:* High (Contextual).
2. **Credential Harvesting (T1056.003)**
   * *Narrative:* User accessed lookalike portal and submitted credentials over TLS.
   * *Evidence:* `phishing_click.pcap` (DNS query for `meddefense-portal.com` to `91.234.99.107`, TLS SNI match at 15:02:58).
   * *Confidence:* Strong Inference.
3. **C2 Beaconing (T1071.001)**
   * *Narrative:* Compromised host initiated regularized outbound HTTPS requests.
   * *Evidence:* `c2_beaconing.pcap` (24 sessions from `10.10.2.15` to `91.234.99.107` at ~300-second intervals).
   * *Confidence:* Confirmed.
4. **External Access / VPN Pivot (T1133)**
   * *Narrative:* External IP established an encrypted VPN session utilizing stolen credentials.
   * *Evidence:* `full_timeline.pcap` (VPN connection from `154.118.42.89` to `10.10.0.1` at 13:45:22).
   * *Confidence:* Strong Inference.
5. **Lateral Movement (T1021.001)**
   * *Narrative:* RDP session initiated from clinical workstation to billing server.
   * *Evidence:* `lateral_movement.pcap` (`10.10.2.15` to `10.10.1.10` as `dmarsh` at 14:30:12, yielding RDP/NLA SUCCESS).
   * *Confidence:* Confirmed.
6. **Discovery (T1135, T1083)**
   * *Narrative:* SMB enumeration, share listing, and directory checks across servers and NAS.
   * *Evidence:* `lateral_movement.pcap` (SMB session setups and directory listings against `10.10.1.20`, `10.10.1.30`, and NAS `10.10.1.60`).
   * *Confidence:* Confirmed.
7. **Exfiltration (T1048.003)**
   * *Narrative:* Encoded data transmitted via high-frequency DNS TXT record queries.
   * *Evidence:* `dns_exfil.pcap` (~120 anomalous DNS TXT queries with long left-most labels between 22:15 and 22:45).
   * *Confidence:* Confirmed.

## Network-Level IOC Table
| Type | Value | Source | Confidence | Detection Utility |
|---|---|---|---|---|
| Domain | `meddefense-portal.com` | `phishing_click.pcap` | High | Blocklist / DNS Sinkhole |
| IP Address | `91.234.99.107` | `c2_beaconing.pcap` | High | Firewall Outbound Drop / SIEM Alert |
| IP Address | `154.118.42.89` | `full_timeline.pcap` | Medium | Geo-IP / VPN Access Deny |
| Domain | `data-sync.meddefense-portal.com` | `dns_exfil.pcap` | High | DNS Security Inspection / Tunnel Alert |

## Impact Assessment
* **Data Likely Exfiltrated:** Structured patient/billing database records tunneled via DNS TXT queries.
* **Systems Involved:** `WS-NURSE-04` (10.10.2.15), VPN Gateway (10.10.0.1), `billing-srv-01` (10.10.1.10), `NAS-01` (10.10.1.60).
* **Systems Protected or Not Reached:** Restricted internal subnets (`10.10.4.100`, `10.10.4.101`) which returned TCP resets/refused connections.
* **Credential Exposure:** Domain account `dmarsh` compromised.
* **Regulatory/Business Concerns:** Potential HIPAA data breach involving clinical/billing records, requiring mandatory notification and remediation audit.

## Detection Gap Analysis
* **Initial Access:** Email gateway lacked link-rewriting or robust domain-age verification.
* **Behavioral Detection:** Lack of real-time alerting on clinical workstation RDP access to critical server infrastructure.
* **DNS Tunneling:** Absence of query length and entropy monitors permitted covert outbound data loss over standard port 53.
* **VPN Anomaly:** Lack of impossible travel or geographic risk-scoring allowed foreign ASN authentication.

## Detection Rules Recommended
1. **C2 Beaconing Detection:** Frequency-based rule checking for >10 outbound connections to the same external IP within 60 minutes with low interval standard deviation.
2. **DNS Query Length Anomaly:** Alert on left-most DNS labels exceeding 40 characters, especially for TXT record queries.
3. **VPN Geo-Anomaly:** Flag VPN sessions originating from unapproved foreign countries or high-risk ASNs.
4. **Cross-Role RDP:** Alert when clinical or standard user accounts initiate RDP sessions into server subnets.
5. **DNS Tunneling TXT Pattern:** Monitor high-frequency TXT requests targeting a single base domain with randomized or encoded labels.
6. **TLS to Campaign Lookalike Domain:** Enforce active blocklists matching newly observed lookalike infrastructure domains.

## Recommendations
### Immediate (Next 24 Hours)
* Isolate compromised clinical workstation (`WS-NURSE-04`) and billing server (`billing-srv-01`).
* Force immediate password reset and session invalidation for user `dmarsh`.
* Block attacker IP (`91.234.99.107`) and domain (`meddefense-portal.com`) at perimeter firewalls.
* Preserve all local system logs and full PCAP buffers for legal/forensic chain of custody.

### Short-Term (Next 7 Days)
* Deploy behavioral detection rules for regularized C2 beaconing and cross-subnet RDP traffic.
* Review and tighten VPN access policies, enforcing multi-factor authentication (MFA) and geo-restrictions.
* Implement strict DNS egress monitoring to detect abnormal TXT query volumes.
* Scan adjacent internal hosts for signs of secondary persistence or credential dumping.

### Medium-Term (Next 30 Days)
* Upgrade email security gateway controls with advanced link analysis and domain-age filters.
* Implement role-based access control (RBAC) network segmentation restricting clinical-to-server RDP paths.
* Conduct a comprehensive healthcare data exposure and asset inventory audit.

## Evidence Chain
* `phishing_click.pcap` | Credential Harvest Analysis | 2026-04-14 15:02 - 15:04 | SHA256: [Stored locally in lab archive]
* `c2_beaconing.pcap` | Beaconing Behavior Trace | 2026-04-15 02:00 - 04:00 | SHA256: [Stored locally in lab archive]
* `full_timeline.pcap` | Composite VPN Pivot Log | 2026-04-15 13:40 - 14:00 | SHA256: [Stored locally in lab archive]
* `lateral_movement.pcap` | RDP & SMB Enumeration Trace | 2026-04-15 14:30 - 14:45 | SHA256: [Stored locally in lab archive]
* `dns_exfil.pcap` | DNS Tunneling & Exfiltration Capture | 2026-04-15 22:10 - 22:50 | SHA256: [Stored locally in lab archive]

## Continuity with 4x00
This network-level forensics investigation successfully builds upon the initial 4x00 assessment by updating the following dimensions:
* **Credential Exposure:** Upgraded from a theoretical risk to a strongly supported finding backed by active TLS session metadata and subsequent VPN authentication.
* **Network Timeline:** Established an exact, timestamped chronology of the lateral movement from workstation to server resources.
* **Campaign Infrastructure:** Directly linked initial email IOCs to active post-click C2 beaconing and VPN infrastructure (`91.234.99.107`, `154.118.42.89`).
* **Exfiltration Scope:** Quantified data loss via DNS tunneling (`dns_exfil.pcap`), expanding the impact assessment beyond internal discovery alone.
EOF

echo "Done."
