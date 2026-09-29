# 4x01 — Wire Shark Territory

*PCAP-only network forensics, incident reconstruction and detection engineering for MedDefense Health Systems*

![Track](https://img.shields.io/badge/Track-SOC%20Analyst%20%2F%20Network%20Forensics-blue)
![Tooling](https://img.shields.io/badge/Tooling-tshark%20%7C%20Bash-informational)
![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)
![Lint](https://img.shields.io/badge/Bash-shellcheck%20clean-brightgreen)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)

> *"The network never lies. People lie. Logs can be tampered with. But the packets on the wire are physics, not policy."* — Richard Bejtlich

**Program:** DLH Cybersecurity Academy — SOC Analyst / Penetration Testing track
**Author:** [hafidhbakarjuma](https://github.com/hafidhbakarjuma)
**Repository path:** [`threat_detection/4x01_wire_shark_territory`](https://github.com/hafidhbakarjuma/dlh-cyber/tree/main/threat_detection)

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Incident Scenario](#incident-scenario)
3. [Key Indicators](#key-indicators)
4. [Attack Chain](#attack-chain)
5. [Repository Structure](#repository-structure)
6. [Scripts and Deliverables](#scripts-and-deliverables)
7. [Task Index](#task-index)
8. [Evidence Set](#evidence-set)
9. [Tooling and Quick Reference](#tooling-and-quick-reference)
10. [Getting Started](#getting-started)
11. [Investigation Standards](#investigation-standards)
12. [Skills Demonstrated](#skills-demonstrated)
13. [References](#references)

---

## Executive Summary

The 4x00 phishing investigation ended with an open question: **what happened after the click?**

This project answers it using **packet captures only**, with no SIEM, EDR or endpoint logs. Starting from a traffic baseline, the analysis reconstructs a multi-stage intrusion: credential-harvesting phishing, external VPN access with stolen credentials, internal lateral movement over RDP and SMB, and covert data exfiltration through DNS TXT tunneling.

Every finding is produced by a reproducible `tshark` script and supported by exact PCAP timestamps.

---

## Incident Scenario

Week eleven at MedDefense Health Systems. A nurse workstation contacted a credential-harvesting domain shortly after a targeted phishing email. Overnight, a workstation made HTTPS connections every five minutes to one external IP, each lasting about two seconds with almost no data transferred. No signatures fired. `billing-srv-01` also generated hundreds of long, encoded-looking DNS TXT queries to a never-before-seen domain.

The incident response team needed to determine:

- What happened after the phishing click
- How the attacker moved through the network
- Whether stolen credentials were actually used
- Whether data left the environment

---

## Key Indicators

| Type | Value | Note |
|------|-------|------|
| Compromised workstation | `WS-NURSE-04` (`10.10.2.15`) | Clinical VLAN |
| Compromised account | `dmarsh` | Clinical / domain user |
| Phishing domain | `meddefense-portal.com` (`91.234.99.107`) | Lookalike credential harvester |
| External VPN pivot IP | `154.118.42.89` | Spectranet Limited, Lagos, Nigeria |
| Lateral movement target | `billing-srv-01` (`10.10.1.10`) | Reached via RDP and SMB |
| Exfiltration channel | DNS TXT tunneling via `data-sync.meddefense-portal.com` | Base64-style encoded labels |

---

## Attack Chain

```text
Phishing click ─► Credential theft ─► External VPN access ─► Lateral movement
 (WS-NURSE-04)      (dmarsh)           (154.118.42.89)        (billing-srv-01)
                                                                    │
                        C2 beaconing ◄──────────────────────────────┤
                        (5-minute HTTPS)                            ▼
                                                        DNS TXT exfiltration
                                                        (data-sync subdomain)
```

`6-kill_chain.sh` assembles these findings into a chronological 7-phase narrative mapped to MITRE ATT&CK.

---

## Repository Structure

```text
4x01_wire_shark_territory/
├── README.md
├── 0-baseline_analysis.sh
├── 1-phishing_click.sh
├── 3-dns_tunnel.sh
├── 4-lateral_movement.sh
├── 5-vpn_pivot.sh
├── 6-kill_chain.sh
├── 7-detection_rules.sh
├── 8-evidence_crosscheck.sh
├── 11-network_forensics_report.sh
├── 11-network_forensics_report.md     # Generated report
└── pcaps/                             # Provided evidence (not modified)
    ├── normal_baseline_clinical.pcap
    ├── phishing_click.pcap
    ├── c2_beaconing.pcap
    ├── dns_exfil.pcap
    ├── lateral_movement.pcap
    └── full_timeline.pcap
```

> Adjust the `pcaps/` folder name to match your repository layout.

---

## Scripts and Deliverables

| Script | Purpose |
|:-------|:--------|
| `0-baseline_analysis.sh` | Profiles normal clinical and server network baselines. |
| `1-phishing_click.sh` | Analyzes DNS, TLS SNI and session metadata for phishing portal interaction. |
| `3-dns_tunnel.sh` | Detects high-frequency DNS TXT queries and long encoded labels. |
| `4-lateral_movement.sh` | Traces cross-subnet traffic, RDP/SMB authentication events and failures (`TCP RST`). |
| `5-vpn_pivot.sh` | Identifies external SSL-VPN sessions, source geolocation and timeline correlation. |
| `6-kill_chain.sh` | Assembles isolated findings into a chronological 7-phase attack narrative. |
| `7-detection_rules.sh` | Converts forensic gaps into SOC detection logic and pseudocode. |
| `8-evidence_crosscheck.sh` | Correlates PCAP findings with investigation context and calculates a visibility score. |
| `11-network_forensics_report.sh` | Generates the full Markdown incident report. |

---

## Task Index

### Practical Analysis Tasks

| Task | Focus | Script |
|------|-------|--------|
| 0 | **Baseline profiling** — normal traffic across clinical and server VLANs | `0-baseline_analysis.sh` |
| 1 | **Phishing click analysis** — user interaction with lookalike `meddefense-portal.com` | `1-phishing_click.sh` |
| 3 | **DNS tunneling detection** — abnormal query lengths and record types | `3-dns_tunnel.sh` |
| 4 | **The lateral trail** — cross-subnet RDP, SMB setup, access denials (`TCP RST`), share enumeration | `4-lateral_movement.sh` |
| 5 | **The VPN pivot** — external access from `154.118.42.89` with stolen `dmarsh` credentials | `5-vpn_pivot.sh` |
| 6 | **Kill chain reconstruction** — 7-phase master timeline mapped to ATT&CK | `6-kill_chain.sh` |
| 7 | **Detection engineering** — frequency-based, geo-anomaly and protocol-abuse logic | `7-detection_rules.sh` |
| 8 | **Evidence cross-check** — confirmed packet facts vs. analytical inference (86% visibility score) | `8-evidence_crosscheck.sh` |
| 11 | **Network forensics report** — executive and technical documentation | `11-network_forensics_report.sh` |

### Analytical Review Questions

| Task | Topic | Question |
|------|-------|----------|
| 13 | DNS exfiltration indicators | Analyze base64-encoded subdomain queries (`aGVhbHRoX3JlY29yZDppZD00ODkx`) from a production database server and distinguish legitimate traffic from DNS tunneling. |
| 14 | Lateral movement detection | Evaluate cross-role RDP from a clinical VLAN to a billing server, analyze SMB enumeration and interpret blocked connections (`TCP RST`). |
| 15 | Network evidence correlation | Reconstruct timelines across email logs, VPN captures and SIEM firewall blocks without mistaking defensive actions for the initial attack vector. |
| 16 | Methodology and large-PCAP triage | Prioritize 75 GB of captures across 48 hours using `tshark` triage filters, conversation statistics, baseline comparison and reproducible documentation. |

> The C2 beaconing capture (`c2_beaconing.pcap`) supports the timing analysis behind the five-minute HTTPS beacon. Add its script to the tables above if it lives in your repo.

---

## Evidence Set

| PCAP | Purpose |
|------|---------|
| `normal_baseline_clinical.pcap` | Known-good DNS, TLS and connection patterns for comparison |
| `phishing_click.pcap` | The exact phishing-click event: DNS, TLS metadata, credential submission |
| `c2_beaconing.pcap` | Machine-regular beaconing vs. human browsing |
| `dns_exfil.pcap` | DNS TXT abuse, encoded subdomains, exfiltration volume estimate |
| `lateral_movement.pcap` | Cross-subnet RDP and SMB, successful and failed access |
| `full_timeline.pcap` | External access and full cross-phase correlation |

---

## Tooling and Quick Reference

All scripts use `tshark` with validated field names (for example `frame.time`, not deprecated absolute-time fields).

**Protocol hierarchy summary**
```bash
tshark -r capture.pcap -qz io,phs
```

**IP conversation summary**
```bash
tshark -r capture.pcap -qz conv,ip
```

**Search for an IP IOC**
```bash
tshark -r capture.pcap -Y "ip.addr == 91.234.99.107" \
  -T fields -e frame.time -e ip.src -e ip.dst -e _ws.col.Protocol
```

**Hunt for DNS tunneling (query name longer than 40 characters)**
```bash
tshark -r dns_exfil.pcap -Y "dns.qry.name and string(dns.qry.name).len > 40" \
  -T fields -e frame.time -e ip.src -e dns.qry.type -e dns.qry.name
```

**Extract TLS SNI values**
```bash
tshark -r phishing_click.pcap -Y "tls.handshake.type == 1" \
  -T fields -e frame.time -e ip.dst -e tls.handshake.extensions_server_name
```

**Decode a suspicious label**
```bash
echo "aGVhbHRoX3JlY29yZDppZD00ODkx" | base64 -d
```

---

## Getting Started

### Prerequisites

- `tshark` (Wireshark CLI), `bash`, `base64`
- `shellcheck` for linting
- The six provided PCAP files

### Run the analysis

```bash
# Lint every script
shellcheck ./*.sh

# Run each phase
chmod +x ./*.sh
./0-baseline_analysis.sh
./1-phishing_click.sh
./3-dns_tunnel.sh
./4-lateral_movement.sh
./5-vpn_pivot.sh
./6-kill_chain.sh
./7-detection_rules.sh
./8-evidence_crosscheck.sh
./11-network_forensics_report.sh
```

No SIEM, Wazuh, Suricata or prior-module infrastructure is required.

---

## Investigation Standards

- **Every filter is documented.** Each `tshark` command, display filter and search query lives in the scripts, so results are reproducible.
- **Timestamps are mandatory.** Every finding carries its exact PCAP timestamp.
- **Facts vs. inference.** Confirmed packet evidence is separated from analytical judgment (see the evidence cross-check).
- **Behavior over signatures.** Beaconing and tunneling are found through timing, frequency and structure, since no content signature exists.
- **Scripts are standardized.** `#!/bin/bash` header, `shellcheck` clean, files end with a newline.

---

## Skills Demonstrated

**Network forensics:** baselining, TCP session analysis, TLS metadata analysis without decryption, large-PCAP triage
**Attack recognition:** C2 beaconing, DNS tunneling, RDP/SMB lateral movement, VPN pivoting
**Analysis:** IOC extraction, multi-capture timeline correlation, ATT&CK mapping
**Detection engineering:** frequency, geo-anomaly and protocol-abuse rules
**Communication:** evidence-backed executive and technical reporting
**Tooling:** `tshark`, Bash, `shellcheck`, `base64`

---

## References

- [MITRE ATT&CK: Command and Control (TA0011)](https://attack.mitre.org/tactics/TA0011/)
- [MITRE ATT&CK: Exfiltration Over Alternative Protocol (T1048)](https://attack.mitre.org/techniques/T1048/)
- [MITRE ATT&CK: Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008/)
- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [RFC 1035: Domain Names](https://www.rfc-editor.org/rfc/rfc1035) and [RFC 8446: TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)

---

*Educational project completed as part of the DLH Cybersecurity Academy curriculum. All organizations, personnel and incident details belong to a training scenario.*
