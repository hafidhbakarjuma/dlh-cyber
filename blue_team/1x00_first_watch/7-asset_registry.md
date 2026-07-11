# MedDefense Health Systems — Asset Registry

**Prepared by:** Junior Security Analyst
**Prepared for:** James Chen, Deputy CISO
**Sources consolidated:** Task 0 (Environment Summary), Tasks 1–2 (Incident Log), Task 3 (Physical Walk-Through), Task 4 (Control Artifacts), Task 6 (MRI/Legacy Dilemma), and the Network Scan Summary (Nmap, scanned by Sarah Park)

---

## Asset Registry

| Asset ID | Name | Type | Location | Owner (Dept) | OS/Platform | Critical Services | Network Segment | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|
| A-001 | ehr-srv-01 | Server | Central, server room | IT | Ubuntu 20.04 | EHR application | 10.10.2.0/24 | Active | Only server with hardened SSH config (Task 4, C-005/C-006). Backed up nightly. |
| A-002 | ehr-db-01 | Server | Central, server room | IT | Ubuntu 20.04 (PostgreSQL) | EHR database (PHI) | 10.10.2.0/24 | Active | Port 5432 reachable network-wide per scan — confirms Marcus's Task 0 concern directly. |
| A-003 | pacs-srv-01 | Server | Central, server room | IT / Radiology | Windows Server 2016 | PACS imaging | 10.10.2.0/24 | Active | Not covered by nightly backup ("too large" — Artifact 5). Not covered by Sophos AV. |
| A-004 | billing-srv-01 | Server | Central, server room | IT / Finance | Ubuntu 18.04 | Billing/claims | 10.10.2.0/24 | Active | Compromised twice (Jan ransomware, ongoing cryptominer per Task 3). Standard support ended June 2023. |
| A-005 | ad-dc-01 | Server | Central, server room | IT | Windows Server 2019 | Primary domain controller | 10.10.2.0/24 | Active | Backed up nightly. |
| A-006 | ad-dc-02 | Server | Central, server room | IT | Windows Server 2019 | Secondary domain controller | 10.10.2.0/24 | Active | Not backed up ("redundant with ad-dc-01" — Artifact 5); single point of failure if both compromised together. |
| A-007 | file-srv-01 | Server | Central, server room | IT | Windows Server 2016 | Department file shares | 10.10.2.0/24 | Active | Backed up nightly; only system with a tested (partial) recovery. |
| A-008 | print-srv-01 | Server | Central, server room | IT | Windows Server 2012 R2 | Print services | 10.10.2.0/24 | Active | Marked [UNVERIFIED] in Task 0; **network scan now confirms it is active and responding.** OS EOL since Oct 2023. Not backed up. |
| A-009 | backup-srv-01 | Server | Central, server room | IT | Ubuntu 22.04 | Backup orchestration (Veeam) | 10.10.2.0/24 | Active | Same room/rack as NAS-01 (A-012) — co-location risk previously flagged by Tom Reeves. |
| A-010 | web-srv-01 | Server | Central, DMZ | IT | Ubuntu 20.04 | Public website, patient portal | 10.10.2.0/24 (DMZ) | Active | Only asset with a dedicated inbound firewall rule (Task 4, C-001). |
| A-011 | ws-srv-01 | Server | Westside Clinic | IT | Windows Server 2016 | Local file/scheduling | 10.10.10.0/24 | Active | Confirmed present in scan. No firewall protects this subnet locally. |
| A-012 | NAS-01 | Data Store | Central, server room | IT | Synology DSM 7 | Backup storage | 10.10.2.0/24 | Active | Management interface (ports 5000/5001) reachable network-wide per scan — an undocumented exposure. |
| A-013 | O365 Tenant Data | Data Store | Cloud (Microsoft) | IT / Org-wide | Microsoft 365 | Email, SharePoint, OneDrive | N/A (cloud) | Active | Not covered by any MedDefense backup ("Microsoft handles it" — Artifact 5, unverified assumption). |
| A-014 | PACS Imaging Study Data | Data Store | Hosted on pacs-srv-01 | Radiology | DICOM | Diagnostic imaging records | 10.10.2.0/24 | Active | Not backed up; only Corrective control gap identified for this data (Gap G-007). |
| A-015 | WS-RAD-01 (MRI control workstation) | Endpoint | Central, Radiology | Radiology / IT | Windows XP SP3 | MRI scanner control, PACS transmission | 10.10.1.0/24 | Active | **Critical.** Subject of Task 6 compensating control strategy. Confirmed via scan at 10.10.1.70, flagged "END OF LIFE." |
| A-016 | Central Windows 10 Workstations (aggregate) | Endpoint | Central, all floors | Multiple depts (Reception, Nursing, Admin, Pharmacy, Lab) | Windows 10 (build 19045) | Clinical/admin workflows | 10.10.1.0/24 | Active | ~320 units per Task 0; scan confirms consistent port profile (135/139/445, some with RDP 3389 open). |
| A-017 | ER Thin Clients (TC-ER-01–04) | Endpoint | Central, Emergency Dept | Emergency / IT | Linux (thin client) | ER clinical access | 10.10.1.0/24 | Active | Only SSH (22) exposed; smaller attack surface than standard workstations. |
| A-018 | Physician iPads (aggregate) | Endpoint | Central, patient rounds | Unclear (no MDM) | iOS (unspecified version) | Clinical rounds access | Not identified in scan | Shadow IT (unmanaged) | Management status explicitly unclear per Task 0; not covered by Sophos; did not appear in the network scan at all — see Reconciliation. |
| A-019 | Westside Workstations (WS-WC-01–36) | Endpoint | Westside Clinic | Westside Clinic / IT | Windows 10 | Outpatient clinical/admin | 10.10.10.0/24 | Active | Behind only a consumer router with no firewall (A-025). |
| A-020 | WS-WC-XRAY | Endpoint | Westside Clinic | Westside Clinic / Radiology | Unknown (vendor-specific) | X-ray imaging workstation | 10.10.10.0/24 | Unknown | OS/platform not identified by scan or documentation; port 4242 open (matches pacs-srv-01's DICOM-adjacent port), suggesting imaging-protocol traffic. |
| A-021 | HQ Workstations & Laptops (aggregate) | Endpoint | Corporate HQ | Finance, HR, Legal, Marketing, Executive / IT | Windows 10/11 | Administrative functions | 10.10.20.0/24 | Active | ~120 workstations + ~25 laptops; laptops noted as intermittent (mobile workers). |
| A-022 | FortiGate 100F Firewall | Network Device | Central | IT (Network) | FortiOS | Perimeter firewall, VPN termination | Perimeter / all subnets route through it | Active | Central point of enforcement for nearly every Technical Preventive control identified in Task 4. |
| A-023 | Cisco Core & Access Switches (aggregate) | Network Device | Central, all floors | IT (Network) | Cisco IOS (model unspecified) | Internal switching | 10.10.1.0/24–10.10.3.0/24 | Active | Scan confirms no VLAN separation is enforced across any switch-connected subnet. |
| A-024 | Ubiquiti UniFi Access Points (12 units) | Network Device | Central, all floors + garage/lobby/cafe | IT (Network) | UniFi OS | Wireless connectivity | 10.10.1.0/24 | Active | Scan reveals individual placements (incl. AP-GARAGE, AP-CAFE) not itemized in Task 0 documentation. |
| A-025 | Netgear Consumer Router | Network Device | Westside Clinic | IT (nominal) | Netgear firmware | Internet gateway, site-to-site VPN endpoint | 10.10.10.0/24 | Active | Consumer-grade device carrying the entire Westside VPN tunnel; no firewall present at this site. |
| A-026 | UNKNOWN-01 | Network Device | Central, server subnet | Unassigned | Linux 4.x | Two unidentified web services | 10.10.2.0/24 | Shadow IT (unmanaged) | No DNS hostname, absent from all documentation. Sarah Park speculates it may belong to Marcus or the IT intern. |
| A-027 | Unknown Device (Westside) | Network Device | Westside Clinic | Unassigned | Linux 5.x | Port 3000 (possible Grafana/Node.js) | 10.10.10.0/24 | Shadow IT (unmanaged) | Sarah suspects an unofficial monitoring tool set up by Westside staff. |
| A-028 | Philips IntelliVue Patient Monitors (aggregate) | IoT Medical | Central, ICU/ER/3F | Unclear (no documented owner — IT vs. Biomedical Engineering) | Philips proprietary | Vital signs monitoring | 10.10.3.0/24 | Active | ~80 units; HTTP/HTTPS management interfaces exposed network-wide per scan. |
| A-029 | BD Alaris Infusion Pumps (aggregate) | IoT Medical | Central, ICU/ER/3F | Unclear (no documented owner) | Firmware 12.1.2 | Medication dosage delivery | 10.10.3.0/24 | Active | Vendor issued a security bulletin 18 months ago recommending network isolation for known CVEs — not implemented. |
| A-030 | MON-VITALS-3F-01 | IoT Medical | Central, 3rd floor patient room | Unclear | Unknown vendor | Vital signs display | 10.10.3.0/24 | Unknown | Same device observed directly during the Task 3 walk-through; vendor/firmware still unidentified even after the scan. |
| A-031 | MRI Scanner (Siemens MAGNETOM) | IoT Medical | Central, Radiology | Radiology | N/A (imaging hardware; controlled via WS-RAD-01) | Diagnostic imaging | Physically connected via WS-RAD-01 | Active | The scanner itself is not independently addressable in the scan; all network exposure runs through A-015. |
| A-032 | CT Scanner (GE Revolution) | IoT Medical | Central, Radiology | Radiology | Unknown (undocumented) | Diagnostic imaging | Not identified in scan | Unknown | OS/connectivity never documented in any source, including the scan — this Known Unknown from Task 0 remains fully open. |
| A-033 | Nurse Call System | IoT Medical | Central, all floors | Facilities / IT | IP-based, integrated with phone system | Patient-to-staff alerting | 10.10.3.0/24 | Active | Ports 80 and 5060 (SIP) open — same flat segment as monitors and pumps. |
| A-034 | HID Badge Reader System (Main/Server/ER) | IoT Medical / Network Device | Central, multiple entry points | Facilities (Security) / IT | HID Global | Physical access control | 10.10.3.0/24 | Active | Connected to AD "for some doors" per Task 0 — scan confirms network presence but not which doors or AD-integration scope. |
| A-035 | Server Room | Physical Infrastructure | Central, ground floor | Facilities / IT | N/A | Houses nearly all critical servers | N/A | Active | Subject of Task 3, Observation 1 — generic badge, no camera, no visitor log. |
| A-036 | Network Closet (2nd floor) | Physical Infrastructure | Central, 2nd floor | Facilities / IT | N/A | Houses switches and patch panels | N/A | Active | Subject of Task 3, Observation 2 — unlocked, credentials posted inside. |
| A-037 | Propped Fire Exit (Admin Wing) | Physical Infrastructure | Central, public waiting area to admin wing | Facilities | N/A | Access boundary to restricted admin/IT wing | N/A | Active | Subject of Task 3, Observation 5 — access control defeated by standing practice. |
| A-038 | Patient Portal (Application) | Application | Hosted on web-srv-01 | IT | Web application | Patient-facing PHI access | 10.10.2.0/24 | Active | Subject of Incident B (IDOR vulnerability, Task 1–2). |
| A-039 | EHR Application Software | Application | Hosted on ehr-srv-01 | IT / Clinical | Application software | Clinical documentation, records | 10.10.2.0/24 | Active | Subject of Incident E (migration outage, Task 1–2). |

---

## Reconciliation Notes

### Assets found in the network scan with no prior documentation (shadow IT / undocumented systems)

- **UNKNOWN-01 (10.10.2.99, A-026):** An undocumented Linux host on the *servers* subnet — the most sensitive network segment in the environment — running two unidentified web services, with no DNS hostname and no owner in any prior documentation. Sarah Park's best guess (Marcus's or the intern's) is speculation, not confirmation. This is the single most concerning reconciliation finding: an unknown device sitting directly among critical infrastructure.
- **Unknown Device (10.10.10.200, Westside, A-027):** A second undocumented Linux host, this time at Westside, on port 3000 — plausibly an unofficial monitoring tool someone deployed without IT's knowledge.
- **Individual access point placements (A-024):** Task 0 documented only a count ("12 UniFi APs"). The scan reveals specific locations, including **AP-GARAGE** — a wireless access point in the parking garage that was never mentioned in any prior physical or network discussion.
- **HID badge reader system as a networked asset (A-034):** Task 0 mentioned badge access only in passing ("connected to AD for some doors"). The scan is the first source to reveal these are independently addressable network devices with their own IP addresses and open web management ports (80/443) — a detail with real security implications (badge readers are themselves attackable network endpoints) that no prior source surfaced.

### Assets mentioned in documentation that do NOT appear in the network scan

- **The rumored second Westside server** (mentioned secondhand by Mike Torres to Marcus, Task 0): does not appear anywhere in the 10.10.10.0/24 scan results. This does not resolve the question — Sarah's own note acknowledges devices powered off during the scan would be missed. Status remains genuinely unconfirmed either way.
- **CT Scanner (GE Revolution, A-032):** does not appear under any IP address in the scan. Combined with Task 0's finding that its OS was never documented, this Known Unknown remains fully open — it's unclear whether the device has no network connectivity at all, or simply didn't respond during the scan window.
- **Physician iPads (A-018):** ~25 units were documented in Task 0 with an explicit note that management status was unclear. None appear in the network scan under any subnet. This could mean they connect only via a wireless network segment not captured by this scan (e.g., guest WiFi, whose isolation Marcus separately flagged as unverified), or that they were simply offline during the scan window.
- **MRI and imaging hardware itself (A-031):** the scan shows only the Windows XP *control workstation* (WS-RAD-01); the imaging hardware itself has no independent network identity, which is expected but worth stating explicitly for completeness.

### Discrepancies or corroborations between sources

- **print-srv-01 (A-008) status resolved:** Task 0 marked this asset `[UNVERIFIED]`, not physically confirmed in over a year. The network scan now directly confirms it is active and responding — this Known Unknown from Task 0 is now closed, though the finding itself (an active EOL server) is unchanged in severity.
- **Database exposure corroborated, not contradicted:** Marcus's notes (Task 0) specifically flagged that ehr-db-01's PostgreSQL and billing-srv-01's MySQL were reachable from the entire network. The scan independently confirms both exposures via open-port data (5432 and 3306 respectively), strengthening rather than conflicting with the earlier finding.
- **BD Alaris CVE exposure confirmed and quantified:** the scan confirms the exact firmware version (12.1.2) referenced in the vendor's 18-month-old security bulletin, and confirms that the vendor-recommended mitigation (network isolation) still has not been applied — consistent with, and now more precisely evidenced than, the general flat-network finding from earlier tasks.
- **New finding, not previously documented anywhere:** RDP (port 3389) is open on reception and administrative workstations with no network-level restriction. This did not appear in Task 0, Task 3, or Task 4 — it is a genuinely new exposure surfaced only by this scan, and should be treated as a new finding rather than a discrepancy.
- **Flat network finding formally confirmed at the technical level:** all prior sources (Marcus's notes, the draft network diagram, the walk-through) described the flat network qualitatively. The scan is the first source to *prove* it directly — Sarah's scan host at HQ (10.10.20.10) reached every subnet, including the medical device segment, with zero restriction, during the scan itself.
