# MedDefense Health Systems — The Control Landscape

**Prepared by:** Junior Security Analyst
**Prepared for:** James Chen, Deputy CISO
**Source:** MedDefense Security Controls — Source Artifacts (firewall config, SSH config, password policy, Sophos AV report, backup config, physical security contract, training records, log management summary)
**Purpose:** Document existing security controls, classified by category and function, to establish the baseline against which future gap analysis will be performed.

---

## Control Inventory

---

**Control ID:** C-001
**Control Name:** DMZ Inbound Firewall Rule (Allow-Web-Inbound)
**Description:** FortiGate rule permitting only HTTP/HTTPS traffic from the internet to web-srv-01, with all traffic logged. Restricts public inbound access to a single system rather than exposing the internal network directly.
**Category:** Technical
**Function:** Preventive
**Asset(s) Protected:** web-srv-01 (public website + patient portal), internal network (by containment)
**Source:** Artifact 1 — Firewall Configuration Extract

---

**Control ID:** C-002
**Control Name:** Default-Deny Firewall Policy (Rule 5)
**Description:** Final catch-all firewall rule denying any traffic not explicitly permitted by an earlier rule, with logging enabled. Establishes a default-deny security posture at the network perimeter.
**Category:** Technical
**Function:** Preventive
**Asset(s) Protected:** Entire internal network (all sites routed through the FortiGate)
**Source:** Artifact 1 — Firewall Configuration Extract

---

**Control ID:** C-003
**Control Name:** Site-to-Site VPN Access Control (Westside & HQ)
**Description:** Firewall rules permitting only defined VPN interfaces (vpn-westside, vpn-hq) to reach the server subnet, rather than allowing direct internet access to internal servers. Note: rules currently permit ALL services once inside the tunnel, which limits the control's effectiveness but does not eliminate its function of restricting the entry path.
**Category:** Technical
**Function:** Preventive
**Asset(s) Protected:** Server subnet (accessed from Westside Clinic and Corporate HQ)
**Source:** Artifact 1 — Firewall Configuration Extract

---

**Control ID:** C-004
**Control Name:** Firewall Traffic Logging
**Description:** All firewall policies have `logtraffic` enabled (all or utm level), recording traffic that traverses the FortiGate. Retained locally for 30 days; not forwarded to any central system.
**Category:** Technical
**Function:** Detective
**Asset(s) Protected:** Entire perimeter-facing network
**Source:** Artifact 1 — Firewall Configuration Extract; Artifact 8 — Log Management

---

**Control ID:** C-005
**Control Name:** SSH Hardened Configuration (ehr-srv-01)
**Description:** sshd_config disables root login, password authentication, empty passwords, X11 forwarding, and TCP forwarding; enforces public-key authentication, a 3-attempt limit, and a 60-second login grace period. Reduces the attack surface for remote administrative access to this specific server.
**Category:** Technical
**Function:** Preventive
**Asset(s) Protected:** ehr-srv-01 (EHR application server)
**Source:** Artifact 2 — SSH Configuration

---

**Control ID:** C-006
**Control Name:** SSH Authentication Logging (ehr-srv-01)
**Description:** sshd_config sets `SyslogFacility AUTH` and `LogLevel VERBOSE`, recording authentication attempts and session activity to the system log for this server.
**Category:** Technical
**Function:** Detective
**Asset(s) Protected:** ehr-srv-01
**Source:** Artifact 2 — SSH Configuration

---

**Control ID:** C-007
**Control Name:** AD Group Policy Password Enforcement (Windows)
**Description:** The documented password policy (8-char minimum, complexity, 90-day rotation, 5-password history, 5-attempt lockout) is technically enforced via Active Directory Group Policy on Windows systems.
**Category:** Technical
**Function:** Preventive
**Asset(s) Protected:** All Windows workstations and servers joined to the domain
**Source:** Artifact 3 — Password Policy, Section 5 (Enforcement)

---

**Control ID:** C-008
**Control Name:** Endpoint Antivirus Protection (Sophos)
**Description:** Sophos Endpoint Protection deployed to 387 managed devices, actively blocking/quarantining detected threats. Coverage is limited to Windows 10/11 workstations (372 devices); Windows servers (15) and all Linux servers are explicitly not covered under the current license tier.
**Category:** Technical
**Function:** Preventive
**Asset(s) Protected:** Windows workstations organization-wide
**Source:** Artifact 4 — Sophos Antivirus Status Report

---

**Control ID:** C-009
**Control Name:** Antivirus Threat Detection & Quarantine
**Description:** Demonstrated detection capability: four threats blocked/quarantined in the last 30 days across covered endpoints (Adware, a cryptominer PUA, a phishing URL, and a Trojan), confirming the tool is actively identifying and acting on threats within its coverage scope.
**Category:** Technical
**Function:** Detective
**Asset(s) Protected:** Windows workstations within Sophos coverage
**Source:** Artifact 4 — Sophos Antivirus Status Report

---

**Control ID:** C-010
**Control Name:** Nightly Backup Job (Veeam)
**Description:** Automated full nightly backup of six defined VMs (ehr-srv-01, ehr-db-01, billing-srv-01, ad-dc-01, file-srv-01, web-srv-01) to a local NAS, 14-day retention. Enables restoration of covered systems following data loss or corruption. Notable exclusions: pacs-srv-01, ad-dc-02, print-srv-01, the Westside server, medical device configurations, and O365 data are not backed up by this job.
**Category:** Technical
**Function:** Corrective
**Asset(s) Protected:** ehr-srv-01, ehr-db-01, billing-srv-01, ad-dc-01, file-srv-01, web-srv-01
**Source:** Artifact 5 — Backup Configuration

---

**Control ID:** C-011
**Control Name:** Decentralized System & Application Logging
**Description:** Individual logging exists across multiple systems without centralization: Windows Event Viewer, Linux syslog (/var/log), Apache logs (4-week retention via logrotate), Active Directory event logs, and a vendor-managed EHR audit log (exportable on 48-hour request). No cross-system correlation or automated alerting exists; logs are reviewed manually and reactively.
**Category:** Technical
**Function:** Detective
**Asset(s) Protected:** Windows servers, Linux servers, web-srv-01, billing-srv-01, Active Directory, EHR application
**Source:** Artifact 8 — Log Management

---

**Control ID:** C-012
**Control Name:** Documented Password Policy
**Description:** Formal written policy (v1.2) defining minimum length, complexity, rotation, history, and lockout requirements for all employees, contractors, and vendors accessing MedDefense systems. Approved by the IT Director.
**Category:** Administrative
**Function:** Preventive
**Asset(s) Protected:** All systems requiring authentication, organization-wide
**Source:** Artifact 3 — Password Policy

---

**Control ID:** C-013
**Control Name:** Annual Security Awareness Training ("CyberSafe Basics")
**Description:** Mandatory annual 45-minute training module covering password hygiene, phishing recognition, physical security awareness (tailgating, clean desk), and reporting suspicious activity. Completion varies significantly by site (94% HQ, 71% Central, 58% Westside).
**Category:** Administrative
**Function:** Preventive
**Asset(s) Protected:** All staff (human layer), indirectly all systems staff interact with
**Source:** Artifact 7 — Training Records

---

**Control ID:** C-014
**Control Name:** Security Guard Service (Central Main Entrance)
**Description:** Contracted uniformed guard at the Central main entrance, Monday–Friday 07:00–19:00, performing visitor registration, badge verification, and incident reporting. Does not patrol floors, restricted areas, or parking, and provides no coverage outside contracted hours or at other sites. Primary operational duty is access control (verifying who enters); the visible guard presence also produces a secondary deterrent effect, but the contracted function is preventive.
**Category:** Physical
**Function:** Preventive
**Asset(s) Protected:** Central main entrance / lobby access point
**Source:** Artifact 6 — Physical Security Contract

---

**Control ID:** C-015
**Control Name:** CCTV Camera System (Central)
**Description:** Four analog cameras (main entrance x2, ER entrance, parking garage entrance) recording to a standalone DVR, 30-day retention before overwrite. Self-monitored by whoever staffs the security desk; no coverage of the server room, network closets, or administrative wing. Operational function is after-the-fact review of recorded footage; visible camera presence also produces a secondary deterrent effect, but the operational function is detective.
**Category:** Physical
**Function:** Detective
**Asset(s) Protected:** Central entrances and parking garage entrance only
**Source:** Artifact 6 — Physical Security Contract

---

**Control ID:** C-016
**Control Name:** CCTV Camera (Westside Clinic)
**Description:** Single camera covering the front entrance only, recording to a local SD card with approximately 48-hour capacity before being overwritten. Same operational logic as C-015: functions as after-the-fact review, with a secondary deterrent effect from visible presence.
**Category:** Physical
**Function:** Detective
**Asset(s) Protected:** Westside Clinic front entrance only
**Source:** Artifact 6 — Physical Security Contract

---

## Control Summary Matrix

| Category | Preventive | Detective | Corrective | Compensating | Deterrent |
|---|---|---|---|---|---|
| **Technical** | C-001, C-002, C-003, C-005, C-007, C-008 | C-004, C-006, C-009, C-011 | C-010 | *(none identified)* | *(none identified)* |
| **Administrative** | C-012, C-013 | *(none identified)* | *(none identified)* | *(none identified)* | *(none identified)* |
| **Physical** | C-014 | C-015, C-016 | *(none identified)* | *(none identified)* | *(none identified)* |

---

## Observations on the Matrix (Gaps Signaled by Empty Cells)

- **The entire Deterrent column is empty.** This does not mean MedDefense has zero deterrent effect — the guard and cameras plainly discourage some opportunistic behavior as a side effect. But no control in the artifacts is *purposed and contracted* as a deterrent; deterrence is incidental to controls whose documented operational function is preventive (access verification) or detective (recording). No standalone deterrent control (e.g., visible warning signage, "premises monitored" notices, login banners) is evidenced anywhere. That absence — not the side effects of other controls — is the actual finding.
- **No Compensating controls exist anywhere in the artifacts.** Given known infeasible-to-patch items (print-srv-01 past EOL, the MRI running Windows XP), the absence of any documented compensating control (isolation, restricted access, enhanced monitoring in lieu of patching) is itself a finding, not just an empty cell.
- **Administrative Detective and Corrective are both empty.** No documented incident response plan, escalation procedure, or after-action process exists in any provided artifact — consistent with earlier findings that MedDefense's response to both the January ransomware incident and the ongoing billing-srv-01 compromise has been ad hoc.
- **Physical Corrective is empty.** No documented physical incident recovery procedure (e.g., what happens after a break-in or theft) appears anywhere in the artifacts.

*This inventory documents controls only as evidenced in the provided artifacts. No control was invented to fill a matrix gap. Full risk-weighted gap analysis, cross-referencing these controls against asset criticality, is addressed in a subsequent deliverable.*
