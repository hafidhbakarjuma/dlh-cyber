# MedDefense Health Systems — The Data Map

**Prepared by:** Junior Security Analyst
**Prepared for:** James Chen, Deputy CISO

---

## Data Classification & Lifecycle Table

| Data Category | Classification | At Rest (where) | In Transit (how) | In Use (by whom, on what) | Current Protection | Protection Gaps |
|---|---|---|---|---|---|---|
| **Patient Medical Records** | Restricted | ehr-db-01 (PostgreSQL) | Internal network, nurse stations to EHR server; VPN for Westside/HQ | Clinicians, on nurse-station and clinical workstations | SSH key-only auth on ehr-srv-01; AD password policy | Database reachable from the entire network, not restricted to the app server (Task 0). Unattended EHR session with a patient record on screen for 15+ minutes at the nurse station (Task 3) — a direct in-use exposure. |
| **Medical Imaging Data** | Restricted | pacs-srv-01 | DICOM protocol, MRI/CT/X-ray workstations to pacs-srv-01 | Radiology staff, on WS-RAD-01/02 | None specifically documented | Zero backup coverage — loss is permanent, not recoverable. Traverses WS-RAD-01, which runs unpatchable Windows XP. No network segmentation. |
| **Financial / Billing Data** | Restricted | billing-srv-01 (MySQL) | Internal network to finance/admin workstations | Billing/finance staff, Central | AD password policy only | Server already compromised twice (ransomware, cryptominer). Password-based SSH still enabled (only ehr-srv-01 was migrated to key-only). No antivirus coverage (Linux server). |
| **Employee HR Records** | Confidential | Unclear — no dedicated HR system was ever identified in any documentation | HQ network, VPN to Central for shared access | HR staff, Corporate HQ | AD password policy | No HR/ERP system was ever documented (Known Unknown, Task 0) — protection at rest cannot even be verified. The intern's rogue laptop sat on the same network segment as the HR file share for 3 weeks (Incident F). |
| **System Credentials** (AD passwords, SSH keys, shared/service logins) | Restricted | Active Directory; individual server configs; a laminated sheet in the network closet | Authentication traffic (Kerberos/LDAP) across the network | All staff at login; IT during administration | Password complexity/rotation policy; SSH key-only on one server only | Switch management credentials are posted in plaintext on a laminated sheet in an unlocked network closet (Task 3). Shared PACS login ("raduser") never addressed. No MFA anywhere except one personal account. |
| **Audit Logs** (system, EHR, firewall, AD) | Confidential | Scattered across local disk per system, no central store | Not forwarded anywhere | IT/sysadmins, reviewed manually and reactively | Basic local log rotation and retention windows | No centralization, no alerting, no integrity protection (no hashing or write-once storage). This is directly why the billing-srv-01 cryptominer ran undetected for roughly two weeks. |
| **Medical Device / IoT Telemetry** (vitals, infusion dosage data) | Restricted | On-device buffers, transmitted to monitoring/nurse-call systems | Flat network, same segment as general workstations | Clinical staff at bedside/nurse stations | None specific; devices expose HTTP/HTTPS management interfaces | Shares the same flat network as workstations and servers — a compromised workstation can reach pump/monitor management interfaces directly. Known BD Alaris CVEs remain unmitigated 18 months after the vendor's bulletin. |
| **Internal IT / Organizational Documentation** (network diagrams, policies, org charts) | Internal | Shared drives (e.g., `S:\Security\Notes`), HR shared drive | Internal file share access | Staff referencing during normal work | Standard file share permissions (assumed) | Marcus's own security observations file — which documents exploitable weaknesses — was marked "DO NOT SHARE" internally but stored at ordinary Internal-level protection, a mismatch between actual sensitivity and assigned classification. |

---

## Data Risk Summary

MedDefense's most significant data protection weakness is **System Credentials in the "at rest" state** — specifically, switch management credentials for core network infrastructure stored as plaintext on a laminated sheet inside an unlocked network closet. This is the widest gap in the entire map relative to classification level: a Restricted-tier asset, whose compromise could expose or redirect traffic for the entire network, is protected by nothing more than a door that doesn't lock. Every other technical control in this assessment — firewall rules, VLAN plans, database restrictions — ultimately depends on the network infrastructure underneath it staying secure. A single person walking into that closet undermines the whole chain at once, regardless of how well any individual data category further up the stack is protected.
