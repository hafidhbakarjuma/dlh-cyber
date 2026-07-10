# MedDefense Health Systems — Structured Environment Summary

**Prepared by:** Junior Security Analyst
**Prepared for:** James Chen, Deputy CISO
**Source:** MedDefense Security Documentation Package (HR onboarding guide, IT asset export, Marcus Webb's notes, IT contracts summary, draft network diagram, org chart)
**Purpose:** Structured extraction of the organization's environment, as a foundation for the subsequent security posture assessment.

---

## 1. Organization Overview

### Sites

| Site | Location Type | Function | Approx. Headcount |
|---|---|---|---|
| MedDefense Central Hospital | Downtown, 350-bed acute care facility, 6 floors + basement | Emergency, Surgery, Cardiology, Radiology, Oncology, Pediatrics, Maternity, Pharmacy, Laboratory, Administration | ~1,400 |
| Westside Clinic | Suburban outpatient facility, 2-story medical office complex, 12 minutes from Central | Primary care, diagnostic imaging (X-ray, ultrasound — no MRI), blood work, minor procedures, physical therapy | ~180 |
| Corporate HQ | Leased office space, 3rd floor of a 5-story commercial building, Greenfield Business Park, 15 minutes from Central | Finance, HR, Legal, Marketing, Executive Leadership, IT | ~220 |

Total organization-wide headcount: approximately 2,000.

### Reporting Structure Relevant to Security

- CEO Dr. Patricia Morales sits above a CISO position that is currently **vacant**.
- James Chen (Deputy CISO) is acting head of security but, per the org chart, reports to the vacant CISO role — in practice, directly to the CEO.
- Sarah Park (IT Director) and James Chen are **organizational peers**, both ultimately reporting toward the CEO through separate lines.
- **Structural note:** James "has authority over security policy but no authority over IT operations," which the org chart explicitly flags as a source of friction. This is relevant because IT (under Sarah Park) controls implementation — servers, network, endpoints — while security (under James) can only request changes, not mandate them. Several items in Marcus Webb's notes (e.g., network segmentation "planned for next fiscal year" for four months, a denied backup budget request) are consistent with this authority gap.
- The security function itself consists of a single analyst role (previously Marcus Webb, now this position), reporting to James Chen. IT operations staff (3 sysadmins, 2 network technicians, 1 DBA, helpdesk, desktop support) report through Sarah Park, not through security.

---

## 2. IT Infrastructure Identified

**Reliability note:** Sarah Park stated the underlying asset export is "not complete," and items marked `[UNVERIFIED]` have not been physically confirmed in over a year. This is reflected below.

### Servers — MedDefense Central

| Name | OS/Platform | Function | Notes |
|---|---|---|---|
| ehr-srv-01 | Ubuntu 20.04 LTS | EHR application server | — |
| ehr-db-01 | Ubuntu 20.04 LTS | EHR database (PostgreSQL) | Per Marcus's notes, reachable from the entire 10.10.0.0/16 range rather than restricted to ehr-srv-01 |
| pacs-srv-01 | Windows Server 2016 | PACS imaging server | — |
| billing-srv-01 | Ubuntu 18.04 LTS | Billing/claims processing | Recurring, unresolved performance issues per Marcus's notes; also the system affected by a ransomware incident in January |
| ad-dc-01 | Windows Server 2019 | Primary domain controller | — |
| ad-dc-02 | Windows Server 2019 | Secondary domain controller | — |
| file-srv-01 | Windows Server 2016 | Department file shares | — |
| print-srv-01 | Windows Server 2012 R2 | Print server | `[UNVERIFIED]`; OS end-of-support was October 2023 |
| backup-srv-01 | Ubuntu 22.04 LTS | Backup server (Veeam agent) | Backs up nightly to a NAS located in the same server room, same network, same rack as the source systems |
| web-srv-01 | Ubuntu 20.04 LTS | Public website + patient portal | Positioned in a DMZ per the network diagram |

### Servers — Westside Clinic

| Name | OS/Platform | Function | Notes |
|---|---|---|---|
| ws-srv-01 | Windows Server 2016 | Local file server + scheduling | Confirmed in asset export |
| (possible second server) | Unknown | Unknown | Unconfirmed — referenced only as secondhand mention (Mike Torres to Marcus), never verified. Treated as unconfirmed, not counted as inventory. |

### Servers — Corporate HQ

No on-premise servers. HQ staff use cloud services and connect to Central's infrastructure via site-to-site VPN.

### Network Equipment

| Site | Equipment |
|---|---|
| Central | Cisco core switch (model not specified), 2x Cisco access switches per floor, 1x Fortinet FortiGate 100F firewall, 12x Ubiquiti UniFi wireless access points |
| Westside | 1x unmanaged switch (brand unknown), 1x consumer-grade router (Netgear Nighthawk) — carries the site-to-site VPN to Central; no firewall present |
| HQ | Network managed by the building landlord; MedDefense has its own VLAN on that shared infrastructure |

### Endpoints

| Site | Count | Type |
|---|---|---|
| Central | ~320 | Windows 10 workstations |
| Central | ~60 | Thin clients (clinical areas) |
| Westside | ~45 | Windows 10 workstations |
| HQ | ~120 | Windows 10/11 workstations |
| HQ | ~30 | Laptops (remote-capable) |
| Central | ~25 | iPads used by physicians for rounds — management status unclear |

Note: all endpoint counts are sourced from an Active Directory report stated to be 8 months old; no source claims a current, verified count.

### Medical Devices (IoT)

| Device | Count/Detail | Location | Notes |
|---|---|---|---|
| Patient monitors (Philips IntelliVue) | ~80 units, network-connected | Central | — |
| Infusion pumps (BD Alaris) | ~120 units, network-connected for dosage updates | Central | — |
| MRI scanner (Siemens MAGNETOM) | 1 unit | Central, Radiology | Runs Windows XP per Marcus's note; a referenced supporting file on this was not included in the provided documentation |
| CT scanner (GE Revolution) | 1 unit | Central | Operating system not documented |
| Nurse call system | IP-based | Central | Integrated with the phone system |
| Badge/access system (HID Global) | — | Central (implied; not stated for other sites) | Connected to Active Directory for some doors — extent unspecified |

### Network Topology (per Marcus's draft diagram — explicitly incomplete)

- Central: Internet → FortiGate 100F (with web-srv-01 in a DMZ) → core switch → a single flat network, 10.10.0.0/16, with no VLANs, spanning all floors, workstations, thin clients, medical devices, and the server tier.
- Westside: connects to the FortiGate at Central via IPSec VPN, routed through the Netgear consumer router.
- HQ: connects to the FortiGate at Central via site-to-site VPN, through the building-managed network.
- The diagram's author states it is simplified and that "real topology is messier" — it should be treated as directionally indicative, not authoritative.

---

## 3. Data and Services

### Data Types Handled

- **Protected Health Information (PHI):** electronic health records (via the EHR application/database), medical imaging (PACS), lab results — implied by the presence of Laboratory, Radiology, Oncology, and Maternity departments alongside an EHR system.
- **Financial/billing data:** claims and billing data processed via billing-srv-01.
- **Employee data:** implied by HR's role at Corporate HQ, though no HR-specific system is named in the asset list.
- **Authentication data:** Active Directory credentials organization-wide; a separate shared credential set for the PACS workstation in Radiology ("raduser" account).

### Critical Services Dependent on IT Infrastructure

- **Clinical care delivery at Central:** EHR application and database, PACS imaging, connected patient monitors, and infusion pumps are all described as network-dependent.
- **Diagnostic imaging:** MRI and CT scanners at Central; X-ray/ultrasound at Westside (no MRI at Westside).
- **Billing/claims processing:** billing-srv-01, currently experiencing unresolved recurring issues.
- **Public-facing patient access:** the patient portal, served from web-srv-01.
- **Inter-site connectivity:** Westside and HQ both depend on VPN links back to Central's FortiGate for any centralized service access.
- **Backup/recovery capability:** entirely dependent on backup-srv-01 and its co-located NAS.

### Who Uses These Services

- Clinical staff (physicians, nurses) at Central and Westside — EHR, PACS, medical devices.
- Radiology staff specifically — PACS via a shared login.
- Billing/administrative staff — billing-srv-01.
- Patients — the public patient portal.
- IT/security staff — domain controllers, file shares, backup infrastructure.
- HQ staff (Finance, HR, Legal, Marketing, Executive Leadership) — connect to Central's infrastructure over VPN; specific applications used at HQ are not documented beyond "cloud services."

---

## 4. Known Unknowns

This section lists what the documentation does not establish, flags where sources conflict or admit uncertainty, and separates rumor from fact.

### Explicitly flagged as unverified or incomplete by the source documents themselves

- The entire IT asset export is stated by Sarah Park to be incomplete, compiled from multiple contributors over time.
- print-srv-01 is explicitly marked `[UNVERIFIED]` — not physically confirmed in over a year.
- A possible second server at Westside is unconfirmed — mentioned secondhand (Mike Torres → Marcus), never checked.
- The network diagram is described by its own author as simplified, with the real topology being "messier."
- iPad management status at Central is explicitly noted as unclear ("managed? unclear").
- Whether Central's guest WiFi SSID is genuinely isolated from the internal network is explicitly flagged by Marcus as unverified.
- HQ VPN access control lists have not been audited, per Marcus's own notes.
- Antivirus (Sophos) deployment currency across all machines is not confirmed.
- Whether individual departments use cloud services beyond O365 has not been inventoried.

### Gaps not explicitly flagged, but absent from the documentation

- No documented owner (IT vs. biomedical engineering vs. a vendor) for the medical IoT devices (patient monitors, infusion pumps, MRI, CT).
- No endpoint security detail is provided for Westside or HQ specifically — only that Sophos exists as a contracted service organization-wide.
- No current (non-8-month-old) endpoint count exists for any site.
- Westside's "server closet" is referenced only by description (Sarah Park calls it for "basic needs") — no inventory of what it actually contains beyond ws-srv-01.
- Badge/access system coverage is stated as connected to AD "for some doors" — which doors, and what governs the rest, is not specified.
- No HR system, ERP, or finance system is named despite HR, Finance, and Legal departments existing at HQ — these functions clearly depend on some system(s) not captured in the asset list.
- No information is provided on cloud infrastructure specifics (e.g., where O365 tenant data resides, whether any workloads run in a cloud provider beyond O365).

### Contradictions or tensions between documents

- The org chart states Sarah Park and James Chen are peers, yet also states James holds security policy authority without operational authority — this is not a factual contradiction, but a structural tension directly relevant to why previously identified issues (segmentation, backup budget, shared PACS account) remain unresolved.
- The IT asset list states HQ has "no on-premise servers" and relies on cloud services and VPN to Central, yet no cloud service inventory beyond O365 is documented elsewhere — leaving HQ's actual data flows only partially described.
- Document 5 (network diagram) and Document 3 (Marcus's notes) both describe a flat 10.10.0.0/16 network with no VLANs at Central, which is internally consistent — but the diagram is explicitly marked incomplete by its author, so the *full* extent of what sits on that flat network cannot be treated as fully enumerated.

### Referenced but not provided

- A "separate file" on the MRI's Windows XP status, referenced directly in Marcus's notes, was not included in the provided documentation package.

---

*This summary reflects only information present in, or directly implied by, the provided documentation package. No control evaluation, risk rating, or recommendation is included at this stage — those are addressed in subsequent deliverables.*
