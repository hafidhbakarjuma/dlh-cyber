# MedDefense Health Systems — The Complete Control Matrix

**Prepared by:** Junior Security Analyst
**Prepared for:** James Chen, Deputy CISO
**Purpose:** Single, authoritative consolidation of every security control identified across the project, rated for effectiveness and mapped against the Top 5 Critical Assets.

**Scope note:** This registry includes only controls confirmed to exist today. The compensating control strategy proposed for the MRI workstation (Task 6) is **not** included here, since those controls have not yet been implemented — including them would misrepresent MedDefense's actual current posture to the Board. They remain a pending recommendation, tracked separately.

---

## Part 1: Control Registry

| Control ID | Control Name | Category | Function | Asset(s) Protected | Effectiveness | Evidence/Source |
|---|---|---|---|---|---|---|
| C-001 | DMZ Inbound Firewall Rule | Technical | Preventive | web-srv-01 | **Strong** | Correctly scoped to one system, one port set, fully logged (Task 4) |
| C-002 | Default-Deny Firewall Policy | Technical | Preventive | Entire network | **Strong** | Sound default-deny posture at the perimeter (Task 4) |
| C-003 | Site-to-Site VPN Access Control | Technical | Preventive | Server subnet (via Westside/HQ) | **Weak** | Marcus's own notes flag rules as permitting ALL services once inside the tunnel — far too permissive (Task 4) |
| C-004 | Firewall Traffic Logging | Technical | Detective | Perimeter-facing network | **Weak** | Local only, 30-day retention, never forwarded or alerted on (Task 4, Artifact 8) |
| C-005 | SSH Hardened Configuration | Technical | Preventive | ehr-srv-01 only | **Adequate** | Well-configured, but applied to just 1 of many Linux servers (Task 4) |
| C-006 | SSH Authentication Logging | Technical | Detective | ehr-srv-01 only | **Adequate** | Verbose logging present, but isolated, not centralized (Task 4) |
| C-007 | AD Group Policy Password Enforcement | Technical | Preventive | Windows-joined systems only | **Adequate** | Solid on Windows; Linux systems configured individually and inconsistently (Task 4) |
| C-008 | Endpoint Antivirus Protection (Sophos) | Technical | Preventive | Windows workstations only | **Weak** | Explicitly excludes all Linux and Windows servers — the exact category where two real compromises occurred (Task 3, Task 4) |
| C-009 | Antivirus Threat Detection & Quarantine | Technical | Detective | Windows workstations within Sophos coverage | **Adequate** | Functions well within its scope, but that scope is narrow (Task 4) |
| C-010 | Nightly Backup Job (Veeam) | Technical | Corrective | 6 of ~10 core servers | **Weak** | Co-located with production, major exclusions (PACS, ad-dc-02, print-srv-01, Westside), never fully tested (Task 4, Task 5) |
| C-011 | Decentralized System & Application Logging | Technical | Detective | Entire technical environment | **Weak** | No correlation, no alerting; failed to surface a 2-week active compromise (Task 3, Task 4) |
| C-012 | Documented Password Policy | Administrative | Preventive | All authenticated systems | **Adequate** | Reasonable baseline, but no MFA requirement and 18 months since last review (Task 4) |
| C-013 | Annual Security Awareness Training | Administrative | Preventive | All staff | **Weak** | 58% completion at Westside, no phishing simulations, generic non-healthcare content (Task 4) |
| C-014 | Security Guard Service | Physical | Preventive | Central main entrance only | **Weak** | Single entrance, business hours only, zero coverage at Westside/HQ (Task 4) |
| C-015 | CCTV Camera System (Central) | Physical | Detective | Central entrances/garage only | **Weak** | No coverage of the server room, network closets, or admin wing — the areas that matter most (Task 3, Task 4) |
| C-016 | CCTV Camera (Westside) | Physical | Detective | Westside front entrance only | **Weak** | 48-hour retention window, single camera, single entrance (Task 4) |

**Pending / Not Yet Implemented:** Task 6 proposed 5 compensating controls for the MRI workstation (isolated VLAN, network IPS, dedicated logging, formal risk acceptance policy, restricted physical access to the control room). None are currently in place.

---

## Part 2: Updated Control Summary Matrix

| Category | Preventive | Detective | Corrective | Compensating | Deterrent |
|---|---|---|---|---|---|
| **Technical** | 6 controls — avg **Adequate** (2 Strong, 2 Adequate, 2 Weak) | 4 controls — avg **Weak** (0 Strong, 2 Adequate, 2 Weak) | 1 control — **Weak** | 0 | 0 |
| **Administrative** | 2 controls — avg **Weak–Adequate** (1 Adequate, 1 Weak) | 0 | 0 | 0 | 0 |
| **Physical** | 1 control — **Weak** | 2 controls — avg **Weak** | 0 | 0 | 0 |

**Reading this matrix:** Of 16 total controls, only 2 rate as Strong — both narrow, well-scoped firewall rules. The overwhelming majority (11 of 16) rate Adequate or Weak, and 5 entire cells remain completely empty (both Corrective columns outside Technical, both Compensating columns, and the entire Deterrent column). This confirms, with effectiveness data now added, the same structural pattern identified in Task 5: MedDefense's control base is thin even where controls nominally exist, and almost entirely absent in its ability to detect quietly and recover reliably.

---

## Part 3: Control Coverage Map — Top 5 Critical Assets

| Critical Asset | Preventive | Detective | Corrective | Compensating | Coverage Assessment |
|---|---|---|---|---|---|
| **Infusion Pumps** | None identified | None identified | None identified | None identified | **Unprotected** — no control in this registry covers medical IoT devices in any function. |
| **EHR System** (ehr-srv-01, ehr-db-01) | C-005 (ehr-srv-01 only), C-007 | C-006 (ehr-srv-01 only), C-011 (weak) | C-010 (covers both, but untested at scale) | None | **Partially Protected** — has some coverage in every existing function except Compensating, but ehr-db-01 lacks the hardening applied to ehr-srv-01, and detection remains weak. |
| **Domain Controllers** (ad-dc-01, ad-dc-02) | C-002 (perimeter only — no dedicated host hardening documented) | C-011 (weak, no alerting) | C-010 (ad-dc-01 only — **ad-dc-02 is not backed up**) | None | **Under-Protected** — the single most foundational asset in the environment has no dedicated preventive control of its own, and half its redundancy pair has no recovery path at all. |
| **PACS Server** (pacs-srv-01) | None identified | C-011 (generic Windows Event Viewer logging only) | None (explicitly excluded from backup) | None | **Unprotected** — effectively covered only by passive, unreviewed default OS logging. |
| **billing-srv-01** | None dedicated (C-002 perimeter only; not covered by C-007 or C-008) | C-004, C-011 | C-010 | None | **Under-Protected** — nominal coverage exists on paper, but this server has already been compromised twice despite it, demonstrating the existing controls are insufficient in practice, not just incomplete on paper. |

---

## Summary for the Board

Of the five most critical assets at MedDefense, **none are rated Well-Protected.** One is completely unprotected by any documented control (infusion pumps), a second is protected only by a logging feature nobody actively reviews (PACS), and a third — the domain controllers, on which nearly every other system depends — has a documented backup gap on one of its two redundant nodes. The billing server's "Under-Protected" rating is the most concrete evidence in this entire assessment: it has nominal coverage across three of four control functions, and has still been compromised twice. Control existence is not the same as control effectiveness, and this matrix is the document that proves it.
