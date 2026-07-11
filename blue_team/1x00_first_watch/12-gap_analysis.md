# MedDefense Health Systems — The Gap Analysis

**Prepared by:** Junior Security Analyst
**Prepared for:** James Chen, Deputy CISO
**Source:** Asset Criticality Assessment (Task 8), Data Map (Task 9), Complete Control Matrix (Task 10), Shadow IT Findings (Task 11)

---

## Prioritized Gap List

---

**Gap ID:** GAP-001
**Title:** Medical IoT devices (infusion pumps) have no control coverage of any kind
**Affected Asset(s):** Infusion Pumps — Medical IoT (**Critical**, Task 8)
**Data at Risk:** Medical Device / IoT Telemetry — dosage delivery data (**Restricted**, Task 9)
**Current Control Status:** None. Task 10's Coverage Map rates this asset "Unprotected" across all four control functions.
**What is Missing:** Preventive (no segmentation, no vendor-recommended isolation applied), Detective (no monitoring of device traffic), and Corrective (no incident response path for a compromised device).
**Risk Level:** Critical
**Risk Justification:** Affects a Critical-rated asset and Restricted data, with literally no detective or corrective control in place — meets the Critical threshold on both conditions simultaneously.
**Potential Impact:** A compromised infusion pump could deliver an incorrect medication dose in real time, directly endangering a specific patient. This is not speculative — the manufacturer's own 18-month-old security bulletin confirms exploitable CVEs, with the recommended mitigation never implemented.

---

**Gap ID:** GAP-002
**Title:** PACS imaging server has no preventive or corrective control
**Affected Asset(s):** PACS Server (pacs-srv-01) — PACS/Imaging (**Critical**, Task 8)
**Data at Risk:** Medical Imaging Data (**Restricted**, Task 9)
**Current Control Status:** Only generic, unreviewed Windows Event Viewer logging (C-011, rated Weak). No antivirus, no dedicated hardening, explicitly excluded from the backup job.
**What is Missing:** Preventive (no AV, no hardening) and Corrective (zero backup coverage — "too large" per IT).
**Risk Level:** Critical
**Risk Justification:** Critical-rated asset, Restricted data, with no detective control worth relying on and no corrective control at all.
**Potential Impact:** Any compromise, corruption, or ransomware event affecting this server results in permanent, unrecoverable loss of diagnostic imaging data — unlike every other core server, there is no backup to fall back on.

---

**Gap ID:** GAP-003
**Title:** Secondary domain controller (ad-dc-02) has no backup and no dedicated hardening
**Affected Asset(s):** Domain Controllers — Identity/AD (**Critical**, Task 8)
**Data at Risk:** System Credentials (**Restricted**, Task 9)
**Current Control Status:** Perimeter firewall protection only (C-002); generic decentralized logging (C-011, Weak); backup covers ad-dc-01 but explicitly **not** ad-dc-02 ("redundant with ad-dc-01" per IT).
**What is Missing:** Corrective (no backup for one of two redundancy nodes) and dedicated Preventive control (no host-level hardening documented for either domain controller specifically).
**Risk Level:** Critical
**Risk Justification:** Critical-rated foundational asset, Restricted data, with no corrective control for half of its own redundancy pair — the exact scenario redundancy is supposed to prevent.
**Potential Impact:** If ad-dc-01 and ad-dc-02 are both compromised or damaged in the same incident (a realistic outcome on a flat, unsegmented network), there is no way to recover authentication services for the organization, cascading into simultaneous unavailability of nearly every Windows-dependent clinical and administrative system.

---

**Gap ID:** GAP-004
**Title:** Antivirus/endpoint protection does not cover Linux servers or Windows servers
**Affected Asset(s):** billing-srv-01 (**High**), ehr-srv-01/ehr-db-01 (**Critical**), pacs-srv-01 (**Critical**), backup-srv-01, web-srv-01 — spans EHR, Billing, PACS, and Backup & Storage categories
**Data at Risk:** Patient Medical Records, Financial/Billing Data, Medical Imaging Data (all **Restricted**, Task 9)
**Current Control Status:** Sophos (C-008) explicitly excludes all Linux servers and all Windows servers; only Windows workstations are covered.
**What is Missing:** Preventive control (endpoint protection) across the entire server tier — the layer hosting nearly every Critical asset in the registry.
**Risk Level:** Critical
**Risk Justification:** Affects multiple Critical-rated assets and Restricted data; this is not a theoretical detective/corrective gap — it is a confirmed root cause, already directly responsible for a real, undetected compromise.
**Potential Impact:** This is the confirmed root cause of the billing-srv-01 cryptominer persisting undetected for approximately two weeks (Task 3). The same blind spot applies to every other server in this list, including those hosting the EHR database and PACS imaging.

---

**Gap ID:** GAP-005
**Title:** No centralized log correlation or automated alerting exists anywhere in the environment
**Affected Asset(s):** Cross-cutting — affects nearly every Critical asset simultaneously (EHR, PACS, Identity/AD, Billing, Network Core)
**Data at Risk:** All Restricted and Confidential data categories (Task 9) — a compromise of any of them would go unnoticed regardless of classification
**Current Control Status:** Individual logs exist per system (firewall, SSH, Windows Event Viewer, syslog, EHR audit log) but are never aggregated, correlated, or alerted on (C-004, C-011, both rated Weak).
**What is Missing:** A functioning Detective control at the organizational level — the individual pieces exist, but the capability they're meant to enable does not.
**Risk Level:** Critical
**Risk Justification:** Affects Critical assets and Restricted data organization-wide, with no effective detective control despite the appearance of logging infrastructure — a gap in capability, not just documentation.
**Potential Impact:** A genuine intrusion can persist indefinitely without triggering any alert. This already happened once, for roughly two weeks, on a server holding financial data — the same blind spot applies equally to the EHR database, PACS, and every domain controller.

---

**Gap ID:** GAP-006
**Title:** Network closet has no functioning lock and displays switch management credentials in plaintext
**Affected Asset(s):** Network Core (**Critical**, Task 8), Physical Security Systems (**High**, Task 8)
**Data at Risk:** System Credentials (**Restricted**, Task 9)
**Current Control Status:** No physical Preventive control (door does not lock); no physical Detective control (no camera covers this location, per Task 4/10).
**What is Missing:** Both Preventive and Detective functions, in the physical category, for the single location housing the credentials to the organization's core switching infrastructure.
**Risk Level:** Critical
**Risk Justification:** Affects a Critical-rated asset category (Network Core) and Restricted data, with no detective or corrective control whatsoever for this specific exposure.
**Potential Impact:** Anyone who walks past this unlocked closet can read live switch credentials and reconfigure, disable, or monitor traffic across the entire flat network — undermining every technical control built on top of that network simultaneously.

---

**Gap ID:** GAP-007
**Title:** Undocumented devices exist on the most sensitive network segments with no active discovery mechanism
**Affected Asset(s):** Network Core (**Critical**, Task 8) — specifically UNKNOWN-01 (server subnet) and the abandoned Raspberry Pi (2nd floor)
**Data at Risk:** Potentially any data traversing the segments these devices sit on, including System Credentials and Patient Medical Records (**Restricted**, Task 9)
**Current Control Status:** None. These devices were found only through a one-time manual network scan (Task 7); no standing detection mechanism exists.
**What is Missing:** A Detective control capable of continuously identifying unauthorized devices — the current "control" is a single scan that happened to catch these two, not a repeatable capability.
**Risk Level:** Critical
**Risk Justification:** Affects the Critical-rated Network Core, with no detective control for the underlying problem (unauthorized devices going unnoticed) — the scan was a one-off discovery, not a functioning safeguard.
**Potential Impact:** An unidentified device sitting on the same subnet as the domain controllers and EHR database could already be an active foothold, and MedDefense would have no way to know — this is an unbounded risk sitting directly next to the organization's most critical infrastructure.

---

**Gap ID:** GAP-008
**Title:** No formal incident response plan or administrative escalation process exists anywhere in the organization
**Affected Asset(s):** Cross-cutting — every Critical and High-rated asset category is affected simultaneously, since response capability applies organization-wide, not per-asset
**Data at Risk:** All categories, all classifications (Task 9) — response quality during an actual incident depends on this regardless of what was breached
**Current Control Status:** None. The Administrative/Detective and Administrative/Corrective cells of the Control Matrix (Task 10) are both entirely empty.
**What is Missing:** Both Detective and Corrective functions in the Administrative category, organization-wide.
**Risk Level:** Critical
**Risk Justification:** Affects Critical assets and Restricted data across the board, with a complete, entire-function absence of both detective and corrective administrative capability.
**Potential Impact:** Response to any future incident — regardless of which Critical asset is involved — will continue to be improvised rather than procedural, as already demonstrated twice on billing-srv-01, directly extending both detection time and recovery time for every category in this registry.

---

**Gap ID:** GAP-009
**Title:** Billing infrastructure has nominal control coverage that has already failed twice in practice
**Affected Asset(s):** billing-srv-01 — Billing Infrastructure (**High**, Task 8)
**Data at Risk:** Financial/Billing Data (**Restricted**, Task 9)
**Current Control Status:** Perimeter firewall (C-002), basic logging (C-004, C-011), nightly backup (C-010) — all present but each rated Weak or Adequate at best (Task 10).
**What is Missing:** No function is completely absent, but every function present is incomplete: no AV, no dedicated hardening, no alerting, and an untested-at-scale backup.
**Risk Level:** High
**Risk Justification:** Per the prioritization rule, this affects a High-rated asset with incomplete control coverage — formally High, not Critical, though the Board should note this is the only gap in the entire list with two confirmed real-world compromises behind it, arguably warranting Critical-level urgency regardless of its formal asset-criticality tier.
**Potential Impact:** A third compromise of this server, following the same pattern as the first two, remains entirely plausible given that the underlying control weaknesses (no AV, no centralized detection) have not changed since either prior incident.

---

**Gap ID:** GAP-010
**Title:** Employee HR records have no confirmed storage location or documented protection
**Affected Asset(s):** Admin Endpoints (HQ) (**Medium**, Task 8)
**Data at Risk:** Employee HR Records (**Confidential**, Task 9)
**Current Control Status:** Unknown. No HR/ERP system was ever identified in any source document (a Known Unknown carried since Task 0).
**What is Missing:** Total visibility gap — it is not possible to state which control functions apply, because the data's location itself is undocumented.
**Risk Level:** High
**Risk Justification:** Per the prioritization rule, Confidential data with incomplete (in this case, entirely unknown) control coverage meets the High threshold independent of the hosting asset's Medium criticality rating.
**Potential Impact:** MedDefense cannot assess, let alone guarantee, protection for employee financial and personal data it cannot even confirm the location of — and the Incident F laptop already sat on the same network segment as the HR file share for three weeks without detection.

---

**Gap ID:** GAP-011
**Title:** Physical security coverage exists only at Central, and only partially
**Affected Asset(s):** Physical Security Systems (**High**, Task 8) — specifically Westside Clinic and Corporate HQ
**Data at Risk:** Whatever data or systems are physically accessible at those sites, including Westside Clinic servers and workstations
**Current Control Status:** Guard service and CCTV exist only at Central's main entrance (C-014, C-015); Westside has one camera covering only its front entrance (C-016); HQ relies entirely on landlord-managed building security with no MedDefense visibility into footage.
**What is Missing:** Preventive and Detective physical controls at two of three sites are either absent or minimal.
**Risk Level:** High
**Risk Justification:** Affects a High-rated asset category with incomplete coverage — full coverage exists at only one of three sites.
**Potential Impact:** Physical compromise of Westside's unlocked-adjacent infrastructure (already flagged as having no firewall either) or unauthorized access at HQ would go largely or entirely unrecorded, consistent with the physical exposure pattern already identified at Central.

---

**Gap ID:** GAP-012
**Title:** Security awareness training has low completion and no phishing simulation program
**Affected Asset(s):** Clinical & Administrative Endpoints (**Medium**, Task 8) — the human layer across all sites
**Data at Risk:** Broadly applicable — phishing/social engineering can be a path to any data category depending on which credentials are compromised
**Current Control Status:** Annual training exists (C-013) but completion is only 58% at Westside, content is generic, and no phishing simulation has ever been run.
**What is Missing:** Nothing is completely absent, but the existing Preventive control reduces risk only partially given low completion and lack of realistic simulation.
**Risk Level:** Medium
**Risk Justification:** Per the prioritization rule, this affects a Medium-rated asset category with a partial control in place that reduces but does not eliminate risk.
**Potential Impact:** Nearly half of Westside staff have not completed even baseline awareness training, leaving a meaningful portion of the workforce more susceptible to phishing or social engineering — a plausible initial access vector for any of the more severe gaps above.

---

## Gap Distribution Summary

**By risk level:**
- Critical: 8 (GAP-001 through GAP-008)
- High: 3 (GAP-009, GAP-010, GAP-011)
- Medium: 1 (GAP-012)
- Low: 0 — no gap qualified for Low under the prioritization rules, because no asset category in Task 8's Criticality Matrix was rated Low; the lowest-rated categories (Clinical Endpoints, Admin Endpoints) are both Medium.

**Asset categories with the most gaps:**
Physical Security Systems and the Admin/Clinical Endpoint categories each appear in two gaps directly. However, the more significant pattern is that **3 of the 12 gaps (25%) are cross-cutting rather than tied to any single asset category** — the antivirus coverage gap (GAP-004), the log correlation gap (GAP-005), and the missing incident response plan (GAP-008) each affect multiple Critical-rated categories simultaneously. This means MedDefense's biggest structural weakness is not concentrated in one asset type; it is the absence of organization-wide capabilities that would otherwise catch or contain a problem regardless of which specific asset it hit.

**Concentration by control function:**
Across all 12 gaps, **Detective** and **Corrective** functions are the most consistently missing or inadequate — Detective is cited as absent or ineffective in 7 of 12 gaps, and Corrective in 5 of 12. Preventive controls are inconsistent (strong in a few places, weak in most). **Compensating** controls are absent from every single gap in this list without exception — consistent with the Control Matrix (Task 10) showing zero Compensating controls anywhere in the organization. This confirms, at the highest level of analysis in this project, the same finding first surfaced in Task 5: MedDefense can sometimes stop an initial attempt, but has almost no ability to notice or recover once one succeeds.
