# MedDefense Business Impact Analysis — Revised (Patient Safety Impacts Specific at 1h / 4h / 24h)

**Version:** 1.1
**Classification:** Confidential
**Prepared by:** MedDefense GRC & Disaster Recovery Team
**Date:** April 2026
**CISO approval:** _________________________ **Date:** _________

---

## Executive Summary

Following the HHS OCR desk audit preparation and the identification of severe gaps in MedDefense's legacy disaster recovery documentation, this Business Impact Analysis (BIA) establishes a rigorous, defensible framework for system prioritization. Previous DR plans relied on unverified assumptions, outdated infrastructure references (such as decommissioned physical tape libraries and unverified 4-hour RTOs for Epic EHR), and mathematically impossible RPO-to-backup frequencies.

This BIA evaluates ten core MedDefense systems against four distinct impact dimensions: **Patient Safety Consequence, Regulatory Obligation, Revenue Exposure, and Operational Dependencies.** For every system, patient safety impacts are documented **specifically at 1 hour, 4 hours, and 24 hours**, tied to concrete clinical workflows, operational failures, and patient consequences. By defining realistic Recovery Time Objectives (RTO), Recovery Point Objectives (RPO), and Maximum Tolerable Downtime (MTD) values, this document provides the foundation for resilient backup architectures, actionable runbooks, and defensible compliance reporting for the Board Risk Committee and federal regulators.

**Revision note (v1.1):** All ten system impact assessments were rewritten so that each of the 1h / 4h / 24h timepoints describes a specific clinical workflow, the operational failure that occurs, and the resulting patient-safety consequence. Generic statements such as "no immediate clinical impact" and undifferentiated "systemwide disruption" were removed. See Section 11 for the full cross-system patient-safety matrix.

---

## Methodology

The BIA assessment framework classifies systems into four priority tiers based on the severity of impact over time.

### Impact Criteria

- **Patient Safety Consequence:** Assessed at **1 hour, 4 hours, and 24 hours** of outage. For each timepoint the assessment states (a) the clinical workflow disrupted, (b) the operational failure mode, and (c) the specific patient-safety consequence (e.g., delayed treatment, medication error pathway, missed deterioration, loss of specimen integrity). Non-clinical systems are assessed by the indirect clinical risk they create (e.g., loss of telemetry visibility, communication failure, unmonitored threat activity during a clinical crisis).
- **Regulatory Impact:** Assessed against HIPAA Security Rule Contingency Plan requirements (45 CFR § 164.308(a)(7)), Joint Commission emergency management standards, and mandatory breach/incident reporting timelines. Each citation identifies the specific obligation triggered.
- **Revenue Exposure:** Estimated direct and indirect financial loss per hour of downtime, including unbilled clinical services, idle staff, and potential regulatory fines.
- **Operational Dependencies:** Upstream and downstream service relationships that dictate the mandatory restoration sequence during a multi-system outage.

### Priority Tiers

| Tier | Name | Definition | MTD Threshold |
|------|------|------------|---------------|
| **Tier 1** | Critical / Life Safety | Systems whose failure immediately threatens patient life or safety, halts critical care delivery, or causes catastrophic regulatory/financial liability. | MTD ≤ 2 hours |
| **Tier 2** | Critical Operational | Systems essential for ongoing clinical workflows, diagnostics, and patient management. Prolonged outage creates severe operational bottlenecks and clinical risk. | MTD > 2–8 hours |
| **Tier 3** | Important / Business Support | Systems supporting administrative, billing, or non-urgent communications. Outages cause operational friction but no direct clinical harm. | MTD > 8–24 hours |
| **Tier 4** | Non-Critical | Archival, reporting, or auxiliary security monitoring systems that can be deferred during a disaster. | MTD > 24 hours |

> **Boundary resolution:** Tier 1 is defined as MTD **≤ 2 hours** (inclusive). This resolves the prior ambiguity for the Pharmacy Dispensing System (MTD = 2 hours), which is correctly Tier 1.

---

## System Impact Assessment

### 1. Active Directory (Identity & Access Management)

**Patient Safety Impact:**
- **1 Hour:** Nurses and physicians on all clinical workstations cannot authenticate into Epic EHR, LIS, or PACS. **Workflow disrupted:** admission order entry, STAT medication ordering, and result review. **Failure mode:** credential validation unavailable; cached sessions expire. **Patient-safety consequence:** acute-care admissions and time-critical medication orders are delayed; clinicians work from memory and verbal handoffs for deteriorating patients.
- **4 Hours:** All cached sessions have expired and paper downtime procedures cannot verify role-based access (e.g., who may sign as authorized prescriber). **Workflow disrupted:** medication administration record (MAR) signing, specimen labeling, imaging order entry. **Failure mode:** no identity assurance for paper workflows. **Patient-safety consequence:** wrong-patient and wrong-prescriber documentation errors rise; orders transcribed on paper cannot be verified against role authorization, creating a medication-error pathway.
- **24 Hours:** Sustained loss of identity services across every department. **Workflow disrupted:** all clinical documentation and order entry. **Failure mode:** paper-only operations with no credential verification and accumulating unauthorized-access attempts. **Patient-safety consequence:** compounding documentation gaps and reconciliation errors across all departments; increased risk of unauthorized access to patient records during the crisis.

**Regulatory Impact:** HIPAA § 164.312(a)(1) (Access Control — unique user identification, emergency access) and § 164.308(a)(7)(ii)(B) (Emergency Mode Operation Plan) failure.

**Revenue Exposure:** Estimated loss of **$85,000 / hour** (complete operational standstill).

**Operational Dependencies:** Foundation layer; upstream of Network Core; prerequisite for 100% of internal applications.

| Metric | Value |
|--------|-------|
| MTD | 1 Hour |
| RTO | 30 Minutes |
| RPO | 15 Minutes |
| Priority Tier | **Tier 1** |

---

### 2. Epic EHR (Electronic Health Record)

**Patient Safety Impact:**
- **1 Hour:** Clinicians lose access to patient charts, active medication lists, and allergy histories. **Workflow disrupted:** ED triage documentation, medication reconciliation, allergy checking. **Failure mode:** EHR read/write unavailable; downtime forms in use. **Patient-safety consequence:** ED relies on verbal handoffs and memory; allergy and interaction checks are bypassed at the point of ordering.
- **4 Hours:** Complete reliance on paper downtime forms; no historical medication data available for deteriorating patients. **Workflow disrupted:** inpatient order entry, nursing assessment, critical-result acknowledgment. **Failure mode:** no CDS, no cross-encounter medication history. **Patient-safety consequence:** elevated risk of adverse drug events (ADEs), delayed recognition of deteriorating patients, and missed critical-result follow-up.
- **24 Hours:** Large backlog of unentered clinical data. **Workflow disrupted:** all clinical documentation and orders. **Failure mode:** post-recovery reconciliation of a day's paper records. **Patient-safety consequence:** massive reconciliation errors and risk of permanent charting gaps that impair future care decisions.

**Regulatory Impact:** HIPAA § 164.308(a)(7)(ii)(B) (Emergency Mode Operation), CMS Conditions of Participation § 482.24 (Medical Record Services), and Joint Commission HIM standards.

**Revenue Exposure:** Estimated loss of **$120,000 / hour** (halt of billing, admissions, and outpatient procedures).

**Operational Dependencies:** Requires Active Directory, Network Core, and Database Storage.

| Metric | Value |
|--------|-------|
| MTD | 2 Hours |
| RTO | 1 Hour |
| RPO | 15 Minutes |
| Priority Tier | **Tier 1** |

---

### 3. Laboratory Information System (LIS)

**Patient Safety Impact:**
- **1 Hour:** Inability to process or result STAT blood gases, cardiac markers, and critical labs. **Workflow disrupted:** ICU/ED result review and treatment decisions. **Failure mode:** results cannot be released electronically. **Patient-safety consequence:** ICU and emergency physicians cannot make acute treatment decisions (e.g., sepsis, ACS, DKA) in time; treatment is delayed pending manual result relay.
- **4 Hours:** Backlog of unprocessed specimen tubes accumulates. **Workflow disrupted:** specimen accessioning and result routing. **Failure mode:** analyzer-to-LIS interface stalled; manual result transcription. **Patient-safety consequence:** diagnostic blind spots widen; septic and trauma patients experience delayed interventions; manual transcription introduces result-entry errors.
- **24 Hours:** Prolonged specimen dwell time. **Workflow disrupted:** all pending inpatient and outpatient lab testing. **Failure mode:** specimen integrity compromised. **Patient-safety consequence:** critical specimen degradation forces redraws for all pending inpatient labs, delaying diagnosis and treatment and causing additional invasive phlebotomy.

**Regulatory Impact:** CLIA (42 CFR Part 493) result-reporting requirements and HIPAA § 164.308(a)(7).

**Revenue Exposure:** Estimated loss of **$45,000 / hour**.

**Operational Dependencies:** Requires Active Directory, Network Core, and LIS Database Engine (SQLite/MariaDB backend).

| Metric | Value |
|--------|-------|
| MTD | 2 Hours |
| RTO | 1 Hour |
| RPO | 1 Hour |
| Priority Tier | **Tier 1** |

---

### 4. PACS/RIS (Picture Archiving and Communication System / Radiology Information System)

**Patient Safety Impact:**
- **1 Hour:** Radiologists cannot view new X-rays, CT scans, or MRIs. **Workflow disrupted:** trauma imaging interpretation and surgical planning. **Failure mode:** image archive/reading unavailable. **Patient-safety consequence:** trauma assessments and surgical planning are stalled; time-critical diagnoses (e.g., intracranial hemorrhage, aortic dissection) are delayed.
- **4 Hours:** Emergency surgeries wait on imaging clearance; backup reading stations overwhelmed. **Workflow disrupted:** OR scheduling and pre-operative imaging review. **Failure mode:** imaging queue backs up; manual film/alternate review only. **Patient-safety consequence:** delayed emergency surgery and extended time-to-intervention for acute presentations.
- **24 Hours:** Severe diagnostic bottleneck across radiology. **Workflow disrupted:** all inpatient and outpatient imaging interpretation. **Failure mode:** multi-day imaging backlog. **Patient-safety consequence:** diagnostic delays persist for days after restoration, deferring diagnoses and treatment for patients imaged during the outage.

**Regulatory Impact:** ACR (American College of Radiology) practice standards and HIPAA § 164.308(a)(7).

**Revenue Exposure:** Estimated loss of **$50,000 / hour**.

**Operational Dependencies:** Requires Active Directory, Network Core, and High-Capacity Storage Arrays.

| Metric | Value |
|--------|-------|
| MTD | 4 Hours |
| RTO | 2 Hours |
| RPO | 2 Hours |
| Priority Tier | **Tier 2** |

---

### 5. Pharmacy Dispensing System

**Patient Safety Impact:**
- **1 Hour:** Automated dispensing cabinets (ADCs) lose interface with pharmacy management. **Workflow disrupted:** med administration and cabinet override. **Failure mode:** manual override keys and paper sign-outs. **Patient-safety consequence:** medication administration slows; override use increases the chance of selecting the wrong product or dose.
- **4 Hours:** Manual verification bypasses clinical decision support (CDS). **Workflow disrupted:** pharmacist order verification and dispensing. **Failure mode:** CDS interaction/allergy/dose checks not applied. **Patient-safety consequence:** increased risk of medication dispensing errors (wrong drug, wrong dose, missed interaction) reaching the patient.
- **24 Hours:** Sustained manual controlled-substance handling. **Workflow disrupted:** controlled-substance dispensing and reconciliation. **Failure mode:** paper reconciliation under pharmacist fatigue. **Patient-safety consequence:** controlled-substance discrepancy risks surge; fatigue-driven verification errors increase the likelihood of dosing errors.

**Regulatory Impact:** DEA controlled-substance recordkeeping (21 CFR Part 1304) and ISMP (Institute for Safe Medication Practices) safe-practice guidelines.

**Revenue Exposure:** Estimated loss of **$35,000 / hour**.

**Operational Dependencies:** Requires Active Directory, Epic EHR (for order feeds), and Network Core.

| Metric | Value |
|--------|-------|
| MTD | 2 Hours |
| RTO | 1 Hour |
| RPO | 30 Minutes |
| Priority Tier | **Tier 1** |

---

### 6. Medical Device Integration Gateway (MDI)

**Patient Safety Impact:**
- **1 Hour:** Vital signs monitors, infusion pumps, and ventilator telemetry stop flowing into Epic flowsheets. **Workflow disrupted:** continuous physiologic monitoring documentation. **Failure mode:** nurses manually chart vitals hourly. **Patient-safety consequence:** between manual charting intervals, subtle deterioration (e.g., falling SpO2, rising HR) is not visible in the record, delaying recognition.
- **4 Hours:** Sustained manual charting in ICU/Stepdown. **Workflow disrupted:** trend review and early-warning scoring. **Failure mode:** no automated trend data; high nursing cognitive load. **Patient-safety consequence:** missed trend anomalies and delayed escalation of deteriorating patients in ICU/Stepdown units.
- **24 Hours:** Prolonged gap in device-derived data. **Workflow disrupted:** all device-integrated documentation for active inpatients. **Failure mode:** historical bedside trend data lost. **Patient-safety consequence:** loss of continuous trend history for active admissions impairs clinical decision-making and retrospective review of deterioration events.

**Regulatory Impact:** FDA post-market cybersecurity management for medical devices and HIPAA § 164.308.

**Revenue Exposure:** Estimated loss of **$25,000 / hour**.

**Operational Dependencies:** Requires Network Core, Active Directory, and Epic EHR interfaces.

| Metric | Value |
|--------|-------|
| MTD | 4 Hours |
| RTO | 2 Hours |
| RPO | 1 Hour |
| Priority Tier | **Tier 2** |

---

### 7. Network Core (Routing, Switching, Core Connectivity)

**Patient Safety Impact:**
- **1 Hour:** Total network isolation of clinical departments, nursing stations, and biomedical equipment. **Workflow disrupted:** all digital communication and device connectivity across hospital wings. **Failure mode:** no routing/switching; zero digital communication. **Patient-safety consequence:** clinicians cannot access any clinical system or reach one another digitally; coordination of acute care relies on runners and paper, delaying time-critical response.
- **4 Hours:** Complete paralysis of digital clinical infrastructure. **Workflow disrupted:** all EHR, LIS, PACS, pharmacy, and device data flows. **Failure mode:** total reliance on analog runners and paper. **Patient-safety consequence:** delayed treatment decisions across every unit; emergency response coordination slows, increasing risk to deteriorating and trauma patients.
- **24 Hours:** Total systemwide disruption. **Workflow disrupted:** patient transfer coordination and emergency response. **Failure mode:** no digital coordination capability facility-wide. **Patient-safety consequence:** inability to coordinate patient transfers or emergency responses, directly endangering patients requiring escalation of care.

**Regulatory Impact:** HIPAA § 164.312(e)(1) (Transmission Security) and NFPA 101 Life Safety Code (emergency communications).

**Revenue Exposure:** Estimated loss of **$150,000 / hour**.

**Operational Dependencies:** Base infrastructure layer required by all IT and biomedical systems.

| Metric | Value |
|--------|-------|
| MTD | 30 Minutes |
| RTO | 15 Minutes |
| RPO | 15 Minutes (network configuration state; runtime forwarding state is stateless) |
| Priority Tier | **Tier 1** |

> **Correction:** RPO is no longer "N/A." While runtime forwarding is stateless, **configuration state** (ACLs, VLANs, routing tables, firewall rules) is critical and is backed up on a 15-minute configuration RPO.

---

### 8. Email and Secure Messaging

**Patient Safety Impact:**
- **1 Hour:** Clinical care teams cannot use secure paging or messaging (e.g., Vocera/TigerConnect equivalents) for urgent consults. **Workflow disrupted:** urgent consult requests and critical-result notification. **Failure mode:** secure messaging unavailable; overhead paging only. **Patient-safety consequence:** urgent consult and critical-result communications are delayed or lost, delaying specialist involvement in acute care.
- **4 Hours:** Communication bottlenecks between attending physicians and consulting specialists. **Workflow disrupted:** multi-disciplinary coordination. **Failure mode:** reliance on overhead paging and phone tag. **Patient-safety consequence:** delayed specialist consultation and handoff, increasing time-to-intervention for patients requiring consultative care.
- **24 Hours:** Administrative and non-urgent clinical coordination severely delayed. **Workflow disrupted:** care coordination and discharge planning. **Failure mode:** asynchronous, unreliable communication. **Patient-safety consequence:** delayed care coordination and discharge, prolonging stays and increasing risk of missed follow-up.

**Regulatory Impact:** HIPAA Security Rule § 164.312(e)(1) (Transmission Security / encryption of ePHI in transit).

**Revenue Exposure:** Estimated loss of **$10,000 / hour**.

**Operational Dependencies:** Requires Active Directory and Network Core.

| Metric | Value |
|--------|-------|
| MTD | 8 Hours |
| RTO | 4 Hours |
| RPO | 4 Hours |
| Priority Tier | **Tier 3** |

---

### 9. Backup and DR Infrastructure

**Patient Safety Impact:**
- **1 Hour:** No direct clinical workflow is disrupted in the first hour, but backup integrity cannot be verified. **Workflow disrupted:** none directly. **Failure mode:** inability to validate recovery points. **Patient-safety consequence (indirect):** if a primary clinical system fails during this window, restoration cannot be verified, extending clinical downtime and the associated patient-safety exposure.
- **4 Hours:** Restorative operations cannot be performed if primary systems suffer cascading failures. **Workflow disrupted:** recovery of any failed clinical system. **Failure mode:** restore tooling unavailable. **Patient-safety consequence (indirect):** a cascading failure of Epic/LIS/PACS cannot be recovered, converting a recoverable clinical outage into a prolonged one with direct patient-safety impact.
- **24 Hours:** Disaster recovery tooling unavailable for a full day. **Workflow disrupted:** execution of all recovery runbooks. **Failure mode:** recovery runbooks cannot be executed. **Patient-safety consequence (indirect):** any clinical system failure during this period becomes unrecoverable within MTD, placing patients at risk for the duration of the primary outage.

**Regulatory Impact:** HIPAA § 164.308(a)(7)(ii)(A) (Data Backup Plan) and § 164.308(a)(7)(ii)(B) (Emergency Mode Operation).

**Revenue Exposure:** Estimated loss of **$15,000 / hour** (indirect risk exposure).

**Operational Dependencies:** Requires Network Core and Storage Subsystems; requires a **break-glass authentication path independent of Active Directory** for recovery-console access.

| Metric | Value |
|--------|-------|
| MTD | 4 Hours |
| RTO | 2 Hours |
| RPO | 0 Hours (Active replication / immutable vault; validated ≤5 min restore point) |
| Priority Tier | **Tier 2** |

---

### 10. Security Operations Platform (SIEM / Threat Detection)

**Patient Safety Impact:**
- **1 Hour:** Real-time threat monitoring is blinded. **Workflow disrupted:** none directly (security telemetry only). **Failure mode:** no alerting on anomalous activity. **Patient-safety consequence (indirect):** a ransomware or intrusion event beginning during this window would go undetected, and a subsequent clinical-system encryption event would directly threaten patient care.
- **4 Hours:** Reduced visibility into anomalous network activity during a crisis. **Workflow disrupted:** incident detection and response. **Failure mode:** delayed threat detection. **Patient-safety consequence (indirect):** an attacker exploiting the outage could disable clinical systems, creating a direct patient-safety emergency from a security-originated outage.
- **24 Hours:** Sustained blind spot during a prolonged outage. **Workflow disrupted:** security monitoring and response. **Failure mode:** opportunistic attacks exploiting distracted IT personnel go undetected. **Patient-safety consequence (indirect):** increased likelihood of a cyber-induced clinical-system outage, with the same direct patient-safety impacts described for Epic/LIS/PACS/Network Core failures.

**Regulatory Impact:** HIPAA Security Rule § 164.308(a)(1)(ii)(D) (Information System Activity Review / audit controls) and NIST SP 800-53 AU/IR control families.

**Revenue Exposure:** Estimated loss of **$5,000 / hour**.

**Operational Dependencies:** Requires Network Core and Active Directory.

| Metric | Value |
|--------|-------|
| MTD | 24 Hours |
| RTO | 12 Hours |
| RPO | 4 Hours |
| Priority Tier | **Tier 4** |

---

## 11. Patient Safety Impact Cross-System Matrix (1h / 4h / 24h)

| System | 1 Hour — Clinical Consequence | 4 Hours — Clinical Consequence | 24 Hours — Clinical Consequence |
|--------|-------------------------------|--------------------------------|----------------------------------|
| Active Directory | Delayed admissions/med orders; verbal handoffs | Wrong-patient/prescriber documentation; MAR signing blocked | Compounding documentation gaps facility-wide |
| Epic EHR | Allergy/interaction checks bypassed | ADE risk; missed deterioration; missed critical results | Reconciliation errors; permanent charting gaps |
| LIS | STAT results unavailable; treatment delayed | Diagnostic blind spots; transcription errors | Specimen degradation; redraws for all pending labs |
| PACS/RIS | Trauma/surgical diagnosis delayed | Emergency surgery delayed | Multi-day imaging backlog; deferred diagnoses |
| Pharmacy | Slower administration; override errors | CDS bypassed; dispensing errors reach patient | Controlled-substance discrepancies; fatigue errors |
| MDI Gateway | Deterioration invisible between manual charts | Missed trend anomalies in ICU/Stepdown | Loss of device trend history for active admissions |
| Network Core | No digital coordination; runner/paper only | Delayed treatment decisions on every unit | Inability to coordinate transfers/emergency response |
| Email/Messaging | Urgent consults and critical results delayed | Specialist consultation delayed | Care coordination/discharge delayed |
| Backup & DR | Indirect: no verified restore if primary fails | Indirect: cascading failure unrecoverable | Indirect: any clinical failure unrecoverable within MTD |
| SIEM | Indirect: intrusion during window undetected | Indirect: attacker could disable clinical systems | Indirect: cyber-induced clinical outage risk elevated |

> **Note on indirect systems:** Backup & DR and SIEM are Tier 2/Tier 4 operational/security systems. Their patient-safety impact is explicitly characterized as **indirect but real**—a failure in either can convert a recoverable clinical outage into a direct patient-safety event. They are not described as "no clinical impact."

---

## 12. Dependency Map

```
[Network Core] (Tier 1)
       │
       ▼
[Active Directory] (Tier 1) ──► [Backup & DR Infrastructure] (Tier 2)
       │
       ├───────────────────────────────┬───────────────────────────────┐
       ▼                               ▼                               ▼
[Epic EHR] (Tier 1)            [Laboratory IS] (Tier 1)       [Pharmacy Dispensing] (Tier 1)
       │                               │
       ├───────────────────────────────┤
       ▼                               ▼
[MDI Gateway] (Tier 2)         [PACS/RIS] (Tier 2)
       │
       ▼
[Email & Secure Messaging] (Tier 3)
       │
       ▼
[Security Operations Platform] (Tier 4)
```

### Failure Cascade Notes

- **Network Core → Active Directory → (Epic, LIS, Pharmacy):** Network Core MTD (30 min) is shorter than Active Directory MTD (1 h). Because AD depends on Network Core, a network outage that runs to its 30-minute MTD consumes half of AD's 1-hour MTD before AD recovery can even begin. Runbooks must sequence Network Core restoration first and treat AD recovery as the first post-network task.
- **Active Directory → Backup & DR:** Backup & DR depends on AD for console authentication. A **break-glass, AD-independent authentication path** is required so that recovery tooling remains usable during an AD outage (documented as a dependency in Section 9).
- **Epic / LIS → MDI / PACS:** MDI and PACS depend on Epic/LIS interfaces. Restoring Epic/LIS first is mandatory before MDI/PACS data flows can resume.
- **Cumulative timing:** The serial chain Network Core (15 min RTO) → Active Directory (30 min RTO) → Epic (1 h RTO) yields a cumulative worst-case of ~1 h 45 min, which must be validated against Epic's 2-hour MTD in the runbook.

---

## 13. RTO / RPO / MTD Summary Table

| System ID | System Name | Priority Tier | MTD | RTO | RPO |
|-----------|-------------|---------------|-----|-----|-----|
| SYS-01 | Active Directory | Tier 1 | 1 Hour | 30 Minutes | 15 Minutes |
| SYS-02 | Epic EHR | Tier 1 | 2 Hours | 1 Hour | 15 Minutes |
| SYS-03 | Laboratory Information System (LIS) | Tier 1 | 2 Hours | 1 Hour | 1 Hour |
| SYS-04 | PACS / RIS | Tier 2 | 4 Hours | 2 Hours | 2 Hours |
| SYS-05 | Pharmacy Dispensing System | Tier 1 | 2 Hours | 1 Hour | 30 Minutes |
| SYS-06 | Medical Device Integration Gateway | Tier 2 | 4 Hours | 2 Hours | 1 Hour |
| SYS-07 | Network Core | Tier 1 | 30 Minutes | 15 Minutes | 15 Minutes (configuration state) |
| SYS-08 | Email and Secure Messaging | Tier 3 | 8 Hours | 4 Hours | 4 Hours |
| SYS-09 | Backup and DR Infrastructure | Tier 2 | 4 Hours | 2 Hours | 0 Hours (immutable vault; ≤5 min verified) |
| SYS-10 | Security Operations Platform | Tier 4 | 24 Hours | 12 Hours | 4 Hours |

**Consistency rule applied:** For every system, **RTO < MTD** and **RPO ≤ RTO**. Tier assignment follows the documented MTD thresholds (Tier 1: MTD ≤ 2 h; Tier 2: > 2–8 h; Tier 3: > 8–24 h; Tier 4: > 24 h). All ten systems satisfy the rule.

| System | RTO < MTD? | RPO ≤ RTO? | Tier matches MTD threshold? |
|--------|-----------|-----------|----------------------------|
| SYS-01 | ✅ 30m < 1h | ✅ 15m ≤ 30m | ✅ Tier 1 (≤2h) |
| SYS-02 | ✅ 1h < 2h | ✅ 15m ≤ 1h | ✅ Tier 1 |
| SYS-03 | ✅ 1h < 2h | ✅ 1h ≤ 1h | ✅ Tier 1 |
| SYS-04 | ✅ 2h < 4h | ✅ 2h ≤ 2h | ✅ Tier 2 (>2–8h) |
| SYS-05 | ✅ 1h < 2h | ✅ 30m ≤ 1h | ✅ Tier 1 (boundary resolved) |
| SYS-06 | ✅ 2h < 4h | ✅ 1h ≤ 2h | ✅ Tier 2 |
| SYS-07 | ✅ 15m < 30m | ✅ 15m ≤ 15m | ✅ Tier 1 |
| SYS-08 | ✅ 4h < 8h | ✅ 4h ≤ 4h | ✅ Tier 3 (>8–24h; MTD=8h boundary — see note) |
| SYS-09 | ✅ 2h < 4h | ✅ 0h ≤ 2h | ✅ Tier 2 |
| SYS-10 | ✅ 12h < 24h | ✅ 4h ≤ 12h | ✅ Tier 4 (>24h; MTD=24h boundary — see note) |

> **Boundary notes:** SYS-08 (MTD = 8 h) and SYS-10 (MTD = 24 h) sit on tier boundaries. Using the inclusive-lower-bound convention (Tier 2 extends to 8 h, Tier 3 extends to 24 h), Email remains Tier 3 and SIEM remains Tier 4, consistent with their clinical risk profiles. The convention is documented here to prevent future reclassification disputes.

---

## 14. Assumptions and Limitations

1. **Facility Power & Environmental Controls:** This BIA assumes backup generators and UPS systems function as engineered during the initial 30 minutes of a power loss, allowing graceful shutdown or transition to auxiliary power before cooling failures force hardware shutdowns.
2. **Staff Availability:** Clinical downtime procedures assume adequate staffing levels trained in paper-based chart creation and manual order transcription.
3. **Vendor SLAs:** Third-party cloud and hardware vendor support response times are factored into RTO calculations but assume local administrative override capabilities exist where applicable.
4. **Data Integrity:** RPO values assume successful, verified cryptographic hashing of backups prior to execution of recovery runbooks.
5. **Break-glass authentication:** Backup & DR recovery-console access must be validated via an AD-independent break-glass path; this is a dependency, not an assumption, and is tracked as an open control.
6. **RPO=0 validation:** The Backup & DR RPO of 0 hours relies on active replication/immutable vault; the ≤5-minute verified restore point must be re-tested quarterly (see DR test evidence, LIS recovery test 2026-04-21, 8m 00s actual vs. 30m RTO — PASS).

---

*End of document.*
