# MedDefense Business Impact Analysis

**Version:** 1.0  
**Classification:** Confidential  
**Prepared by:** MedDefense GRC & Disaster Recovery Team  
**Date:** April 2026  
**CISO approval:** _________________________  **Date:** _________

---

## Executive Summary

Following the HHS OCR desk audit preparation and the identification of severe gaps in MedDefense's legacy disaster recovery documentation, this Business Impact Analysis (BIA) establishes a rigorous, defensible framework for system prioritization. Previous DR plans relied on unverified assumptions, outdated infrastructure references (such as decommissioned physical tape libraries and unverified 4-hour RTOs for Epic EHR), and mathematically impossible RPO-to-backup frequencies.

This BIA evaluates ten core MedDefense systems against four distinct impact dimensions: **Patient Safety Consequence, Regulatory Obligation, Revenue Exposure, and Operational Dependencies.** By defining realistic Recovery Time Objectives (RTO), Recovery Point Objectives (RPO), and Maximum Tolerable Downtime (MTD) values, this document provides the foundation for resilient backup architectures, actionable runbooks, and defensible compliance reporting for the Board Risk Committee and federal regulators.

---

## Methodology

The BIA assessment framework classifies systems into four priority tiers based on the severity of impact over time.

### Impact Criteria

- **Patient Safety Consequence:** Assessed at 1 hour, 4 hours, and 24 hours of outage. Evaluates direct clinical risk, treatment delays, medication errors, and inability to monitor deteriorating patients.
- **Regulatory Impact:** Assessed against HIPAA Security Rule Contingency Plan requirements (45 CFR § 164.308(a)(7)), Joint Commission emergency management standards, and mandatory breach/incident reporting timelines.
- **Revenue Exposure:** Estimated direct and indirect financial loss per hour of downtime, including unbilled clinical services, idle staff, and potential regulatory fines.
- **Operational Dependencies:** Upstream and downstream service relationships that dictate the mandatory restoration sequence during a multi-system outage.

### Priority Tiers

| Tier | Name | Definition | MTD Threshold |
|------|------|------------|---------------|
| **Tier 1** | Critical / Life Safety | Systems whose failure immediately threatens patient life or safety, halts critical care delivery, or causes catastrophic regulatory/financial liability. | MTD < 2 hours |
| **Tier 2** | Critical Operational | Systems essential for ongoing clinical workflows, diagnostics, and patient management. Prolonged outage creates severe operational bottlenecks and clinical risk. | MTD 2–8 hours |
| **Tier 3** | Important / Business Support | Systems supporting administrative, billing, or non-urgent communications. Outages cause operational friction but no direct clinical harm. | MTD 8–24 hours |
| **Tier 4** | Non-Critical | Archival, reporting, or auxiliary security monitoring systems that can be deferred during a disaster. | MTD > 24 hours |

---

## System Impact Assessment

### 1. Active Directory (Identity & Access Management)

**Patient Safety Impact:**
- **1 Hour:** Authentication fails across all clinical workstations; staff cannot log into Epic EHR, LIS, or PACS, delaying acute care admissions and medication orders.
- **4 Hours:** Total halt of electronic clinical workflows; transition to paper-only operations stalls due to inability to verify user credentials or role-based access.
- **24 Hours:** Severe compounding clinical risk across all departments; unauthorized access attempts increase risk of data compromise.

**Regulatory Impact:** HIPAA § 164.312 (Access Control) and § 164.308(a)(7) Contingency Operations failure.

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
- **1 Hour:** Clinicians lose access to patient charts, active medication lists, and allergy histories. Emergency departments rely on verbal handoffs and memory.
- **4 Hours:** Complete reliance on paper downtime forms. High risk of adverse drug events (ADEs) due to lack of historical medication data for deteriorating patients.
- **24 Hours:** Backlog of unentered clinical data creates massive post-recovery reconciliation errors and risks permanent charting gaps.

**Regulatory Impact:** HIPAA § 164.308(a)(7), CMS Conditions of Participation, and Joint Commission HIM standards.

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
- **1 Hour:** Inability to process STAT blood gases, cardiac markers, or critical lab results. ICU and emergency physicians cannot make acute treatment decisions.
- **4 Hours:** Backlog of unprocessed specimen tubes. Diagnostic blind spots widen, leading to delayed interventions for septic or trauma patients.
- **24 Hours:** Critical specimen degradation; complete loss of sample integrity requiring redraws for all pending inpatient labs.

**Regulatory Impact:** CLIA (Clinical Laboratory Improvement Amendments) regulations and HIPAA § 164.308(a)(7).

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
- **1 Hour:** Radiologists cannot view new X-rays, CT scans, or MRIs; surgical planning and trauma assessments are stalled.
- **4 Hours:** Emergency surgeries delayed waiting for imaging clearance; backup reading stations overwhelmed.
- **24 Hours:** Severe diagnostic bottlenecks; imaging queue backlog takes days to clear post-restoration.

**Regulatory Impact:** ACR (American College of Radiology) standards and HIPAA § 164.308(a)(7).

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
- **1 Hour:** Automated dispensing cabinets (ADCs) lose interface with pharmacy management, requiring manual override keys and paper sign-outs.
- **4 Hours:** Increased risk of medication dispensing errors due to manual verification processes bypassing clinical decision support (CDS).
- **24 Hours:** Controlled substance discrepancy risks surge; pharmacist exhaustion from manual verification protocols.

**Regulatory Impact:** DEA regulations on controlled substances and ISMP (Institute for Safe Medication Practices) guidelines.

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
- **1 Hour:** Vital signs monitors, infusion pumps, and ventilator telemetry stop flowing into Epic EHR flowsheets. Nurses must manually chart vitals hourly.
- **4 Hours:** High cognitive load on nursing staff increases risk of missed trend anomalies in ICU/Stepdown units.
- **24 Hours:** Historical bedside device trend data lost for active inpatient admissions.

**Regulatory Impact:** FDA post-market management of cybersecurity in medical devices and HIPAA § 164.308.

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
- **1 Hour:** Total network isolation of all clinical departments, nursing stations, and biomedical equipment. Zero digital communication across hospital wings.
- **4 Hours:** Complete paralysis of digital clinical infrastructure; total reliance on emergency analog runners and paper.
- **24 Hours:** Total systemwide disruption; inability to coordinate patient transfers or emergency responses.

**Regulatory Impact:** HIPAA § 164.312 (Transmission Security) and Life Safety Code.

**Revenue Exposure:** Estimated loss of **$150,000 / hour**.

**Operational Dependencies:** Base infrastructure layer required by all IT and biomedical systems.

| Metric | Value |
|--------|-------|
| MTD | 30 Minutes |
| RTO | 15 Minutes |
| RPO | N/A (Stateless infrastructure) |
| Priority Tier | **Tier 1** |

---

### 8. Email and Secure Messaging

**Patient Safety Impact:**
- **1 Hour:** Clinical care teams cannot use secure paging or messaging apps (e.g., Vocera/TigerConnect equivalents) for urgent consults.
- **4 Hours:** Communication bottlenecks between attending physicians and consulting specialists; reliance on overhead paging.
- **24 Hours:** Administrative and non-urgent clinical coordination severely delayed.

**Regulatory Impact:** HIPAA Security Rule (Encryption and Transmission Security).

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
- **1 Hour:** No direct clinical impact during the initial hour, but inability to verify backup integrity creates vulnerability for secondary failures.
- **4 Hours:** Inability to perform restorative operations if primary systems suffer cascading failures.
- **24 Hours:** Prolonged outage of disaster recovery tooling prevents execution of recovery runbooks.

**Regulatory Impact:** HIPAA § 164.308(a)(7)(ii)(A) (Data Backup Plan).

**Revenue Exposure:** Estimated loss of **$15,000 / hour** (indirect risk exposure).

**Operational Dependencies:** Requires Network Core and Storage Subsystems.

| Metric | Value |
|--------|-------|
| MTD | 4 Hours |
| RTO | 2 Hours |
| RPO | 0 Hours (Active replication/immutable vault) |
| Priority Tier | **Tier 2** |

---

### 10. Security Operations Platform (SIEM / Threat Detection)

**Patient Safety Impact:**
- **1 Hour:** Real-time threat monitoring blinded; no immediate clinical impact.
- **4 Hours:** Reduced visibility into anomalous network activity during a crisis scenario.
- **24 Hours:** Increased vulnerability to opportunistic cyberattacks exploiting distracted IT personnel during an outage.

**Regulatory Impact:** HIPAA Security Rule audit controls and NIST SP 800-53 (Incident Response).

**Revenue Exposure:** Estimated loss of **$5,000 / hour**.

**Operational Dependencies:** Requires Network Core and Active Directory.

| Metric | Value |
|--------|-------|
| MTD | 24 Hours |
| RTO | 12 Hours |
| RPO | 4 Hours |
| Priority Tier | **Tier 4** |

---

## Dependency Map

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

---

## RTO / RPO / MTD Summary Table

| System ID | System Name | Priority Tier | MTD | RTO | RPO |
|-----------|-------------|---------------|-----|-----|-----|
| SYS-01 | Active Directory | Tier 1 | 1 Hour | 30 Minutes | 15 Minutes |
| SYS-02 | Epic EHR | Tier 1 | 2 Hours | 1 Hour | 15 Minutes |
| SYS-03 | Laboratory Information System (LIS) | Tier 1 | 2 Hours | 1 Hour | 1 Hour |
| SYS-04 | PACS / RIS | Tier 2 | 4 Hours | 2 Hours | 2 Hours |
| SYS-05 | Pharmacy Dispensing System | Tier 1 | 2 Hours | 1 Hour | 30 Minutes |
| SYS-06 | Medical Device Integration Gateway | Tier 2 | 4 Hours | 2 Hours | 1 Hour |
| SYS-07 | Network Core | Tier 1 | 30 Minutes | 15 Minutes | N/A |
| SYS-08 | Email and Secure Messaging | Tier 3 | 8 Hours | 4 Hours | 4 Hours |
| SYS-09 | Backup and DR Infrastructure | Tier 2 | 4 Hours | 2 Hours | 0 Hours |
| SYS-10 | Security Operations Platform | Tier 4 | 24 Hours | 12 Hours | 4 Hours |

---

## Assumptions and Limitations

1. **Facility Power & Environmental Controls:** This BIA assumes backup generators and UPS systems function as engineered during the initial 30 minutes of a power loss, allowing graceful shutdown or transition to auxiliary power before cooling failures force hardware shutdowns.

2. **Staff Availability:** Clinical downtime procedures assume adequate staffing levels trained in paper-based chart creation and manual order transcription.

3. **Vendor SLAs:** Third-party cloud and hardware vendor support response times are factored into RTO calculations but assume local administrative override capabilities exist where applicable.

4. **Data Integrity:** RPO values assume successful, verified cryptographic hashing of backups prior to execution of recovery runbooks.
