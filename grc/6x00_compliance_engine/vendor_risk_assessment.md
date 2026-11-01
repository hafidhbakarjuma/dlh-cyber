# Vendor Security Risk Assessment: CloudVault Medical

**Assessment Date:** 2026-11-01

**Assessor:** Security Analyst / Compliance Officer

**Evaluating Policy:** MedDefense Vendor Management Policy (POL-VMP-2026-03)

**Target Entity:** CloudVault Medical

## 1. Vendor Overview

**Vendor Name:** CloudVault Medical

**Service Type:** Cloud-Based Clinical Data Backup and Disaster Recovery Storage

**Proposed Risk Classification:** Tier A (Critical Risk) — Vendor directly ingests, maintains, and stores clinical data backups containing electronic Protected Health Information (ePHI).

**ePHI Exposure:** Yes (Active ePHI Storage & Processing)

## 2. Risk Findings Matrix

| **Item #** | **Finding (Abbreviated Response)** | **Risk Rating** | **Gap Description** | **Required Action** |
|---|---|---|---|---|
| 1 | SOC 2 Type II valid; dated 11 months ago | Pass | None. Within 12-month policy requirement. | Obtain updated report upon annual rollover. |
| 2 | No HITRUST CSF Certification | Acceptable | None. SOC 2 Type II satisfies alternative audit standard under Section 3.1. | No action required. |
| 3 | Encryption at rest: AES-256 | Pass | None. Meets HIPAA Technical Safeguard standard. | None. |
| 4 | Encryption in transit: TLS 1.2 | Pass | None. Complies with transport security standards. | Ensure TLS 1.3 upgrade path on vendor roadmap. |
| 5 | Penetration test 22 months old; no report provided | Critical Concern | Fails Section 3.1 requirement for annual pen test (within 12 months) and summary of findings/remediation. | Vendor must provide a pen test executive summary dated within 12 months and proof of critical finding remediation. |
| 6 | 2 sub-processors: US CDN & EU data analytics firm | Critical Concern | Discloses EU-based analytics sub-processor handling ePHI without prior written agreement, risking unauthorized offshore export. | Vendor must legally commit to US-only data processing or exclude EU sub-processor from MedDefense data flow. |
| 7 | Primary US datacenter; DR location undisclosed | Concern | Undisclosed DR location risks unapproved international or non-compliant hosting site. | Vendor must disclose exact geographic location and physical security specs of DR facility. |
| 8 | Incident notification SLA: 72 hours post-confirmation | Critical Concern | Conflicts with POL-VMP-2026-03 Section 4.2 & 7.1 requirement of 24-hour SLA upon confirmed or suspected breach. | Vendor must amend contract/BAA SLA to guarantee initial notification within 24 hours. |
| 9 | Data deletion within 90 days of written request | Concern | Exceeds MedDefense 30-day sanitization standard (POL-VMP-2026-03 Section 6.2). | Vendor must contractually align data destruction/return timeframe to within 30 days. |
| 10 | Staff background checks at hire only | Acceptable | Initial screening performed; lack of recurring checks presents low operational risk. | Recommend periodic checks for privileged admins during annual review. |
| 11 | MFA enforced for privileged access (TOTP) | Pass | Complies with enterprise access control requirements. | Enforce hardware-key MFA where feasible. |
| 12 | Monthly scans; quarterly critical remediation | Concern | Quarterly remediation window for critical vulnerabilities is too long for ePHI backup infrastructure. | Vendor must commit to a 14-day SLA for critical vulnerability remediation. |
| 13 | Right-to-audit permitted with 60 days notice | Acceptable | Satisfies independent audit oversight terms. | Ensure notice requirement is reflected in main service agreement. |
| 14 | Willing to execute BAA | Critical Concern | BAA is currently unexecuted. POL-VMP-2026-03 Section 4.1 strictly prohibits ePHI access without a signed BAA. | Fully execute MedDefense-approved BAA prior to contract execution or data transfer. |
| 15 | Annual PHI training for staff | Pass | Meets administrative safeguard training standards. | None. |

## 3. Critical Findings Analysis

### Item 5: Outdated Penetration Test (22 Months Old)

**Specific Risk:** CloudVault Medical's most recent independent penetration test was conducted 22 months ago, and no summary of findings or remediation evidence was provided.

**Regulatory Exposure:** Operating with stale security testing violates NIST CSF 2.0 (ID.RA-01 / PR.IP-12) and HIPAA § 164.308(a)(8) evaluation requirements. For MedDefense, placing ePHI backups on an unverified platform exposes the organization to undetected zero-day or systemic application vulnerabilities, directly risking a catastrophic breach of backup storage.

**Pre-Approval Requirement:** CloudVault Medical must provide an executive summary of an independent third-party penetration test completed within the last 12 months, along with formal attestation that all critical and high-severity findings have been remediated.

### Item 6: Uncontrolled Offshore Sub-processor (EU Analytics)

**Specific Risk:** CloudVault dispatches data to an EU-based data analytics third party without clear controls surrounding ePHI boundary isolation.

**Regulatory Exposure:** Transferring ePHI to an overseas sub-processor without explicit contract boundaries and HIPAA BAA flow-down provisions violates HIPAA § 164.504(e) and MedDefense Vendor Policy Section 4.2. In the event of an OCR audit, MedDefense cannot account for data sovereignty or downstream sub-processor compliance.

**Pre-Approval Requirement:** CloudVault Medical must either formally execute a sub-processor agreement binding the EU entity to HIPAA safeguards, or contractually guarantee that MedDefense clinical backup streams are excluded from EU data routing and analytics.

### Item 8: Non-Compliant Incident Notification SLA (72 Hours)

**Specific Risk:** CloudVault offers a 72-hour notification SLA after internal confirmation of a security incident, whereas MedDefense policy mandates notification within 24 hours of suspected or confirmed discovery.

**Regulatory Exposure:** A 72-hour delay severely impairs MedDefense's internal Incident Response capabilities and compromises MedDefense's ability to comply with legal breach reporting obligations to HHS OCR and affected individuals. Under HIPAA Breach Notification Rule (45 CFR §§ 164.400–414), delay by a business associate does not exempt the covered entity from liability.

**Pre-Approval Requirement:** CloudVault Medical must update the service agreement and BAA notification clause to reflect a 24-hour maximum SLA for notifying MedDefense IT Security of any suspected or confirmed incident.

### Item 14: Unexecuted Business Associate Agreement (BAA)

**Specific Risk:** CloudVault is willing to sign a BAA, but no executed agreement currently exists on file.

**Regulatory Exposure:** Disclosing or transmitting ePHI to a third party without an active, legally binding BAA is a direct, egregious violation of 45 CFR § 164.502(e) and Section 4.1 of the MedDefense Vendor Management Policy. This represents an immediate red flag during an OCR desk audit.

**Pre-Approval Requirement:** A formal, CISO-approved Business Associate Agreement must be fully executed by authorized representatives of both MedDefense and CloudVault Medical before any clinical data integration or contract signature occurs.

## 4. Recommendation

**APPROVE WITH CONDITIONS**

**Rationale:** CloudVault Medical demonstrates strong baseline technical controls, including valid SOC 2 Type II certification, AES-256 data encryption at rest, TLS 1.2 transit encryption, and mandatory MFA on privileged accounts. However, because CloudVault represents a Tier A (Critical Risk) vendor storing enterprise ePHI backups, contract execution and clinical data transfer cannot proceed until the four critical compliance gaps (Penetration Test recency, EU Sub-processor jurisdiction, Breach SLA, and BAA execution) are fully remediated.

## 5. Required Mandatory Conditions

Prior to Dr. Morales signing the CloudVault Medical contract or transmitting any MedDefense data, the vendor must fulfill the following binding conditions:

1. **Executed Business Associate Agreement:** CloudVault Medical must execute the MedDefense standard BAA without modifications to core HIPAA safeguard requirements.

2. **24-Hour Incident SLA Amendment:** CloudVault must amend Section 8 of their Service Level Agreement to guarantee written and telephonic notification to MedDefense IT Security within 24 hours of discovering any confirmed or suspected security incident affecting MedDefense data.

3. **Current Penetration Test Submission:** CloudVault must deliver an executive summary of an independent penetration test dated within the last 12 months, accompanied by an official letter confirming remediation of all Critical and High vulnerabilities.

4. **Data Sovereignty & Sub-Processor Restriction:** CloudVault must provide written contractual confirmation that all MedDefense backup data and derivative datasets will remain strictly within US-based data centers, excluding the EU analytics sub-processor from handling MedDefense PHI.

5. **Data Deletion Alignment:** CloudVault must amend contract terms to guarantee data sanitization and return within 30 days (down from 90 days) following contract termination, providing cryptographic destruction certificates meeting NIST SP 800-88 standards.
