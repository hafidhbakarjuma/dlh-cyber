## Enterprise Data Classification Policy & Governance Framework  
**Status:** Operational Policy & Classification Specification Report  

---

## Executive Summary
Encryption cannot be applied uniformly across all enterprise data without causing immense administrative and financial friction. Data protection is a risk-driven spectrum governed by asset sensitivity. This policy establishes a systematic data classification matrix, defines four distinct classification tiers, provides an intuitive decision tree for employees, and addresses cloud data sovereignty and geographic compliance requirements for MedDefense.

---

## Part 1: Data Type Inventory

MedDefense assets are categorized across six primary data types, mapped directly to their regulatory and operational profiles:
* **Regulated (HIPAA / PHI):** Patient health records, medical imaging (DICOM), clinical notes, diagnoses, and treatment histories.
* **PII (Personally Identifiable Information):** Employee and patient Social Security numbers, home addresses, dates of birth, and contact phone numbers.
* **Financial:** Billing records, patient insurance details, credit card transactions, payroll data, and vendor contracts.
* **Intellectual Property (IP):** Proprietary clinical research, custom medical device configurations, and internal treatment methodologies.
* **Legal:** Compliance audits, active litigation files, regulatory correspondence, and policy legal reviews.
* **Operational:** Staff directories, internal meeting schedules, non-public system architecture diagrams, and general IT ticketing data.

---

## Part 2: Data Classification Levels Matrix

| Level | Access Control | Encryption Required (At Rest & In Transit) | Impact of Exposure |
| :--- | :--- | :--- | :--- |
| **Public** | Unrestricted / Universal access for staff and general public. | **At Rest:** None.<br>**In Transit:** Standard HTTPS (optional for non-sensitive static assets). | Negligible. No risk to operations, privacy, or safety. |
| **Internal** | Authenticated MedDefense employees and approved contractors. | **At Rest:** Standard OS-level or volume encryption.<br>**In Transit:** TLS 1.2+ for internal web services. | Low. Minor operational confusion or internal leakage of non-sensitive schedules. |
| **Confidential** | Authorized department personnel and specific business units on a need-to-know basis. | **At Rest:** AES-256 database/storage encryption.<br>**In Transit:** Encrypted channels (TLS 1.2/1.3, encrypted email/SFTP). | Moderate. Financial loss, regulatory scrutiny, minor breach notification requirements, or contract breaches. |
| **Restricted** | Strictly limited to designated clinical care teams, system administrators, and legal officers via strict RBAC/MFA. | **At Rest:** AES-256 (TDE / LUKS) with dedicated KMS key hierarchy.<br>**In Transit:** Mutual TLS (mTLS) with enforced high-cipher suites. | Critical / Catastrophic. Massive HIPAA penalties, severe patient harm, complete loss of organizational trust, and legal prosecution. |

---

## Part 3: The Classification Decision Tree

MedDefense staff must follow this step-by-step logic workflow to classify new data elements:

```text
[Start: New Data Asset Created/Acquired]
 ├── Is it patient health data or clinical care history?
 │    ├── YES ──> [Restricted]
 │    └── NO  ──> Next Check
 ├── Does it contain credentials, encryption keys, or sensitive PII (e.g., SSN)?
 │    ├── YES ──> [Restricted]
 │    └── NO  ──> Next Check
 ├── Does it contain financial information, billing data, or vendor contracts?
 │    ├── YES ──> [Confidential]
 │    └── NO  ──> Next Check
 ├── Is it internal operational data meant solely for employee collaboration?
 │    ├── YES ──> [Internal]
 │    └── NO  ──> [Public]
```
# Part 4: Data Sovereignty and Geolocation

* **Definition & Compliance Context:** Data sovereignty governs how data is legally bound by the laws and regulations of the physical jurisdiction where it is stored and processed. For healthcare organizations like MedDefense, maintaining strict geographic control over patient backups is critical to upholding HIPAA compliance and fulfilling Business Associate Addendum (BAA) obligations.
* **Jurisdictional Risks:** If cloud backups are migrated to an AWS region outside permitted jurisdictions, legal exposure increases due to conflicting state privacy laws or unauthorized cross-border data transfer implications.
* **Encryption vs. Sovereignty:** While robust customer-managed encryption (such as AES-256 via KMS) ensures that raw data remains unreadable to third parties if intercepted or exposed, **encryption alone does not fully mitigate sovereignty concerns**; regulatory frameworks legally mandate where PHI resides and who maintains jurisdictional control over the decryption keys and infrastructure boundaries.
* **Operational Mandate:** Therefore, MedDefense backups must remain explicitly pinned to approved, compliance-bound regional cloud data centers under an executed BAA.

