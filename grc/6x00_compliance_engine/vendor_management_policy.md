# MedDefense Health Systems - Information Security Policy

## Policy Metadata

| **Details** | |
|---|---|
| **Policy Number** | POL-VMP-2026-03 |
| **Effective Date** | November 1, 2026 |
| **Review Date** | Annual (Next: November 1, 2027) |
| **Policy Owner** | IT Security & Procurement (Joint Ownership) |
| **Approved By** | Chief Information Security Officer (CISO) |

## 1. Purpose and Scope

### 1.1 Purpose

This policy establishes mandatory security, risk assessment, and governance controls for managing third-party vendor relationships. It ensures that external entities interacting with MedDefense Health Systems systems or data maintain security safeguards equal to or exceeding enterprise standards, protecting electronic Protected Health Information (ePHI) and operational infrastructure from supply chain risks.

### 1.2 Scope

This policy applies to all third-party entities, service providers, contractors, and consultants providing goods or services to MedDefense. The scope specifically encompasses:

- Software-as-a-Service (SaaS) providers
- Managed Service Providers (MSPs) and Managed Security Service Providers (MSSPs)
- Cloud Infrastructure Providers (IaaS/PaaS)
- Medical device vendors with network-connected products or maintenance access
- Staffing agencies, clinical contractors, and third parties with physical or logical IT system access

## 2. Vendor Risk Classification Tiers

All vendors must be classified into a risk tier by IT Security and Procurement prior to contract execution or access provisioning based on their level of system access and data exposure.

| **Risk Tier** | **Categorization** | **Definition & Qualification Criteria** | **Representative Examples** |
|---|---|---|---|
| **Tier A** | Critical Risk | Any vendor that creates, receives, maintains, transmits, or processes ePHI, or maintains direct network access to clinical and operational systems. | Backup and disaster recovery providers handling PHI, patient scheduling platforms, diagnostic imaging vendors, EHR (Epic) integration partners. |
| **Tier B** | Standard Risk | Vendors with access to internal MedDefense networks, non-PHI business systems, or non-sensitive internal documentation, without ePHI access. | Facilities management network contractors, internal corporate IT tools, non-clinical SaaS tools without health data. |
| **Tier C** | Low Risk | Vendors with no physical or logical access to MedDefense network systems, internal data, or ePHI. | Office supply vendors, physical maintenance contractors for non-restricted areas, catering services. |

## 3. Pre-Engagement Assessment Requirements

No vendor may be granted system access or receive data until all pre-engagement requirements for their assigned risk tier are fulfilled and formally approved by IT Security.

### 3.1 Tier A Pre-Engagement Requirements (Mandatory)

Before any Tier A vendor is onboarded or permitted data access, the vendor must submit and pass evaluation on all of the following documentation:

- **Third-Party Security Audit:** A valid SOC 2 Type II report (covering Security, Confidentiality, and Availability) or HITRUST CSF certification dated within the preceding 12 months.
- **Security Questionnaire:** A fully completed MedDefense Vendor Security Questionnaire detailing control implementations, encryption, and access governance.
- **Penetration Test Results:** An executive summary of an independent third-party penetration test conducted within the last 12 months, including evidence of critical/high finding remediation.
- **Sub-processor Inventory:** Comprehensive identification of all sub-processors handling MedDefense data, including the specific geographic jurisdictions where data will be stored or processed.
- **Executed Business Associate Agreement (BAA):** A fully executed BAA in accordance with Section 4. No exceptions or conditional waivers are permitted.

### 3.2 Tier B and Tier C Requirements

- **Tier B:** Must complete the MedDefense Security Questionnaire and demonstrate basic security control alignment (e.g., encryption in transit, MFA for remote access).
- **Tier C:** Procurement verification only; no security assessment required unless access scope changes.

## 4. Business Associate Agreement (BAA) Requirements

### 4.1 Mandate

A formal BAA is required for all Tier A vendors and any vendor whose service delivery creates a potential or incidental exposure to ePHI. **Unconditional Requirement:** No Tier A vendor shall be onboarded, integrated, or granted data access without an executed BAA on file.

### 4.2 Minimum Required BAA Content

All MedDefense BAAs must include legally binding clauses that enforce:

- Permitted and required uses and disclosures of ePHI under HIPAA (45 CFR § 164.504(e)).
- Mandatory implementation of administrative, physical, and technical safeguards complying with the HIPAA Security Rule (45 CFR § 164.308, § 164.310, § 164.312).
- Prohibition on unauthorized offshore processing or storage of ePHI without prior written authorization.
- Sub-processor flow-down requirements binding all downstream entities to the exact same restrictions and safeguards.
- **Specific Incident Notification SLA:** Explicit clause requiring the vendor to notify MedDefense within 24 hours of any confirmed or suspected security incident, breach, or unauthorized disclosure affecting MedDefense ePHI.

## 5. Ongoing Vendor Monitoring & Re-assessment

Vendor security risk is not static and requires continuous evaluation throughout the contract lifecycle.

- **Annual Review Cadence:** Tier A vendors must undergo a formal compliance and security review annually. The review requires updating the SOC 2/HITRUST report, re-evaluating sub-processors, and verifying BAA standing. Tier B vendors are reviewed every two years.
- **Out-of-Cycle Re-evaluation Triggers:** An immediate, mandatory out-of-cycle risk assessment is triggered by any of the following events:
  - Material changes in vendor ownership or corporate structure
  - Addition or substitution of downstream sub-processors handling MedDefense data
  - Relocation of data hosting infrastructure or data centers
  - Any confirmed or suspected security breach or major incident experienced by the vendor

## 6. Vendor Offboarding Protocol

Upon contract termination, expiration, or vendor retirement, the following steps must be executed:

- **Access Revocation:** All network, application, database, and physical facility access granted to the vendor or vendor personnel must be completely revoked within 24 hours of effective termination.
- **Data Sanitization / Return:** The vendor must return or provide certified proof of destruction (cryptographic erasure or physical destruction meeting NIST SP 800-88 standards) for all MedDefense data and ePHI within 30 days.
- **Record Retention:** IT Security and Procurement must retain all vendor risk assessment records, executed contracts, BAAs, and audit logs for a minimum of six (6) years from the date of creation or contract termination, strictly adhering to HIPAA regulatory requirements (45 CFR § 164.316(b)(2)).

## 7. Incident Notification & Audit Rights

### 7.1 Breach Notification SLA

Any vendor processing, storing, or handling MedDefense data must notify the MedDefense IT Security team via telephone and high-priority email within 24 hours of discovering a confirmed or suspected security compromise, data loss, ransomware event, or unauthorized access to ePHI.

### 7.2 Independent Investigation Rights

MedDefense retains the explicit right to conduct an independent security investigation and audit of the vendor's systems, log files, and operational controls following a reported incident affecting MedDefense data. The vendor must provide full cooperation, forensic assistance, and relevant audit logs upon request.
