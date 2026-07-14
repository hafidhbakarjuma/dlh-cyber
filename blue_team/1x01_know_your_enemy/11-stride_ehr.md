# MedDefense STRIDE Threat Model - EHR System

Date: July 14, 2026

Classification: CONFIDENTIAL – SECURITY ASSESSMENT

References:
- Project 1x00 Asset Registry
- Project 1x00 Control Matrix
- Project 1x00 Gap Analysis
- Task 8 Technical Vector Assessment
- Task 9 Vector-to-Asset Matrix


# STRIDE Analysis of MedDefense EHR System

## System Under Assessment

The MedDefense EHR environment consists of:

- **ehr-srv-01** - EHR application server
- **ehr-db-01** - PostgreSQL database server
- **Clinical workstations** - End-user systems accessing patient records
- **Network connections** between clinical users, application servers, and databases

The purpose of this STRIDE assessment is to identify threats affecting confidentiality, integrity, availability, and patient safety.


---

# 1. Spoofing (S) - Pretending to be someone or something else

## Threat ID: EHR-S1

**Description:**
An attacker obtains clinician credentials and impersonates an authorized healthcare employee to access the EHR system.

**Attack Vector:**
Phishing / Spear Phishing → stolen credentials → EHR login.

**Impact:**
An attacker could view patient records, modify clinical information, or access confidential medical histories while appearing as a legitimate employee.

**Existing Control:**
- User authentication controls.

**Gap:**
- GAP-002: Weak Identity and Access Management
- GAP-004: Insufficient MFA Protection


---

## Threat ID: EHR-S2

**Description:**
An attacker uses shared PACS or clinical system accounts to impersonate legitimate users accessing healthcare information.

**Attack Vector:**
Default / Shared Credentials → unauthorized authentication.

**Impact:**
Patient information may be accessed without accountability, making it difficult to determine who performed actions in the EHR.

**Existing Control:**
- Basic account management.

**Gap:**
- GAP-002: Weak Authentication Controls
- GAP-008: Shared Account Management Weakness


---

# 2. Tampering (T) - Unauthorized modification of data or code

## Threat ID: EHR-T1

**Description:**
An attacker who gains access to ehr-db-01 modifies patient records stored in PostgreSQL.

**Attack Vector:**
Vulnerable Software Exploit / Flat Network Access → PostgreSQL database access.

**Impact:**
Incorrect medical information could cause incorrect treatment decisions, medication errors, or patient safety incidents.

**Existing Control:**
- Database permissions.

**Gap:**
- GAP-001: Flat Network Architecture
- GAP-005: Limited Monitoring


---

## Threat ID: EHR-T2

**Description:**
A compromised user workstation modifies EHR application files or configuration settings.

**Attack Vector:**
Malware infection → workstation compromise → application manipulation.

**Impact:**
Attackers could alter workflows, corrupt records, or affect availability of clinical services.

**Existing Control:**
- Endpoint protection.

**Gap:**
- GAP-005: Limited Endpoint Monitoring
- GAP-009: Security Awareness Weakness


---

# 3. Repudiation (R) - Denying an action occurred

## Threat ID: EHR-R1

**Description:**
A user denies accessing or modifying patient records because multiple employees share the same account.

**Attack Vector:**
Default / Shared Credentials.

**Impact:**
MedDefense cannot reliably prove who accessed patient information during an investigation.

**Existing Control:**
- Basic logging.

**Gap:**
- GAP-008: Shared Account Usage
- GAP-005: Monitoring Gap


---

## Threat ID: EHR-R2

**Description:**
An attacker modifies or deletes EHR logs after gaining administrative access.

**Attack Vector:**
Privilege Escalation → administrator access.

**Impact:**
Security teams cannot accurately investigate unauthorized patient record access.

**Existing Control:**
- Application logging.

**Gap:**
- GAP-005: No Centralized SIEM Monitoring


---

# 4. Information Disclosure (I) - Unauthorized exposure of information

## Threat ID: EHR-I1

**Description:**
An attacker accesses ehr-db-01 through open PostgreSQL access and extracts patient records.

**Attack Vector:**
Open Service Ports (PostgreSQL 5432) → database compromise.

**Impact:**
Exposure of sensitive healthcare information including medical history, identity data, and insurance information.

**Existing Control:**
- Firewall controls.

**Gap:**
- GAP-001: Flat Network Architecture
- GAP-005: Monitoring Weakness


---

## Threat ID: EHR-I2

**Description:**
A compromised clinical workstation exports patient records from the EHR system.

**Attack Vector:**
Phishing → malware → credential theft → data exfiltration.

**Impact:**
Large-scale patient privacy breach, regulatory penalties, and loss of patient trust.

**Existing Control:**
- User access permissions.

**Gap:**
- GAP-002: Weak Access Control
- GAP-010: Lack of Data Loss Prevention


---

# 5. Denial of Service (D) - Making resources unavailable

## Threat ID: EHR-D1

**Description:**
A ransomware attacker encrypts ehr-srv-01 and ehr-db-01, preventing access to patient records.

**Attack Vector:**
Phishing → malware deployment → ransomware execution.

**Impact:**
Doctors cannot access patient histories, causing delays in diagnosis and treatment.

**Existing Control:**
- Backup systems.

**Gap:**
- GAP-003: Backup Weakness
- GAP-001: Flat Network Enables Spread


---

## Threat ID: EHR-D2

**Description:**
An attacker floods the EHR application server with malicious requests or exploits vulnerable services.

**Attack Vector:**
Vulnerable Software Exploit / Network Attack.

**Impact:**
Clinical staff cannot access electronic records, forcing manual processes.

**Existing Control:**
- Network firewall.

**Gap:**
- GAP-004: Patch Management Weakness


---

# 6. Elevation of Privilege (E) - Gaining unauthorized capabilities

## Threat ID: EHR-E1

**Description:**
A normal clinical user gains administrative privileges and accesses restricted patient information.

**Attack Vector:**
Privilege Abuse / Credential Theft.

**Impact:**
Unauthorized access to sensitive medical information and ability to modify records.

**Existing Control:**
- Role-based permissions.

**Gap:**
- GAP-002: Weak Privilege Management


---

## Threat ID: EHR-E2

**Description:**
An attacker compromises ehr-srv-01 and uses stored database credentials to gain administrator-level database access.

**Attack Vector:**
Vulnerable Software Exploit → credential discovery → privilege escalation.

**Impact:**
The attacker gains full control over patient databases and can modify or steal healthcare information.

**Existing Control:**
- Server authentication.

**Gap:**
- GAP-001: Excessive Network Access
- GAP-005: Monitoring Gap


---

# STRIDE Threat Summary Table

| Category | Threat IDs | Main Risk |
|---|---|---|
| Spoofing | EHR-S1, EHR-S2 | Unauthorized identity use |
| Tampering | EHR-T1, EHR-T2 | Patient data modification |
| Repudiation | EHR-R1, EHR-R2 | Lack of accountability |
| Information Disclosure | EHR-I1, EHR-I2 | Patient data exposure |
| Denial of Service | EHR-D1, EHR-D2 | Clinical service disruption |
| Elevation of Privilege | EHR-E1, EHR-E2 | Excessive access control |


---

# STRIDE Summary for EHR

The greatest risk to the MedDefense EHR system is **Information Disclosure combined with Elevation of Privilege**. Healthcare databases contain highly sensitive patient information, making them valuable targets for ransomware groups, insiders, and attackers using stolen credentials. The combination of a flat network, weak authentication, exposed database services, and limited monitoring allows attackers who gain initial access to move toward the EHR database. Unlike many industries, a compromised healthcare record can directly affect patient safety, making confidentiality and integrity failures especially dangerous.
