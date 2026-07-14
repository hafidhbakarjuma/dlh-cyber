# MedDefense Threat Scenarios

**Date:** July 14, 2026

**Classification:** CONFIDENTIAL – SECURITY ASSESSMENT

**References:**
- Project 1x00 Asset Registry
- Project 1x00 Gap Analysis
- Task 6 Threat Actor Matrix
- Task 7 Attack Surface Map
- Task 8 Technical Vector Assessment
- Task 9 Vector-to-Asset Matrix
- Task 10 Kill Chains
- Task 11 STRIDE (EHR)
- Task 12 STRIDE Across the Architecture
- Task 13 MITRE ATT&CK Mapping

---

# Scenario 1 – Operation Flatline

## Threat Actor
**BlackReef Ransomware-as-a-Service (RaaS) Affiliate** (Organized Crime)

## Motivation
Financial gain through **double extortion** (data theft + ransomware).

## Initial Vector
Spear phishing email with a malicious attachment targeting an IT administrator.

## Attack Surface Exploited
- Human Surface
- External Surface
- Internal Surface

---

## Attack Sequence

### Step 1 – Initial Access *(ATT&CK: Initial Access)*
The attacker sends a phishing email disguised as a Fortinet security update to the IT Director. The attachment executes a PowerShell payload after being opened.

### Step 2 – Persistence *(ATT&CK: Persistence)*
A reverse shell is installed, and a scheduled task is created to maintain long-term access to the compromised workstation.

### Step 3 – Discovery & Credential Access *(ATT&CK: Discovery / Credential Access)*
The attacker maps the flat network, discovers Active Directory, EHR, NAS, and billing servers, then uses Mimikatz to steal cached administrator credentials.

### Step 4 – Lateral Movement & Collection *(ATT&CK: Lateral Movement / Collection)*
Using Pass-the-Hash, the attacker compromises **ad-dc-01**, accesses **ehr-db-01**, exports approximately **35 GB** of patient records, and steals HR and financial documents.

### Step 5 – Impact *(ATT&CK: Impact)*
Backups on **NAS-01** are deleted, ransomware is deployed through Group Policy, and every Windows workstation becomes encrypted.

---

## STRIDE Categories Triggered

- Spoofing
- Elevation of Privilege
- Information Disclosure
- Denial of Service
- Tampering

---

## MedDefense Assets Impacted

- ad-dc-01
- ad-dc-02
- ehr-srv-01
- ehr-db-01
- billing-srv-01
- file-srv-01
- NAS-01
- Domain Workstations

---

## Business Impact

- Hospital operations interrupted for approximately two weeks.
- Patient records become unavailable during treatment.
- Ambulances diverted to nearby hospitals.
- Estimated recovery cost exceeds **$3 million**.
- HIPAA investigation and regulatory penalties.
- Loss of patient confidence due to exposure of approximately **50,000 PHI records**.

---

## Gaps Exploited

- **GAP-001** – Flat network enables unrestricted lateral movement.
- **GAP-003** – No SIEM to detect attacker activity.
- **GAP-004** – No MFA on privileged accounts.
- **GAP-005** – Backup server accessible from production network.
- **GAP-008** – Weak phishing resistance and credential protection.

---

## Detection Opportunities

| Step | Detection Opportunity | Recommended Control |
|------|-----------------------|---------------------|
| Step 1 | Detect malicious email | Secure Email Gateway |
| Step 2 | Detect PowerShell abuse | EDR + SIEM |
| Step 3 | Detect Mimikatz and network scans | Wazuh SIEM |
| Step 4 | Detect abnormal database exports | Database Monitoring + DLP |
| Step 5 | Detect GPO changes and ransomware | Active Directory Monitoring + Immutable Backups |

---

# Scenario 2 – Trusted Employee, Stolen Data

## Threat Actor

Malicious Insider (Billing Department Employee)

## Motivation

Financial gain by selling protected health information.

## Initial Vector

Legitimate access abused.

## Attack Surface Exploited

- Human Surface
- Internal Surface

---

## Attack Sequence

### Step 1 – Discovery *(ATT&CK: Discovery)*

A billing employee identifies that patient records can be exported without approval or volume restrictions.

### Step 2 – Collection *(ATT&CK: Collection)*

Patient records are exported daily from the EHR and billing applications during normal business hours.

### Step 3 – Collection *(ATT&CK: Collection)*

CSV files containing patient information are copied to a personal USB drive.

### Step 4 – Defense Evasion *(ATT&CK: Defense Evasion)*

The employee deletes local copies from the workstation to reduce evidence of the theft.

### Step 5 – Persistence / Exfiltration *(ATT&CK: Persistence / Exfiltration)*

After employment ends, the employee connects through the still-active VPN account and extracts additional billing records using saved database credentials.

---

## STRIDE Categories Triggered

- Information Disclosure
- Repudiation
- Elevation of Privilege

---

## MedDefense Assets Impacted

- billing-srv-01
- ehr-db-01
- Clinical Workstations
- VPN Gateway

---

## Business Impact

- Approximately **3,000 patient records** stolen.
- HIPAA breach notification.
- Regulatory investigation.
- Identity theft risk for patients.
- Loss of public trust.
- Legal action against MedDefense.

---

## Gaps Exploited

- **GAP-002** – Excessive user permissions.
- **GAP-003** – Audit logs are never reviewed.
- **GAP-004** – VPN lacks MFA.
- **GAP-010** – No DLP controls.
- **GAP-011** – Weak employee offboarding process.

---

## Detection Opportunities

| Step | Detection Opportunity | Recommended Control |
|------|-----------------------|---------------------|
| Step 2 | Detect unusual export volume | UEBA + SIEM |
| Step 3 | Detect USB storage usage | Device Control Policy |
| Step 4 | Detect suspicious file deletion | EDR |
| Step 5 | Detect VPN login after termination | Automated HR Offboarding + MFA |

---

# Scenario 3 – Trusted Vendor Compromise

## Threat Actor

External Attacker using a compromised third-party vendor (Supply Chain)

## Motivation

Long-term espionage and theft of sensitive healthcare information.

## Initial Vector

Compromised vendor remote access account.

## Attack Surface Exploited

- External Surface
- Internal Surface

---

## Attack Sequence

### Step 1 – Initial Access *(ATT&CK: Initial Access)*

Attackers steal credentials belonging to a MedDefense medical software vendor responsible for maintaining the EHR platform.

### Step 2 – Persistence *(ATT&CK: Persistence)*

Using legitimate vendor credentials, the attackers establish remote access to **ehr-srv-01** during off-hours.

### Step 3 – Discovery *(ATT&CK: Discovery)*

The attackers identify PostgreSQL databases, Domain Controllers, backup servers, and shared storage through the flat network.

### Step 4 – Collection *(ATT&CK: Collection)*

Patient records and medical images are copied in small batches to avoid detection.

### Step 5 – Exfiltration *(ATT&CK: Exfiltration)*

Sensitive healthcare information is transferred to attacker-controlled cloud storage for several months before discovery.

---

## STRIDE Categories Triggered

- Spoofing
- Information Disclosure
- Elevation of Privilege
- Repudiation

---

## MedDefense Assets Impacted

- ehr-srv-01
- ehr-db-01
- pacs-srv-01
- ad-dc-01
- Vendor VPN Access

---

## Business Impact

- Long-term compromise lasting several months.
- Continuous theft of patient records.
- Exposure of diagnostic images.
- Regulatory penalties.
- Vendor relationship terminated.
- Significant reputational damage due to delayed detection.

---

## Gaps Exploited

- **GAP-001** – Flat network.
- **GAP-003** – No SIEM monitoring.
- **GAP-004** – Vendor access without MFA.
- **GAP-010** – No DLP monitoring.
- **GAP-012** – Weak vendor access management.

---

## Detection Opportunities

| Step | Detection Opportunity | Recommended Control |
|------|-----------------------|---------------------|
| Step 1 | Detect unusual vendor login | MFA + Conditional Access |
| Step 2 | Detect off-hours remote access | SIEM + UEBA |
| Step 3 | Detect internal reconnaissance | Network IDS |
| Step 4 | Detect abnormal database queries | Database Activity Monitoring |
| Step 5 | Detect outbound PHI transfers | DLP + Network Monitoring |

---

# Scenario Summary

| Scenario | Threat Actor | Primary Vector | Most Critical Asset | Primary Business Impact |
|----------|--------------|----------------|---------------------|-------------------------|
| Operation Flatline | BlackReef RaaS | Spear Phishing | Active Directory & EHR | Organization-wide ransomware |
| Trusted Employee, Stolen Data | Malicious Insider | Legitimate Access Abuse | Billing & EHR Databases | Patient data theft |
| Trusted Vendor Compromise | Supply Chain Attacker | Vendor Remote Access | EHR & PACS | Long-term data exfiltration |

---
