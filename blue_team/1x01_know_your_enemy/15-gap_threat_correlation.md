# MedDefense Gap–Threat Correlation

**Date:** July 14, 2026

**Classification:** CONFIDENTIAL – SECURITY ASSESSMENT

**References:**
- Project 1x00 Task 12 & 13 – Gap Analysis
- Project 1x01 Task 6 – Threat Actor Matrix
- Project 1x01 Task 10 – Kill Chains
- Project 1x01 Task 14 – Threat Scenarios

---

# Gap-to-Threat Correlation

## GAP-001 – Flat Network Architecture

**Gap Description:**  
All major systems (EHR, Active Directory, Billing, PACS, NAS, Medical IoT) communicate on the same internal network with minimal segmentation.

**Original Risk Level:** Critical

**Threat Actors**
- Ransomware Groups
- Nation-State APT
- Malicious Insider
- Negligent Insider
- Opportunistic Attackers

**Kill Chains**
- KC-1: Apache RCE → Domain-wide Ransomware
- KC-2: Phishing → EHR Data Theft
- KC-3: VPN → Medical Device Compromise
- KC-4: Supply Chain → EHR Backdoor
- KC-5: Insider → Ransomware

**Scenarios**
- Scenario 1
- Scenario 2
- Scenario 3

**Updated Risk Level:** **Critical (Unchanged)**

**Justification**

Every major attack path depends on unrestricted lateral movement. Network segmentation would interrupt nearly every attack before critical assets are reached.

---

## GAP-002 – Weak Identity & Access Management

**Gap Description**

Users have excessive privileges and shared accounts remain in use.

**Original Risk Level:** High

**Threat Actors**

- Malicious Insider
- Ransomware Groups
- Nation-State APT

**Kill Chains**

- KC-2
- KC-4
- KC-5

**Scenarios**

- Scenario 2
- Scenario 3

**Updated Risk Level:** **Upgraded to Critical**

**Justification**

Threat analysis showed attackers repeatedly abusing excessive permissions rather than exploiting software vulnerabilities.

---

## GAP-003 – No Centralized SIEM / Security Monitoring

**Gap Description**

Security events are collected but not centrally monitored or correlated.

**Original Risk Level:** High

**Threat Actors**

- All Threat Actors

**Kill Chains**

- KC-1
- KC-2
- KC-3
- KC-4
- KC-5

**Scenarios**

- Scenario 1
- Scenario 2
- Scenario 3

**Updated Risk Level:** **Critical**

**Justification**

Every attack remained undetected because MedDefense lacks centralized monitoring, alerting, and incident correlation.

---

## GAP-004 – No Multi-Factor Authentication (MFA)

**Gap Description**

VPN, privileged accounts, and remote access rely only on passwords.

**Original Risk Level:** High

**Threat Actors**

- Organized Crime
- Nation-State APT
- Opportunistic Attackers
- Malicious Insider

**Kill Chains**

- KC-1
- KC-2
- KC-3
- KC-4
- KC-5

**Scenarios**

- Scenario 1
- Scenario 2
- Scenario 3

**Updated Risk Level:** **Critical**

**Justification**

Credential theft appears in nearly every attack path. MFA would have prevented several successful compromises.

---

## GAP-005 – Backup Infrastructure Connected to Production Network

**Gap Description**

NAS backups are accessible from the production domain.

**Original Risk Level:** High

**Threat Actors**

- Ransomware Groups

**Kill Chains**

- KC-1
- KC-5

**Scenarios**

- Scenario 1

**Updated Risk Level:** High (Unchanged)

**Justification**

Although mainly exploited by ransomware, destroying backups dramatically increases recovery costs and downtime.

---

## GAP-006 – Legacy Operating Systems

**Gap Description**

Windows XP MRI workstation and Windows Server 2012 remain operational.

**Original Risk Level:** High

**Threat Actors**

- Ransomware Groups
- Nation-State APT

**Kill Chains**

- KC-3

**Scenarios**

- Scenario 3

**Updated Risk Level:** High (Unchanged)

**Justification**

Legacy systems remain attractive entry points but affect fewer attack paths than identity and network weaknesses.

---

## GAP-007 – Medical Device Security Weaknesses

**Gap Description**

Medical IoT devices use default credentials and are not isolated.

**Original Risk Level:** Medium

**Threat Actors**

- Organized Crime
- Nation-State APT

**Kill Chains**

- KC-3

**Scenarios**

- Scenario 3

**Updated Risk Level:** **Upgraded to High**

**Justification**

Threat modeling demonstrated the possibility of direct patient harm through compromised medical devices, increasing the overall business risk.

---

## GAP-008 – Weak Email Security & Phishing Protection

**Gap Description**

Employees remain vulnerable to phishing attacks.

**Original Risk Level:** Medium

**Threat Actors**

- Organized Crime
- Opportunistic Attackers

**Kill Chains**

- KC-1
- KC-2

**Scenarios**

- Scenario 1

**Updated Risk Level:** **Upgraded to High**

**Justification**

Most ransomware attacks begin with phishing. Successful phishing enables multiple kill chains.

---

## GAP-009 – Limited Security Awareness Training

**Gap Description**

Security awareness completion rates remain below organizational targets.

**Original Risk Level:** Medium

**Threat Actors**

- Organized Crime
- Social Engineers

**Kill Chains**

- KC-1
- KC-2

**Scenarios**

- Scenario 1

**Updated Risk Level:** High

**Justification**

Employees remain the easiest entry point for attackers using phishing and social engineering.

---

## GAP-010 – No Data Loss Prevention (DLP)

**Gap Description**

Sensitive information can be copied to USB devices or cloud storage without monitoring.

**Original Risk Level:** Medium

**Threat Actors**

- Malicious Insider
- Nation-State APT

**Kill Chains**

- KC-2
- KC-4
- KC-5

**Scenarios**

- Scenario 2
- Scenario 3

**Updated Risk Level:** **Upgraded to High**

**Justification**

Both insider and supply chain attacks successfully exfiltrate sensitive patient data because no DLP solution exists.

---

## GAP-011 – Weak Employee Offboarding

**Gap Description**

User accounts remain active after employment ends.

**Original Risk Level:** Medium

**Threat Actors**

- Malicious Insider

**Kill Chains**

- KC-5

**Scenarios**

- Scenario 2

**Updated Risk Level:** High

**Justification**

Scenario 2 demonstrated that delayed account deactivation allowed unauthorized VPN access after termination.

---

## GAP-012 – Weak Vendor Access Management

**Gap Description**

Vendor remote access lacks strong authentication and continuous monitoring.

**Original Risk Level:** High

**Threat Actors**

- Nation-State APT
- Organized Crime

**Kill Chains**

- KC-4

**Scenarios**

- Scenario 3

**Updated Risk Level:** High (Unchanged)

**Justification**

Supply chain attacks increasingly target trusted vendors to bypass perimeter security.

---

# Re-Prioritized Gap List

| Rank | Gap ID | Updated Risk | Status |
|------|---------|--------------|--------|
| 1 | GAP-001 | Critical | — |
| 2 | GAP-003 | Critical | ▲ Increased Priority |
| 3 | GAP-004 | Critical | ▲ Increased Priority |
| 4 | GAP-002 | Critical | ▲ Increased Priority |
| 5 | GAP-005 | High | — |
| 6 | GAP-012 | High | — |
| 7 | GAP-007 | High | ▲ Upgraded |
| 8 | GAP-010 | High | ▲ Upgraded |
| 9 | GAP-008 | High | ▲ Upgraded |
| 10 | GAP-009 | High | ▲ Upgraded |
| 11 | GAP-011 | High | ▲ Upgraded |
| 12 | GAP-006 | High | — |

---

# The Critical Three

## 1. GAP-001 – Flat Network Architecture

Appears in **all five kill chains** and **all three threat scenarios**. Eliminating unrestricted lateral movement would stop attackers from reaching the EHR, Active Directory, backups, and medical devices.

---

## 2. GAP-004 – No Multi-Factor Authentication

Present in **every major attack path**, allowing stolen credentials to be used immediately. MFA would block ransomware operators, compromised vendors, and former employees.

---

## 3. GAP-003 – No SIEM / Security Monitoring

Every scenario remained undetected because MedDefense lacks centralized monitoring. Deploying SIEM and EDR would dramatically reduce attacker dwell time and improve incident response.

---

# The Surprise

## GAP-010 – No Data Loss Prevention (DLP)

**Original Rating:** Medium

**Updated Rating:** High

Initially, DLP appeared less urgent because it does not prevent attackers from gaining access. However, after completing the kill chains and threat scenarios, it became clear that almost every successful attack ultimately involves **data theft**. Whether through ransomware double extortion, malicious insiders copying patient records, or compromised vendors extracting healthcare data, the absence of DLP significantly increases regulatory exposure and financial loss. The threat analysis showed that protecting sensitive data after attackers gain access is just as important as preventing initial compromise.

---

# Executive Summary

Threat analysis confirms that **identity security, network segmentation, and continuous monitoring** are the three most important defensive priorities for MedDefense. Together, **GAP-001 (Flat Network)**, **GAP-003 (No SIEM)**, and **GAP-004 (No MFA)** appear across nearly every kill chain and threat scenario developed throughout this project. Addressing these three weaknesses would eliminate or significantly disrupt the majority of realistic attack paths against MedDefense, providing the greatest reduction in overall cyber risk.
