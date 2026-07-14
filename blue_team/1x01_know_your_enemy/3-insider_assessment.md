# The Insider File — MedDefense Insider Threat Analysis

## Project Goal

Analyze insider threat scenarios within the MedDefense healthcare environment. The objective is to distinguish malicious and negligent insider behavior, identify warning signs, connect each scenario to existing MedDefense security gaps, and recommend mitigations.

---

# Scenario 1: The Shared Login

## Classification: Negligent

## Justification

The Radiology department uses a shared account (`raduser/radiology1`) for PACS access. Employees are not intentionally attacking the organization, but sharing credentials removes accountability and makes it impossible to determine which individual accessed patient records.

The issue creates an insider risk because legitimate users can access sensitive medical imaging data without individual attribution.

### Behavioral Indicators

- Multiple employees authenticate using the same account.
- Users do not log out between patient sessions.
- Audit logs show activity from one account across multiple users.

### Existing Control

- Identity and Access Management (IAM)
- Access control policies
- PACS audit logging

### Gap Exploited

**G-002 — No administrative process exists for actively detecting policy violations, anomalous behavior, or emerging threats through non-technical means.**

The absence of periodic access reviews allowed the shared PACS account practice to continue without detection or correction.

**GAP-002 — PACS imaging server has no preventive or corrective control.**

The PACS environment lacks strong security controls around access protection and accountability.

### Recommended Mitigation

Implement unique user accounts with Role-Based Access Control (RBAC), enforce MFA where possible, and configure automatic session timeout/logout on PACS workstations.

---

# Scenario 2: The Ghost Account

## Classification: Malicious

## Justification

A contractor's VPN account remained active for 47 days after contract termination. The account was used three times during off-hours, indicating possible unauthorized access by a former contractor or another individual using abandoned credentials.

This represents a malicious insider threat because terminated users should no longer have access to MedDefense systems.

### Behavioral Indicators

- VPN authentication after contract termination.
- Login activity during unusual hours.
- Active accounts belonging to former employees or contractors.

### Existing Control

- User account management
- VPN access controls
- Authentication logging

### Gap Exploited

**G-002 — No administrative process exists for actively detecting policy violations, anomalous behavior, or emerging threats.**

No periodic access review existed to identify inactive or unnecessary accounts.

**GAP-008 — No formal incident response plan or administrative escalation process exists anywhere in the organization.**

The organization lacks a documented process for handling suspicious account activity.

### Recommended Mitigation

Implement an automated Joiner-Mover-Leaver (JML) process that immediately disables accounts when employees or contractors leave the organization.

---

# Scenario 3: The Personal NAS

## Classification: Negligent

## Justification

Dr. Patel connected a personal NAS device to store research data and "convenience copies" of patient files. Although the intention was improving workflow, the device creates major security risks because it is unmanaged, unencrypted, not monitored, and outside IT visibility.

### Behavioral Indicators

- Unauthorized devices connected to hospital network ports.
- Patient data stored outside approved systems.
- Unknown devices communicating on internal networks.

### Existing Control

- Asset management
- Network monitoring
- Data protection controls

### Gap Exploited

**GAP-007 — Undocumented devices exist on the most sensitive network segments with no active discovery mechanism.**

MedDefense has no continuous mechanism to identify unauthorized devices connected to the network.

**G-005 — No network segmentation exists at Central.**

The flat network allows unauthorized devices to communicate with critical systems.

### Recommended Mitigation

Deploy Network Access Control (NAC) to identify, monitor, and block unauthorized devices while enforcing approved storage locations.

---

# Scenario 4: The Curious Employee

## Classification: Malicious

## Justification

The registration clerk intentionally accessed a politician's medical records without a legitimate business purpose and disclosed private information to a friend. This represents abuse of authorized access.

Although the employee did not modify records, unauthorized viewing and disclosure violates patient privacy.

### Behavioral Indicators

- Employees accessing records unrelated to their job duties.
- Access to VIP or sensitive patient records without justification.
- Unusual EHR search patterns.

### Existing Control

- EHR audit logging
- Access control policies
- Security awareness training

### Gap Exploited

**G-002 — No administrative process exists for actively detecting policy violations, anomalous behavior, or emerging threats.**

No access review process existed to identify inappropriate employee behavior.

**G-004 — Logging exists but nothing aggregates, correlates, or actively alerts on this data.**

Without centralized monitoring, suspicious access patterns may not be detected.

**GAP-005 — No centralized log correlation or automated alerting exists anywhere in the environment.**

EHR activity is recorded but not actively analyzed for abnormal behavior.

### Recommended Mitigation

Implement User and Entity Behavior Analytics (UEBA) to identify unusual patient record access and alert security teams.

---

# Scenario 5: The Overworked Admin

## Classification: Negligent

## Justification

The sysadmin created an automation script to reduce workload but stored Active Directory administrator credentials in plaintext and shared the script through email.

The goal was operational efficiency, but the action created a serious privileged credential exposure risk.

### Behavioral Indicators

- Administrator credentials stored in plaintext files.
- Passwords shared through email.
- Employees creating unofficial workarounds outside security procedures.

### Existing Control

- Administrative access controls
- Credential security policies
- Security awareness training

### Gap Exploited

**GAP-003 — Secondary domain controller has no backup and no dedicated hardening.**

Weak identity infrastructure protection increases the impact of compromised administrative credentials.

**GAP-005 — No centralized log correlation or automated alerting exists anywhere in the environment.**

Suspicious privileged account usage may not be detected quickly.

### Recommended Mitigation

Deploy a Privileged Access Management (PAM) solution to securely store, rotate, and control administrator credentials.

---

# Pattern Assessment

The main systemic weakness making insider threats dangerous at MedDefense is weak identity governance combined with insufficient monitoring and visibility.

Healthcare employees require broad access to patient information to perform their duties, but MedDefense lacks enough detective and preventive controls to determine when legitimate access becomes inappropriate use.

This connects directly to MedDefense Gap Analysis findings:

1. **G-002 — Lack of administrative detection processes**
   
   MedDefense does not perform regular access reviews, security reviews, or behavioral checks, allowing risky practices such as shared accounts and excessive access to continue.

2. **G-004 / GAP-005 — Weak logging and monitoring capability**
   
   Logs exist, but there is no centralized correlation or automated alerting. Insider misuse can continue without detection.

3. **GAP-007 — Lack of asset visibility**
   
   Unauthorized devices such as personal NAS systems can exist inside the network without detection.

The organization has focused heavily on external attackers while leaving internal misuse pathways insufficiently controlled.

---

# Recommended Security Improvements

1. Remove shared accounts and enforce individual authentication.
2. Implement MFA for employees, contractors, and administrators.
3. Automate account disabling during employee termination.
4. Deploy PAM for privileged accounts.
5. Improve EHR access monitoring.
6. Implement UEBA for detecting abnormal behavior.
7. Deploy NAC to control unauthorized devices.
8. Establish regular access reviews and insider threat monitoring.
9. Create formal incident response and escalation procedures.
10. Deploy centralized logging and SIEM capabilities.
