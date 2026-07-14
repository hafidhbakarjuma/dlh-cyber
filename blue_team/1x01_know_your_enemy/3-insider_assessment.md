# The Insider File — MedDefense Insider Threat Analysis

## Project Goal

Analyze insider threat scenarios within the MedDefense healthcare environment. The objective is to distinguish malicious and negligent insider behavior, identify warning signs, connect incidents to existing security control gaps from Project 1x00, and recommend mitigations.

---

# Scenario 1: The Shared Login

## Classification: Negligent

### Justification
The Radiology department uses a shared account (`raduser/radiology1`) for PACS access. Employees are not intentionally attacking the organization, but sharing credentials removes accountability and makes it impossible to determine which individual accessed patient records.

### Behavioral Indicators

- Multiple employees authenticate using the same account.
- Users do not log out between patient sessions.
- Audit logs show activity from one account across different users.

### Existing Control (from 1x00)

- Identity and Access Management (IAM)
- Access control policies
- User accountability requirements

### Gap Exploited (from 1x00)

- Weak identity management
- Lack of unique user accounts
- Poor access accountability

### Recommended Mitigation

Implement unique user accounts with Role-Based Access Control (RBAC) and enforce automatic session timeout/logout on PACS workstations.

---

# Scenario 2: The Ghost Account

## Classification: Malicious

### Justification

A contractor's VPN account remained active for 47 days after contract termination. The account was used three times during off-hours, indicating possible unauthorized access by a former contractor or an attacker using abandoned credentials.

### Behavioral Indicators

- VPN authentication after contract termination.
- Login activity during unusual hours.
- Active accounts belonging to former employees or contractors.

### Existing Control (from 1x00)

- User lifecycle management
- VPN access controls
- Identity monitoring

### Gap Exploited (from 1x00)

- Poor account deprovisioning process.
- Weak identity lifecycle management.
- Lack of automated termination controls.

### Recommended Mitigation

Implement an automated Joiner-Mover-Leaver (JML) process that disables accounts immediately when employment or contracts end.

---

# Scenario 3: The Personal NAS

## Classification: Negligent

### Justification

Dr. Patel connected a personal NAS device to store research data and "convenience copies" of patient files. Although the goal was improving workflow, the device creates major security risks because it is unmanaged, unencrypted, not monitored, and outside IT control.

### Behavioral Indicators

- Unauthorized devices connected to hospital network ports.
- Patient data stored outside approved systems.
- Unusual internal data transfers.

### Existing Control (from 1x00)

- Asset management
- Data protection controls
- Network monitoring

### Gap Exploited (from 1x00)

- Shadow IT
- Lack of asset visibility
- Unauthorized devices connected to the network

### Recommended Mitigation

Deploy Network Access Control (NAC) to identify, monitor, and block unauthorized devices while enforcing approved storage solutions.

---

# Scenario 4: The Curious Employee

## Classification: Malicious

### Justification

The registration clerk intentionally accessed a politician's medical records without a legitimate business purpose and disclosed private information to a friend. This represents abuse of authorized access.

### Behavioral Indicators

- Employees accessing records unrelated to their job duties.
- Access to VIP or sensitive patient records without clinical justification.
- Unusual EHR search patterns.

### Existing Control (from 1x00)

- Audit logging
- Least privilege access
- Security awareness training

### Gap Exploited (from 1x00)

- Excessive permissions.
- Insufficient monitoring of user activity.
- Weak detection of inappropriate access.

### Recommended Mitigation

Implement User and Entity Behavior Analytics (UEBA) to identify unusual patient record access and alert security teams.

---

# Scenario 5: The Overworked Admin

## Classification: Negligent

### Justification

The sysadmin created an automation script to reduce workload but stored Active Directory administrator credentials in plaintext and shared the script through email. The intention was operational efficiency, but the practice created a serious security vulnerability.

### Behavioral Indicators

- Administrator credentials stored in plaintext files.
- Passwords shared through email.
- Employees creating unofficial solutions outside security procedures.

### Existing Control (from 1x00)

- Privileged Access Management (PAM)
- Credential security policies
- Security awareness training

### Gap Exploited (from 1x00)

- Weak privileged account protection.
- Lack of secure credential storage.
- Poor administrative access controls.

### Recommended Mitigation

Deploy a Privileged Access Management (PAM) solution to securely store, rotate, and control administrator credentials.

---

# Pattern Assessment

The main systemic weakness making insider threats dangerous at MedDefense is weak Identity and Access Management combined with insufficient monitoring and visibility.

Healthcare employees require broad access to patient information to perform their duties, but MedDefense lacks enough controls to determine when legitimate access becomes inappropriate use.

This connects directly to Project 1x00 findings:

1. **Weak IAM controls** — Shared accounts, excessive permissions, and poor account lifecycle management reduce accountability and allow unauthorized access.

2. **Insufficient monitoring and logging** — Without strong audit trails and behavior monitoring, suspicious employee activity may remain unnoticed.

3. **Shadow IT and asset visibility gaps** — Unauthorized devices such as personal NAS systems can store sensitive data without security controls.

The organization has focused heavily on defending against external attackers while leaving internal misuse pathways insufficiently controlled.

---

# Recommended Security Improvements

1. Remove shared accounts and enforce individual authentication.
2. Implement MFA for employees, contractors, and administrators.
3. Automate account disabling during employee termination.
4. Deploy PAM for privileged accounts.
5. Improve EHR access monitoring.
6. Implement UEBA for detecting abnormal behavior.
7. Deploy NAC to control unauthorized devices.
8. Strengthen insider threat awareness training.
