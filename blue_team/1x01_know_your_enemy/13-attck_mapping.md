# MedDefense ATT&CK Mapping

**Date:** July 14, 2026

**Classification:** CONFIDENTIAL – SECURITY ASSESSMENT

**References:**
- attack-scenarios-attck.txt
- Project 1x00 Asset Registry
- Project 1x00 Gap Analysis
- MITRE ATT&CK Enterprise Framework

---

# Scenario Alpha: "Operation Flatline" – Ransomware Campaign

**Threat Actor:** BlackReef Affiliate (Organized Crime / Ransomware-as-a-Service)

---

## Step 1: Target Selection

**Description:**  
The BlackReef affiliate purchases a list of healthcare organizations running Fortinet VPN appliances from an Initial Access Broker.

- **ATT&CK Tactic:** Reconnaissance
- **Technique:** Gather Victim Network Information (**T1590**)
- **Alternative:** Gather Victim Identity Information (**T1589**)
- **MedDefense Factor:** Public-facing FortiGate VPN appliance and healthcare organization profile make MedDefense an attractive ransomware target.

---

## Step 2: Spear Phishing Attack

**Description:**  
Sarah Park receives a fake Fortinet support email containing a malicious Office document that executes PowerShell.

- **ATT&CK Tactic:** Initial Access
- **Technique:** Phishing: Spearphishing Attachment (**T1566.001**)
- **Alternative:** Spearphishing Link (**T1566.002**)
- **MedDefense Factor:** Limited phishing awareness training, Office macros enabled, and no advanced email filtering.

---

## Step 3: Reverse Shell & Persistence

**Description:**  
The PowerShell payload downloads a reverse shell and creates a scheduled task for persistence.

- **ATT&CK Tactic:** Persistence
- **Technique:** Scheduled Task/Job (**T1053.005**)
- **Alternative:** Command and Scripting Interpreter: PowerShell (**T1059.001**)
- **MedDefense Factor:** No EDR or SIEM monitoring to detect PowerShell abuse or scheduled task creation.

---

## Step 4: Internal Network Discovery

**Description:**  
The attacker enumerates Active Directory and discovers critical servers across the flat network.

- **ATT&CK Tactic:** Discovery
- **Technique:** Network Service Scanning (**T1046**)
- **Alternative:** System Network Configuration Discovery (**T1016**)
- **MedDefense Factor:** Flat network architecture (GAP-001) allows unrestricted visibility of internal systems.

---

## Step 5: Credential Dumping

**Description:**  
Mimikatz is used to dump cached credentials, revealing the NTLM hash for the svc_backup account.

- **ATT&CK Tactic:** Credential Access
- **Technique:** OS Credential Dumping (**T1003.001**)
- **Alternative:** LSASS Memory (**T1003.001**)
- **MedDefense Factor:** Domain administrator credentials cached on workstations and insufficient privileged account management.

---

## Step 6: Pass-the-Hash Attack

**Description:**  
The attacker authenticates to the Domain Controller using the stolen NTLM hash.

- **ATT&CK Tactic:** Lateral Movement
- **Technique:** Pass the Hash (**T1550.002**)
- **Alternative:** Remote Services (**T1021**)
- **MedDefense Factor:** No MFA, flat network, and unrestricted administrative access.

---

## Step 7: Database Theft

**Description:**  
The attacker exports the PostgreSQL patient database and HR files before encryption.

- **ATT&CK Tactic:** Collection
- **Technique:** Data from Information Repositories (**T1213**)
- **Alternative:** Archive Collected Data (**T1560**)
- **MedDefense Factor:** PostgreSQL is accessible across the network, and no DLP or monitoring detects large database exports.

---

## Step 8: Backup Destruction

**Description:**  
The attacker deletes NAS backups and Windows Shadow Copies.

- **ATT&CK Tactic:** Impact
- **Technique:** Inhibit System Recovery (**T1490**)
- **Alternative:** Data Destruction (**T1485**)
- **MedDefense Factor:** Backups are connected to the production network and protected only by Domain Admin credentials.

---

## Step 9: Enterprise-Wide Ransomware Deployment

**Description:**  
A malicious Group Policy Object deploys ransomware to all Windows systems.

- **ATT&CK Tactic:** Impact
- **Technique:** Data Encrypted for Impact (**T1486**)
- **Alternative:** Group Policy Modification (**T1484.001**)
- **MedDefense Factor:** Domain Admin compromise, flat network, and lack of network segmentation enable organization-wide encryption.

---

# Scenario Beta: "The Quiet Departure" – Insider Data Theft

**Threat Actor:** Malicious Insider

---

## Step 1: Insider Motivation

**Description:**  
Maria decides to steal patient records after learning she will be laid off.

- **ATT&CK Tactic:** Resource Development
- **Technique:** Acquire Capabilities (**T1588**) *(planning stage)*
- **Alternative:** N/A
- **MedDefense Factor:** Insider risk monitoring is absent and employee behavior is not assessed after termination notices.

---

## Step 2: Data Assessment

**Description:**  
Maria identifies what information she can legitimately access through the billing and EHR systems.

- **ATT&CK Tactic:** Discovery
- **Technique:** File and Directory Discovery (**T1083**)
- **Alternative:** Data from Information Repositories (**T1213**)
- **MedDefense Factor:** Excessive read permissions and no monitoring of abnormal record access.

---

## Step 3: Patient Data Export

**Description:**  
Maria exports patient records from the EHR over several weeks.

- **ATT&CK Tactic:** Collection
- **Technique:** Data from Information Repositories (**T1213**)
- **Alternative:** Data from Local System (**T1005**)
- **MedDefense Factor:** Export functionality is available to all read-only users, and audit logs are never reviewed.

---

## Step 4: Copy to USB

**Description:**  
Patient records are copied onto a personal USB drive.

- **ATT&CK Tactic:** Collection
- **Technique:** Data Staged (**T1074**)
- **Alternative:** Peripheral Device Discovery (**T1120**)
- **MedDefense Factor:** No USB restriction GPO and no endpoint DLP controls.

---

## Step 5: Delete Evidence

**Description:**  
Maria deletes exported files from her workstation.

- **ATT&CK Tactic:** Defense Evasion
- **Technique:** File Deletion (**T1070.004**)
- **Alternative:** Indicator Removal on Host (**T1070**)
- **MedDefense Factor:** Endpoint monitoring is absent and audit logs are not proactively reviewed.

---

## Step 6: Steal Database Credentials

**Description:**  
Maria copies the billing database configuration file containing credentials.

- **ATT&CK Tactic:** Credential Access
- **Technique:** Credentials from Password Stores (**T1555**)
- **Alternative:** Unsecured Credentials (**T1552**)
- **MedDefense Factor:** Database credentials are stored in plaintext configuration files.

---

## Step 7: Delayed Account Deactivation

**Description:**  
Maria's VPN account remains active for five days after leaving the organization.

- **ATT&CK Tactic:** Persistence
- **Technique:** Valid Accounts (**T1078**)
- **Alternative:** External Remote Services (**T1133**)
- **MedDefense Factor:** No automated HR offboarding process and delayed account deactivation.

---

## Step 8: Remote Database Theft

**Description:**  
Maria connects through the VPN and extracts additional billing records directly from the database.

- **ATT&CK Tactic:** Exfiltration
- **Technique:** Exfiltration Over Web Service (**T1567**)
- **Alternative:** Data from Information Repositories (**T1213**)
- **MedDefense Factor:** Active VPN account, unrestricted database access, and no monitoring of unusual data transfers.

---

# ATT&CK Coverage Assessment

Both attack scenarios demonstrate repeated use of several MITRE ATT&CK tactics, particularly **Initial Access**, **Discovery**, **Credential Access**, **Collection**, **Defense Evasion**, **Persistence**, and **Impact/Exfiltration**. Although Scenario Alpha is an external ransomware campaign and Scenario Beta is an insider data theft incident, both exploit the same weaknesses within MedDefense: weak identity management, excessive privileges, a flat network, insufficient monitoring, poor account lifecycle management, and inadequate data protection controls. This shows that MedDefense should prioritize detection capabilities around credential theft, privileged account abuse, abnormal data access, PowerShell activity, USB device usage, VPN logins, and large-scale data transfers. Deploying SIEM, EDR, MFA, DLP, and continuous log monitoring would significantly improve visibility across the ATT&CK tactics observed in both scenarios.

---

# ATT&CK Tactic Summary

| Scenario | Primary Tactics Observed |
|----------|---------------------------|
| Operation Flatline | Reconnaissance, Initial Access, Persistence, Discovery, Credential Access, Lateral Movement, Collection, Impact |
| The Quiet Departure | Resource Development, Discovery, Collection, Defense Evasion, Credential Access, Persistence, Exfiltration |

---
