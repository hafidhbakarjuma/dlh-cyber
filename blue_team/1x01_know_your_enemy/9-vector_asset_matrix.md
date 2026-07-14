# MedDefense Vector-to-Asset Matrix

## Vector-to-Asset Exposure Map

This matrix maps how different attack vectors can reach MedDefense's most critical assets. It shows potential attack paths and highlights the intersections with the highest risk.

## Critical Assets

| Asset | Description |
|---|---|
| **EHR Database (ehr-db-01)** | Stores patient medical records and sensitive healthcare information. |
| **Billing Server (billing-srv-01)** | Handles financial and operational healthcare data. |
| **Patient Portal (web-srv-01)** | Internet-facing application for patient services. |
| **Backup / NAS Storage** | Contains backups and shared organizational data. |
| **Email Infrastructure (Microsoft 365)** | Main communication platform and phishing target. |
| **Medical IoT Devices** | Connected healthcare equipment and clinical systems. |
| **Active Directory** | Central identity and access management system. |

---

# Attack Vector Matrix

| Attack Vector | EHR Database | Billing Server | Patient Portal | Backup / NAS | Microsoft 365 Email | Medical IoT | Active Directory |
|---|---|---|---|---|---|---|---|
| **Phishing / Spear Phishing** | Phishing email → clinician credentials → AD account compromise → flat network → ehr-db-01 patient data. | Phishing → employee credentials → internal access → billing system compromise. | Phishing → stolen admin credentials → access to web management functions. | Phishing → compromised user account → network access → NAS discovery and backup theft. | Phishing → Microsoft 365 account takeover → email compromise and further attacks. | Phishing → stolen credentials → access to medical device management systems. | Phishing → credential theft → Active Directory account compromise. |
| **VPN Exploit** | VPN compromise → internal network access → flat network movement → EHR database access. | VPN access → internal scanning → billing server exploitation. | VPN access → administrative network access → patient portal compromise. | VPN access → NAS discovery → backup encryption or theft. | VPN credential theft → Microsoft 365 account compromise. | VPN access → medical IoT management interface access. | VPN compromise → AD access → privilege escalation. |
| **Default / Shared Credentials** | PACS/shared credentials → healthcare system access → patient data exposure. | Shared account misuse → billing application access. | Shared admin credentials → patient portal management access. | Default NAS credentials → backup and file access. | Shared accounts → unauthorized email access. | Default medical device credentials → device control. | Shared privileged credentials → Active Directory compromise. |
| **Vulnerable Software Exploit** | Vulnerable server/software → code execution → database access. | Apache/software vulnerability → billing server compromise. | Web application vulnerability → patient portal takeover. | Vulnerable storage services → unauthorized backup access. | Email vulnerabilities → mailbox compromise. | Vulnerable IoT firmware → medical device compromise. | Unpatched systems → AD exploitation. |
| **Supply Chain Compromise** | Vendor access → trusted connection → internal network → EHR access. | Vendor compromise → billing system access. | Third-party service compromise → patient portal access. | Vendor credentials → NAS access. | Compromised vendor email account → phishing campaigns. | Medical device vendor compromise → IoT access. | Vendor account abuse → AD access. |
| **Insider (Malicious)** | Employee with EHR permissions → unauthorized patient record theft. | Insider access → financial data theft or system sabotage. | Administrator abuse → patient portal modification. | Privileged employee → backup deletion or data theft. | Employee account misuse → email data exposure. | Clinical insider → unauthorized device access. | IT insider → privilege abuse and domain compromise. |
| **Insider (Negligent)** | Employee clicks phishing link → stolen credentials → EHR exposure. | User mistake → malware infection → billing system compromise. | Employee exposes credentials → portal compromise. | User error → malware reaches shared storage. | Phishing mistake → Microsoft 365 account takeover. | Unsafe device usage → medical IoT infection. | Weak password reuse → AD account compromise. |
| **Physical Access** | Unauthorized workstation access → saved credentials → EHR access. | Physical access → server room/device compromise. | Physical access → web administration compromise. | Physical access → NAS theft or tampering. | Stolen device → email account access. | Physical access → medical device manipulation. | Physical access → workstation compromise → AD credentials theft. |

---

# Most Connected Assets

## 1. Active Directory

Active Directory is reachable through almost every attack path because it controls authentication and authorization across MedDefense systems. Compromise of AD can provide attackers access to multiple critical assets.

## 2. EHR Database

The EHR database is a primary target because many vectors can eventually reach patient information through stolen credentials, network movement, or vulnerable systems.

## 3. Backup / NAS Storage

Backup systems are highly connected because ransomware groups target them to prevent recovery and increase extortion pressure.

---

# Most Versatile Attack Vectors

## 1. Phishing / Spear Phishing

Phishing reaches the largest number of assets because it targets users first and can provide credentials, malware delivery, and access to internal systems.

## 2. VPN Exploit

VPN compromise provides direct access into the internal environment and allows attackers to bypass external defenses.

## 3. Insider (Malicious)

Insiders already have legitimate access, allowing them to reach sensitive systems without needing to bypass many technical controls.

---

# Matrix Assessment Summary

The highest-risk intersections for MedDefense are:

1. **Phishing → Active Directory → Flat Network → EHR Database**
2. **VPN Compromise → Internal Network → Critical Servers**
3. **Ransomware → Backup/NAS Targeting → Operational Disruption**

These attack paths combine high likelihood vectors with high-value assets and represent the greatest risk to patient safety and business operations.
