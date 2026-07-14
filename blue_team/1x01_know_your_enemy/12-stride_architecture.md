# MedDefense STRIDE Across the Architecture

**Date:** July 14, 2026

**Classification:** CONFIDENTIAL – SECURITY ASSESSMENT

**References:**
- Project 1x00 Asset Registry
- Project 1x00 Network Scan
- Project 1x00 Gap Analysis
- Task 11 STRIDE for EHR

---

# System 1: PACS / Medical Imaging

## Architecture Notes

Components:
- pacs-srv-01
- MRI workstation (Windows XP)
- Radiology workstations
- Shared PACS account
- Flat internal network

The PACS system stores diagnostic medical images and communicates with radiology workstations across the internal network.

| STRIDE | Threat | Impact | Severity |
|---------|--------|--------|----------|
| **S** | Attacker uses shared PACS credentials to impersonate a radiology user. | Unauthorized access to medical images. | **High** |
| **T** | Malware modifies diagnostic images or metadata. | Incorrect diagnosis and patient treatment. | **Critical** |
| **R** | Shared accounts prevent identifying who accessed or changed images. | Poor forensic investigation and accountability. | **Medium** |
| **I** | Medical images are stolen through flat network access. | PHI disclosure and regulatory violations. | **Critical** |
| **D** | Ransomware encrypts the PACS server. | Radiologists cannot access imaging required for patient care. | **Critical** |
| **E** | Windows XP workstation is exploited to gain administrator privileges. | Attacker gains control of PACS infrastructure. | **Critical** |

### Top Threat

**Denial of Service (D)** is the greatest risk because ransomware against the PACS server would immediately prevent clinicians from viewing medical images needed for diagnosis, delaying treatment and affecting patient safety.

---

# System 2: Active Directory

## Architecture Notes

Components:
- ad-dc-01
- ad-dc-02
- Domain authentication
- Group Policy
- User and administrator accounts

Active Directory authenticates users and systems throughout the MedDefense environment.

| STRIDE | Threat | Impact | Severity |
|---------|--------|--------|----------|
| **S** | Stolen administrator credentials allow attackers to impersonate Domain Admins. | Full domain compromise. | **Critical** |
| **T** | Attackers modify Group Policy Objects (GPOs). | Malware or ransomware deployed across the organization. | **Critical** |
| **R** | Attackers delete or alter security logs after gaining Domain Admin privileges. | Incident investigation becomes difficult. | **High** |
| **I** | Attackers access password hashes and sensitive account information. | Credential theft across the organization. | **Critical** |
| **D** | Domain Controllers become unavailable due to ransomware or hardware failure. | Users cannot authenticate to critical systems. | **Critical** |
| **E** | Privilege escalation provides Domain Admin access. | Complete control of MedDefense systems. | **Critical** |

### Top Threat

**Elevation of Privilege (E)** is the most dangerous threat because a compromised Domain Admin account gives attackers complete control over authentication, servers, workstations, and clinical systems.

---

# System 3: Network Infrastructure

## Architecture Notes

Components:
- FortiGate firewall
- Core switch
- Westside consumer router
- VPN gateway
- Flat internal network

The network infrastructure provides connectivity between all MedDefense systems and protects the perimeter.

| STRIDE | Threat | Impact | Severity |
|---------|--------|--------|----------|
| **S** | Attackers use stolen VPN credentials to appear as legitimate remote users. | Unauthorized network access. | **High** |
| **T** | Firewall or router configuration is modified by an attacker. | Security controls bypassed. | **Critical** |
| **R** | Configuration changes are made without sufficient logging. | Changes cannot be traced to responsible users. | **Medium** |
| **I** | Misconfigured VPN or router exposes sensitive network traffic. | Internal information disclosure. | **High** |
| **D** | DDoS attack or firewall failure disconnects hospital services. | Clinical systems become unavailable. | **Critical** |
| **E** | Administrator privileges obtained on FortiGate firewall. | Complete network control and unrestricted attacker movement. | **Critical** |

### Top Threat

**Elevation of Privilege (E)** is the greatest threat because compromise of the FortiGate firewall or network administration accounts allows attackers to bypass perimeter defenses, alter security policies, and reach every internal system.

---

# Architecture STRIDE Summary

Across these three systems, the highest recurring risks are **Elevation of Privilege**, **Denial of Service**, and **Information Disclosure**. Active Directory represents the greatest overall risk because it controls authentication for the entire organization. A successful compromise of Domain Admin accounts would allow attackers to access the EHR, PACS, databases, backups, and medical devices, making it the most critical component to protect within the MedDefense environment.
