# THE WINDOWS FORTRESS

# MedDefense Windows Fortress
## Enterprise Active Directory Hardening, Detection & Security Validation Project

![Windows Security](https://img.shields.io/badge/Platform-Windows%20Server-blue)
![Active Directory](https://img.shields.io/badge/Active%20Directory-Hardening-green)
![PowerShell](https://img.shields.io/badge/Automation-PowerShell-blue)
![Security](https://img.shields.io/badge/Focus-Blue%20Team-red)
![Status](https://img.shields.io/badge/Project-Completed-success)

---

# Project Overview

**MedDefense Windows Fortress** is a complete enterprise Windows security hardening project focused on securing an Active Directory environment against common attack techniques used by real-world threat actors.

The project simulates a healthcare organization (**MedDefense**) where Windows infrastructure must be protected against:

- Credential theft
- Kerberoasting attacks
- Pass-the-Hash attacks
- Ransomware propagation
- Malicious Group Policy abuse
- PowerShell attacks
- Privilege escalation
- Lateral movement
- Weak authentication protocols
- Service account compromise

The objective was not only to apply security controls but also to create a complete security lifecycle:

1. Identify risks
2. Deploy security hardening
3. Validate configurations
4. Generate security telemetry
5. Export evidence
6. Prepare the environment for SOC detection

---

# Project Scenario

## Organization: MedDefense Healthcare

MedDefense operates a Windows enterprise environment containing:

- Active Directory Domain Services
- Domain Controllers
- Windows endpoints
- Service accounts
- Remote administration systems
- Internal applications

Because healthcare organizations are high-value targets, attackers often attempt to compromise:

- Administrative accounts
- Service accounts
- Domain Controllers
- Group Policy
- Backup systems
- Remote access infrastructure


The project follows a realistic enterprise security engineering workflow.

---

# Project Goals

The main objectives were:

## Identity Security

Protect Active Directory identities against:

- Weak passwords
- Privilege abuse
- Kerberos attacks
- Delegation abuse
- Service account compromise


## Endpoint Hardening

Secure Windows systems using:

- Group Policy Objects (GPO)
- Security baselines
- Firewall policies
- Application control
- Authentication hardening


## Detection Engineering

Enable telemetry required for security monitoring:

- Windows Event Logs
- PowerShell logging
- Sysmon
- Audit policies


## Security Validation

Create automated scripts that verify:

- Security settings
- Compliance status
- Configuration drift


---

# Project Structure

```
blue_team/
│
└── 2x00_windows_fortress/
│
├── scripts/
│
├── documentation/
│
├── reports/
│
├── evidence/
│
└── README.md
```

---

# Tasks Completed

The project contains 20 security engineering tasks.

---

# Task 0 - Environment Preparation

## Objective

Prepare the Windows security lab environment.

Implemented:

- Active Directory lab setup
- Domain controller configuration
- Windows endpoints
- Administrative accounts
- Testing environment

Skills developed:

- Windows Server administration
- Active Directory fundamentals
- Enterprise architecture


---

# Task 1-5 - Active Directory Security Foundation

## Objective

Understand and secure the identity layer.

Implemented:

- Domain security baseline
- User management
- Organizational Units
- Group Policy structure
- Administrative separation


Security concepts:

- Least privilege
- Role separation
- Domain security model


---

# Task 6 - Password and Account Security

## Objective

Prevent password-based attacks.

Implemented:

Password policy:

```
Minimum password length:
14 characters

Password history:
24 passwords

Minimum password age:
1 day

Account lockout:
5 attempts

Lockout duration:
15 minutes
```

Protection against:

- Brute force attacks
- Password spraying
- Credential guessing


---

# Task 7 - Audit Policy Hardening

## Objective

Enable Windows security telemetry.

Configured:

Important Windows events:

| Event ID | Purpose |
|-|-|
|4624|Successful logon|
|4625|Failed logon|
|4648|Explicit credential use|
|4672|Special privileges assigned|
|4688|Process creation|
|4720|User creation|
|4726|User deletion|
|4732|Group membership changes|
|1102|Audit log cleared|

Purpose:

Provide visibility for:

- SOC analysts
- Incident response
- Threat hunting


---

# Task 8 - PowerShell Security Logging

## Objective

Detect malicious PowerShell usage.

Enabled:

## Script Block Logging

Event:

```
4104
```

Detects:

- Obfuscated scripts
- Malware execution
- Fileless attacks


## Module Logging

Event:

```
4103
```


## PowerShell Transcription

Records:

- Commands executed
- User activity
- Administrative actions


---

# Task 9 - Sysmon Deployment

## Objective

Improve endpoint visibility.

Sysmon provides detailed telemetry.

Configured monitoring:

| Event | Detection |
|-|-|
|1|Process creation|
|3|Network connections|
|7|Image loading|
|11|File creation|
|13|Registry modification|
|22|DNS queries|


Custom detection rules:

- Rclone abuse
- PsExec execution
- Encoded PowerShell
- VSSAdmin abuse
- Scheduled task abuse


---

# Task 10 - Kerberos Hardening

## Objective

Reduce Kerberos attacks.

Protected against:

## Kerberoasting

Controls:

- Disable RC4
- Disable DES
- Require AES encryption


Attack prevented:

```
Service account SPN
        |
        |
Attacker requests TGS ticket
        |
        |
Offline password cracking
```

---

# Task 11 - SMB Security

## Objective

Prevent legacy file-sharing attacks.

Configured:

Disabled:

```
SMBv1
```

Enabled:

```
SMB signing
```

Protection against:

- EternalBlue style attacks
- SMB relay
- Man-in-the-middle attacks


---

# Task 12 - Windows Firewall Hardening

Configured:

All firewall profiles:

```
Domain
Private
Public
```

Settings:

```
Enabled = True

Default inbound =
Block
```

Logging:

- Dropped packets
- Allowed connections


---

# Task 13 - Remote Desktop Security

Protected RDP using:

Enabled:

```
Network Level Authentication
```

Restricted access:

```
G_IT_Admins group only
```

Configured:

- Session timeout
- Redirection restrictions


Protection against:

- RDP brute force
- Unauthorized remote access


---

# Task 14 - Service Account Security Audit

Created:

```
14-service_accounts.ps1
```

Purpose:

Detect dangerous service account configurations.

Checks:

## Password Age

Detect:

```
Password older than 180 days
```


## Delegation

Detect:

```
Unconstrained delegation
```


## Privileges

Detect:

```
Domain Admins
Enterprise Admins
Administrators
```


## Interactive Login Risk

Prevent:

- Human login using service accounts
- Credential theft


---

# Task 15 - Master Validation Script

Created:

```
15-master_validation.ps1
```

Purpose:

Weekly compliance check.

Runs every Friday.

Checks:

- Password policy
- Audit policy
- PowerShell logging
- Sysmon
- Kerberos
- SMB
- Firewall
- RDP
- Service accounts


Example:

```
[PASS] Minimum length: 14

[PASS] Script Block Logging

[PASS] SMBv1 Disabled

[WARN] svc_backup password age: 235 days
```


Exit codes:

```
0 = All critical checks passed

1 = Critical failure detected
```


---

# Task 16 - Hardened State Export

Created:

```
16-hardened_state_export.ps1
```


Purpose:

Generate security evidence package.

Output:

```
windows_hardened_state.json
```


Contains:

## Domain Metadata

- Domain name
- Domain controller
- Timestamp
- Script owner


## GPO Inventory

- Security GPOs
- Enabled state
- Scope


## Audit Policy

- auditpol output
- Required event IDs


## PowerShell

- Script Block Logging
- Module Logging
- Transcription


## Sysmon

- Service status
- Configuration
- Event coverage


## Firewall

- Profiles
- Rules
- Logging


## Authentication

- Kerberos
- NTLM
- SMB


## Service Accounts

- Password age
- Delegation
- Privileges


---

# Task 17-20 - Security Review Questions

The final section validates understanding of enterprise attacks.

---

# Active Directory Attack Chain

Example:

Attacker compromises:

```
Service Account
        |
        |
SPN configured
        |
        |
Request Kerberos TGS
        |
        |
Offline password cracking
```


Attack:

```
Kerberoasting
```


Defense:

- Strong service account passwords
- AES Kerberos encryption
- Disable RC4
- Managed service accounts


---

# Group Policy Security Paradox

Group Policy can be:

## A Weapon

Attackers with Domain Admin:

- Deploy ransomware
- Disable security tools
- Create persistence


## A Defense

Security teams use GPO to:

- Enable logging
- Configure firewall
- Deploy security controls
- Harden endpoints


Protecting:

```
Domain Controller
        =
Protecting the entire domain
```


---

# Security Tools Used

## Windows

- Active Directory
- Group Policy Management Console
- PowerShell
- Event Viewer
- Audit Policy
- Windows Defender Firewall


## Security Tools

- Sysmon
- PowerShell Logging
- AppLocker
- Event Analysis


---

# Key Security Lessons Learned

## 1. Identity is the Security Boundary

Compromised credentials can bypass many controls.

Protect:

- Admin accounts
- Service accounts
- Domain Controllers


---

## 2. Visibility is Critical

Without logs:

```
Attack happens
        |
        |
No evidence
        |
        |
No investigation
```

Telemetry enables detection.


---

## 3. Security Must Be Automated

Manual checking does not scale.

Automation provides:

- Consistency
- Repeatability
- Compliance validation


---

# Skills Demonstrated

This project demonstrates practical experience with:

### Active Directory

- Domain administration
- GPO management
- Kerberos security
- Service accounts


### Windows Security

- Hardening
- Auditing
- Authentication protocols
- Firewall


### PowerShell

- Security automation
- Validation scripts
- Evidence collection


### Blue Team Operations

- Detection engineering
- Security monitoring
- Incident preparation


---

# Real-World Equivalent Roles

Skills from this project apply to:

- Security Analyst
- SOC Analyst
- Windows Security Engineer
- Identity Security Engineer
- System Administrator
- Detection Engineer


---

# Author

**Hafidh Juma**

Cybersecurity Student  
DLH Cybersecurity Academy

Focus:

- Blue Team Security
- Active Directory Security
- Detection Engineering
- Cloud Security


---

# Final Project Outcome

The MedDefense Windows Fortress project transformed a default Windows enterprise environment into a hardened, monitored, and validated security architecture.

The final environment provides:

✅ Strong authentication controls  
✅ Reduced attack surface  
✅ Security telemetry  
✅ Automated validation  
✅ Evidence-based compliance  

This project represents a realistic workflow used by enterprise security engineers to protect Windows infrastructures.
