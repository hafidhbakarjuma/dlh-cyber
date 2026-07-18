# The Misconfiguration Findings

## Goal

Analyze vulnerabilities that do not have a CVE identifier and understand why they can represent the same or greater risk than CVE-based vulnerabilities.

## Context

The MedDefense scan report contains multiple findings marked as **Misconfiguration** with no CVE identifier.

A missing CVE does not mean the issue is safe. It means the weakness comes from incorrect configuration, poor security practices, or missing controls rather than a software defect.

Misconfigurations are often ignored by automated vulnerability scoring systems because they do not have:

- CVE identifiers
- CVSS scores
- NVD entries
- Exploit-DB records

However, real-world attacks frequently rely on misconfigurations.

---

# Misconfiguration Analysis

## Finding 003 — PostgreSQL Database Exposure

### Finding ID

GAP/Finding 003

### Host

PostgreSQL Database Server

### Misconfiguration

The PostgreSQL database service is exposed with insecure configuration settings, increasing the possibility of unauthorized access.

The database is reachable from unnecessary network locations and lacks proper access restrictions.

### Why No CVE

This is not caused by a software vulnerability.

The PostgreSQL software itself is working as designed. The security issue comes from incorrect deployment and access configuration.

### Severity Assessment

**High**

Reason:

A database exposure can allow attackers to access sensitive healthcare information, modify records, or use the database as a pivot point inside the network.

### Cross-Reference 1x00

Related to:

- **1x00 T7 — Network Scan Findings**

The network scan identified exposed services that should not be accessible from unnecessary network segments.

### Comparable CVE Risk

**CVE-2020-1938 — Ghostcat**

Ghostcat allowed attackers to access sensitive Tomcat files remotely.

The PostgreSQL exposure has a similar impact because both can provide unauthorized access to sensitive application data without requiring a traditional software exploit.

---

# Finding 006 — Missing Security Monitoring on HR Share

### Finding ID

GAP-006 / Finding 006

### Host

HR File Share Server

### Misconfiguration

The HR shared folder lacks proper monitoring, access auditing, and detection controls.

Unauthorized access could occur without generating security alerts.

### Why No CVE

The problem is not a vulnerable application.

The system lacks appropriate security configuration and monitoring controls.

### Severity Assessment

**Medium**

Reason:

Sensitive employee information could be accessed or stolen without detection.

### Cross-Reference 1x00

Related to:

- **1x00 T5 — Control Gap**

The gap represents missing detection and monitoring controls.

### Comparable CVE Risk

**CVE-2021-44790 — Apache HTTP Server Out-of-bounds Write**

Although CVE-2021-44790 is a software vulnerability, both issues can result in unauthorized access to sensitive information.

A missing detection control can allow attackers to remain inside the environment longer than a single exploitable vulnerability.

---

# Finding 008 — Shared PACS Login Accounts

### Finding ID

GAP-008 / Finding 008

### Host

PACS Medical Imaging System

### Misconfiguration

Multiple users share the same PACS login credentials.

Individual user actions cannot be traced accurately.

### Why No CVE

This is an identity and access management configuration problem.

The software is not broken; the authentication model was incorrectly implemented.

### Severity Assessment

**Critical**

Reason:

Shared accounts in healthcare systems can expose patient records and remove accountability.

### Cross-Reference 1x00

Related to:

- **1x00 T5 — Control Gap**

The finding maps to missing identity controls and poor account management.

### Comparable CVE Risk

**CVE-2019-0708 — BlueKeep**

BlueKeep allows remote compromise of systems.

Shared PACS credentials can create the same level of impact because attackers can access critical medical systems using valid credentials.

---

# Finding 009 — Orphaned Raspberry Pi Device

### Finding ID

GAP-009 / Finding 009

### Host

Unknown Raspberry Pi Device

### Misconfiguration

An unmanaged Raspberry Pi device exists on the network without ownership, monitoring, or security management.

### Why No CVE

The risk comes from poor asset management.

The device itself may not contain a software vulnerability, but an unknown device creates an uncontrolled attack surface.

### Severity Assessment

**High**

Reason:

An attacker could compromise the device and use it as a foothold into the internal network.

### Cross-Reference 1x00

Related to:

- **1x00 T3 — Walk-through Observation**

The physical and logical environment review identified unmanaged assets.

### Comparable CVE Risk

**CVE-2008-4250 — MS08-067**

MS08-067 allowed attackers to gain remote access.

An unmanaged device can provide attackers a similar entry point into the network without requiring a CVE.

---

# Finding 012 — Flat Network Architecture

### Finding ID

GAP-012 / Finding 012

### Host

Internal Hospital Network

### Misconfiguration

The network lacks segmentation between critical systems, medical devices, user systems, and administrative resources.

### Why No CVE

The network design is insecure by architecture.

There is no vulnerable software component responsible for the weakness.

### Severity Assessment

**Critical**

Reason:

A single compromised endpoint can allow attackers to move laterally across the entire healthcare environment.

### Cross-Reference 1x00

Related to:

- **1x00 T7 — Network Scan Finding**
- **1x00 T5 — Control Gap**

The issue maps to missing network segmentation controls.

### Comparable CVE Risk

**CVE-2019-0708 — BlueKeep**

BlueKeep compromises one machine remotely.

A flat network increases the impact because one compromised machine can expose many other systems.

---

# Finding 015 — Missing Multi-Factor Authentication

### Finding ID

GAP-015 / Finding 015

### Host

VPN and Privileged Accounts

### Misconfiguration

Remote access and privileged accounts do not require multi-factor authentication.

### Why No CVE

The authentication system is functioning normally.

The weakness exists because required security controls were not implemented.

### Severity Assessment

**Critical**

Reason:

Compromised passwords can provide attackers direct access to internal systems.

### Cross-Reference 1x00

Related to:

- **1x00 T5 — Control Gap**

This corresponds to missing identity protection controls.

### Comparable CVE Risk

**CVE-2020-1938 — Ghostcat**

Ghostcat allows unauthorized access through a vulnerable service.

Missing MFA creates a similar risk because attackers with stolen credentials can bypass normal access protections.

---

# Final Analysis

The statement **"Our CVE scan shows nothing critical, we are secure"** provides dangerous false assurance because CVE scanning only detects known software vulnerabilities and does not measure security weaknesses caused by configuration mistakes, missing controls, poor architecture, or identity failures. Attackers frequently exploit misconfigurations because they do not require a software exploit and are often invisible to traditional vulnerability scanners. In the MedDefense environment, issues such as exposed databases, shared accounts, missing MFA, and flat network design can create attack paths with the same or greater impact than CVE-based vulnerabilities. Security assessment must combine CVE analysis with configuration reviews, architecture analysis, and control validation to understand the complete risk picture.
