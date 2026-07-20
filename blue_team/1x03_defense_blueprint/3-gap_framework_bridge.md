# Gap-to-Framework Bridge
## MedDefense Health Systems
### Project 0x03 – The Defense Blueprint

---

# Executive Summary

This document creates a traceability chain between MedDefense's identified security gaps, technical vulnerabilities, threat scenarios, and security frameworks [cite: 3].

The purpose is to transform isolated findings into actionable security improvements [cite: 3]:

**Gap → Vulnerability → Threat → NIST CSF Function → CIS Control → Recommended Action**

The eight highest-priority gaps were selected based on [cite: 3]:

- Business impact
- Healthcare operational risk
- Ransomware exposure
- Regulatory impact
- Ability to reduce attack paths

Framework alignment [cite: 3]:

- **NIST CSF 2.0** defines the cybersecurity outcome required.
- **CIS Controls v8** defines the technical implementation approach.

---

# Gap 1: GAP-015 – Missing MFA

## Description

Critical systems and remote access services do not enforce multi-factor authentication [cite: 3].

## Vulnerability Evidence

**Project 1x02 Findings [cite: 3]:**

- Weak authentication controls
- Credential-based attack exposure
- Missing MFA controls

Related weakness:

- Shared accounts identified in PACS environment [cite: 3]

## Threat Context

**Threat Actor:**
Ransomware affiliates / Initial Access Brokers [cite: 3]

**Kill Chain:**
Kill Chain #1 – Ransomware Attack [cite: 3]

Attack path [cite: 3]:

1. Obtain stolen credentials
2. Access VPN or external service
3. Escalate privileges
4. Move laterally
5. Deploy ransomware

## NIST CSF Function

**Protect (PR)** [cite: 3]

Category:

- PR.AA – Identity Management, Authentication, and Access Control [cite: 3]

## CIS Control

**CIS Control 6 – Access Control Management** [cite: 3]

Relevant safeguards [cite: 3]:

- 6.3 Require MFA for externally exposed applications
- 6.4 Require MFA for remote network access
- 6.5 Require MFA for administrative access

## Recommended Action

Deploy MFA for VPN access, administrator accounts, and externally exposed healthcare applications [cite: 3].

---

# Gap 2: GAP-012 – Flat Network Architecture

## Description

MedDefense operates a flat internal network allowing unnecessary communication between critical systems [cite: 3].

## Vulnerability Evidence

**Project 1x02 Findings [cite: 3]:**

- Excessive network exposure
- Lack of segmentation controls
- Unrestricted internal communication

## Threat Context

**Threat Actor:**
Ransomware groups (BlackReef RaaS) [cite: 3]

**Kill Chain:**
Kill Chain #1 – Ransomware Deployment [cite: 3]

Attack path [cite: 3]:

1. Initial compromise
2. Internal discovery
3. Lateral movement
4. Domain compromise
5. Encryption

## NIST CSF Function

**Protect (PR)** [cite: 3]

Category:

- PR.IR – Technology Infrastructure Resilience [cite: 3]

## CIS Control

**CIS Control 12 – Network Infrastructure Management** [cite: 3]

Relevant safeguards [cite: 3]:

- 12.2 Establish secure network architecture
- 12.4 Maintain architecture diagrams

## Recommended Action

Implement VLAN segmentation separating medical devices, administrative systems, user networks, and critical healthcare applications [cite: 3].

---

# Gap 3: GAP-011 – Missing Patch Management

## Description

MedDefense lacks a formal vulnerability remediation and patch lifecycle [cite: 3].

## Vulnerability Evidence

**Project 1x02 Findings [cite: 3]:**

Critical vulnerabilities identified [cite: 3]:

- CVE-2008-4250
- CVE-2019-0708
- CVE-2020-1938
- CVE-2021-44790
- CVE-2023-38408

## Threat Context

**Threat Actor:**
External attackers / Exploit developers [cite: 3]

**Kill Chain:**
Kill Chain #2 – Vulnerability Exploitation [cite: 3]

Attack path [cite: 3]:

1. Scan exposed services
2. Exploit vulnerable software
3. Gain access
4. Establish persistence

## NIST CSF Function

**Identify (ID)** and **Protect (PR)** [cite: 3]

Categories:

- ID.RA – Risk Assessment
- PR.PS – Platform Security [cite: 3]

## CIS Control

**CIS Control 7 – Continuous Vulnerability Management** [cite: 3]

Relevant safeguards [cite: 3]:

- 7.1 Vulnerability management process
- 7.3 Automated OS patch management

## Recommended Action

Implement centralized vulnerability scanning and risk-based patch management [cite: 3].

---

# Gap 4: GAP-010 – Backup Protection Weakness

## Description

Backups exist but lack sufficient isolation and ransomware resilience [cite: 3].

## Vulnerability Evidence

**Project 1x02 Findings [cite: 3]:**

- Backup security weaknesses
- Recovery process deficiencies

## Threat Context

**Threat Actor:**
Ransomware operators [cite: 3]

**Kill Chain:**
Kill Chain #1 – Ransomware Extortion [cite: 3]

Attack path [cite: 3]:

1. Encrypt production systems
2. Delete backups
3. Demand payment

## NIST CSF Function

**Recover (RC)** [cite: 3]

Category:

- RC.RP – Incident Recovery Plan Execution [cite: 3]

## CIS Control

**CIS Control 11 – Data Recovery** [cite: 3]

Relevant safeguards [cite: 3]:

- 11.2 Automated backups
- 11.3 Protect recovery data
- 11.4 Isolated recovery instance

## Recommended Action

Deploy immutable offline backups and perform regular recovery testing [cite: 3].

---

# Gap 5: GAP-013 – No Incident Response Plan

## Description

MedDefense lacks documented procedures for handling cybersecurity incidents [cite: 3].

## Vulnerability Evidence

**Project 1x02 Findings [cite: 3]:**

- No documented response workflow
- No tested containment procedures

## Threat Context

**Threat Actor:**
Ransomware groups and insider threats [cite: 3]

**Kill Chain:**
All Kill Chains after initial compromise [cite: 3]

Attackers benefit from delayed detection and response [cite: 3].

## NIST CSF Function

**Respond (RS)** [cite: 3]

Category:

- RS.MA – Incident Management [cite: 3]

## CIS Control

**CIS Control 17 – Incident Response Management** [cite: 3]

Relevant safeguards [cite: 3]:

- 17.1 Incident handling personnel
- 17.3 Incident reporting process

## Recommended Action

Create and test an incident response plan with defined roles, escalation paths, and communication procedures [cite: 3].

---

# Gap 6: GAP-001 – Medical Device Security Weakness

## Description

Infusion pumps and medical devices lack sufficient security controls [cite: 3].

## Vulnerability Evidence

**Project 1x02 Findings [cite: 3]:**

- Unsupported medical device software
- Weak device security configuration

## Threat Context

**Threat Actor:**
Cybercriminal groups and targeted healthcare attackers [cite: 3]

**Kill Chain:**
Kill Chain #3 – Medical Device Compromise [cite: 3]

Attack path [cite: 3]:

1. Compromise device
2. Pivot into healthcare network
3. Disrupt operations

## NIST CSF Function

**Protect (PR)** [cite: 3]

Category:

- PR.PS – Platform Security [cite: 3]

## CIS Control

**CIS Control 1 – Enterprise Asset Inventory** [cite: 3]

Relevant safeguards [cite: 3]:

- 1.1 Asset inventory
- 1.2 Unauthorized asset management

## Recommended Action

Create a medical device inventory, isolate devices, and enforce security monitoring [cite: 3].

---

# Gap 7: GAP-008 – Shared PACS Accounts

## Description

Multiple users share PACS credentials, reducing accountability [cite: 3].

## Vulnerability Evidence

**Project 1x02 Findings [cite: 3]:**

- Shared user accounts
- Weak identity tracking

## Threat Context

**Threat Actor:**
Insiders and compromised accounts [cite: 3]

**Kill Chain:**
Kill Chain #4 – Data Theft [cite: 3]

Attack path [cite: 3]:

1. Obtain credentials
2. Access patient imaging systems
3. Extract sensitive data

## NIST CSF Function

**Protect (PR)** [cite: 3]

Category:

- PR.AA – Identity Management [cite: 3]

## CIS Control

**CIS Control 5 – Account Management** [cite: 3]

Relevant safeguards [cite: 3]:

- 5.1 Account inventory
- 5.2 Unique passwords

## Recommended Action

Replace shared accounts with unique identities and role-based access controls [cite: 3].

---

# Gap 8: GAP-009 – Unauthorized Raspberry Pi Device

## Description

Unknown unmanaged device exists on the healthcare network [cite: 3].

## Vulnerability Evidence

**Project 1x02 Findings [cite: 3]:**

- Unauthorized asset discovered
- Missing asset governance

## Threat Context

**Threat Actor:**
Insider threat / External attacker [cite: 3]

**Kill Chain:**
Kill Chain #5 – Initial Access [cite: 3]

Attack path [cite: 3]:

1. Connect unauthorized device
2. Establish foothold
3. Access internal resources

## NIST CSF Function

**Identify (ID)** [cite: 3]

Category:

- ID.AM – Asset Management [cite: 3]

## CIS Control

**CIS Control 1 – Inventory and Control of Enterprise Assets** [cite: 3]

Relevant safeguards [cite: 3]:

- 1.1 Asset inventory
- 1.2 Unauthorized assets

## Recommended Action

Remove unauthorized devices and maintain continuous asset discovery [cite: 3].

---

# Traceability Summary Table

| Gap | Vulnerability | Threat | NIST Function | CIS Control | Action |
|---|---|---|---|---|---|
| GAP-015 Missing MFA | Weak authentication | Ransomware affiliates | Protect | CIS 6 Access Control | Deploy MFA |
| GAP-012 Flat Network | Excessive network exposure | BlackReef ransomware | Protect | CIS 12 Network Management | Implement segmentation |
| GAP-011 Patch Management | Critical CVEs | Exploit attackers | Identify / Protect | CIS 7 Vulnerability Management | Deploy patch lifecycle |
| GAP-010 Backup Weakness | Recovery weakness | Ransomware operators | Recover | CIS 11 Data Recovery | Implement immutable backups |
| GAP-013 No IR Plan | No response process | Ransomware / insiders | Respond | CIS 17 Incident Response | Build IR program |
| GAP-001 Medical Devices | Device security weakness | Healthcare attackers | Protect | CIS 1 Asset Inventory | Secure medical devices |
| GAP-008 Shared PACS Login | Weak identity controls | Insider / stolen credentials | Protect | CIS 5 Account Management | Enforce unique accounts |
| GAP-009 Rogue Raspberry Pi | Unknown asset | Insider / attacker | Identify | CIS 1 Asset Inventory | Remove unauthorized assets |

---

# Final Assessment

The traceability analysis demonstrates that MedDefense's highest-risk weaknesses are concentrated around [cite: 3]:

1. Identity security
2. Network architecture
3. Vulnerability management
4. Recovery capability
5. Incident response readiness

Addressing these eight gaps provides the greatest reduction in healthcare cyber risk while aligning MedDefense with [cite: 3]:

- NIST CSF 2.0 strategic objectives
- CIS Controls v8 implementation priorities
- Healthcare security expectations
