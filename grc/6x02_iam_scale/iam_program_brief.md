# Identity Program Brief for Dr. Morales

**To:** Dr. Morales, Chief Information Security Officer  
**From:** Security Engineering & GRC Team  
**Date:** November 3, 2026  
**Subject:** Board Risk Committee Briefing: MedDefense Identity Security Transformation  

---

## Identity Posture Summary
MedDefense Health Systems currently carries **2 Critical** and **3 High** severity findings across our identity and cloud infrastructure. These vulnerabilities reflect years of accumulated administrative permissions, dormant accounts, and unmonitored access paths. While our perimeter defenses held during the recent Cobalt Strike intrusion, our identity layer permitted an attacker to escalate from an initial workstation compromise to full domain control in under two hours. To answer the Board's question—*"What is different about our identity posture now?"*—we must demonstrate that we have discovered, measured, and actively eliminated the exact pathways that compromised our systems.

## Connection to the Incident
The recent breach followed a simple, devastating path: credential extraction, authentication as a service account, and lateral movement leveraging excessive administrative rights. Two specific findings in our audit directly mirror this path:
* **IAM-001 (`svc_epic_int`)**: A dormant service account holding `Domain Admin` privileges whose last authentication was over three years ago. This is the exact class of abandoned account an attacker leverages for persistent, undetected domain dominance.
* **IAM-002 (`t.morrison`)**: An orphaned contractor account with active `Domain Admin` rights whose engagement ended seven months prior, leaving an open backdoor into our clinical network.

## What Has Been Completed
1. **Identified & Classified Root Vulnerabilities**: Completed a full inventory audit (200 accounts) and AWS cloud assessment, mapping all findings against CIS benchmarks and HIPAA security rules.
2. **Rewrote Over-Privileged Cloud Policies**: Replaced dangerous wildcard policies (`s3:*` on `Resource: *`) with least-privilege scoping for our SIEM reader and EHR backup roles.
3. **Drafted SAML SSO Reference Architecture**: Completed Keycloak integration specifications to replace fragmented password delegation with centralized authentication and instant off-boarding.
4. **Secured Break-Glass Access**: Implemented strict IP and multi-factor authentication (MFA) constraints on emergency administrator roles.

## What Must Be Completed Before the Next Board Meeting
1. **Disable Dormant and Orphaned Accounts** (Owner: Identity Operations | Target: Immediate / 24 Hours): Permanently disable `svc_epic_int` and `t.morrison`, removing all standing administrative group memberships.
2. **Enforce Privileged MFA Coverage** (Owner: Enterprise Security | Target: 7 Days): Achieve 100% MFA enrollment across all administrative and server accounts (closing the current 28.9% gap).
3. **Remediate Vendor Service Accounts** (Owner: Systems Administration | Target: 7 Days): Demote unvetted vendor accounts like `svc_helpdesk` from `Domain Admins` to least-privilege operational roles.

## What Requires Board Authorization or Budget
To eliminate static administrative service accounts permanently and prevent recurrence, we request Board authorization and budget allocation for the enterprise deployment of **HashiCorp Vault Database Secrets Engine** for Just-In-Time (JIT) dynamic credential generation, alongside automated cloud governance tools.

## Board Resolution Requested
*“The Board Risk Committee approves the immediate execution of the Identity Remediation Roadmap and authorizes the allocation of necessary resources to deploy HashiCorp Vault JIT credential controls across MedDefense core systems.”*
