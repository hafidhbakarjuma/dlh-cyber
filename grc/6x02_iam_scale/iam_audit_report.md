# MedDefense IAM Audit Report

**Classification:** Confidential  
**Audit date:** November 3, 2026  
**Prepared by:** Security Engineering & GRC Team  
**Reviewed by:** James Chen, SOC Lead  
**Approved by:** Dr. Morales, Chief Information Security Officer  Date: November 3, 2026  

---

## Executive Summary

The recent post-incident review following the Cobalt Strike breach revealed an alarming reality: an intrusion moved from an initial workstation compromise to full Domain Administrator access in under two hours. The path was not a sophisticated zero-day exploit; it was an unmonitored identity escalation path. Attackers extracted credentials from memory, authenticated as an over-privileged service account, and discovered that legacy administrative rights granted years prior remained completely active and unrevoked. The perimeter held, but the identity layer rendered the defense trivial.

This comprehensive IAM audit evaluates MedDefense’s current account inventory against rigorous severity models, uncovering systemic accumulation of excessive privileges, orphaned contractor accounts, and dormant service accounts. Most notably, accounts such as `svc_epic_int` and `t.morrison` retain high-level administrative access despite years of inactivity or terminated employment. These findings confirm that identity hygiene has not kept pace with organizational changes, leaving patient care systems vulnerable to lateral movement, ransomware deployment, and ePHI exfiltration.

By executing this audit and implementing the prioritized remediation roadmap, MedDefense transitions from reactive incident response to proactive identity governance. Closing these gaps eliminates the exact class of misconfigurations exploited in the prior breach, ensuring that future intrusions remain isolated and contained before reaching critical clinical infrastructure.

---

## Audit Scope and Methodology

- **Scope:** The directory inventory comprising 200 accounts (`accounts.csv`), covering active directory user objects, service accounts, contractor accounts, and privileged group memberships.
- **Out of Scope:** External SaaS applications not integrated with the core Active Directory domain and local workstation standalone accounts.
- **Classification Framework:** Findings are classified into categories including Service Account Over-Privilege, Dormant Privileged Accounts, Orphaned Contractor Accounts, and Missing MFA Controls.
- **Severity Assignment:** Severity ratings (Critical, High, Medium, Low) are assigned based on the severity model (`severity_model.md`), evaluating blast radius, account persistence, exploitability, and potential impact on patient safety and regulatory compliance (HIPAA/HITECH).

---

## Findings Summary Table

| Finding ID | Account | Category | Severity | Status |
|---|---|---|---|---|
| IAM-001 | `svc_epic_int` | Dormant Service Account Over-Privilege | Critical | Open |
| IAM-002 | `t.morrison` | Orphaned Contractor Account / Privileged Access | Critical | Open |
| IAM-003 | `svc_helpdesk` | Unvetted Vendor Service Account Over-Privilege | High | Open |
| IAM-004 | `j.doe` | Missing Multi-Factor Authentication on Privileged Account | High | Open |
| IAM-005 | `b.vance` | Stale Privileged Account with Inactive Password | Medium | Open |

---

## Detailed Findings

### IAM-001: Dormant Service Account with Domain Admin Rights
- **Account:** `svc_epic_int` (Row 14 in `accounts.csv`)
- **Severity:** Critical
- **Check:** Service account privilege review and last authentication timestamp
- **Evidence:** `accounts.csv` record shows account name `svc_epic_int`, group membership `Domain Admins`, last authentication timestamp over three years ago (`2022-03-15`), and description notes: `"post-EHR-migration service account; no current function identified."`
- **Risk:** An adversary who compromises any workstation and dumps credentials can immediately reuse this dormant static credential. Because the account holds Domain Admin rights without recent usage monitoring or alert triggers, attackers achieve total domain dominance and access to all underlying electronic Protected Health Information (ePHI) and clinical systems, directly threatening patient safety and triggering major HIPAA breach notifications.
- **Remediation:** 
  1. Immediately disable the `svc_epic_int` account object in Active Directory.
  2. Remove `svc_epic_int` from the `Domain Admins` security group.
  3. Archive configuration dependencies and permanently delete the account object within 30 days if no dependent legacy processes are identified.
- **Owner:** Identity & Access Management Team
- **Target completion:** Immediate (24 hours)

### IAM-002: Orphaned Contractor Account with Active Privileges
- **Account:** `t.morrison` (Row 42 in `accounts.csv`)
- **Severity:** Critical
- **Check:** Contractor lifecycle and account status review against HR termination logs
- **Evidence:** `accounts.csv` record shows account name `t.morrison`, title `External Integration Contractor`, group membership `Domain Admins`, status `Enabled`, and contract end date recorded as seven months prior.
- **Risk:** Retaining enabled administrative accounts for departed contractors leaves a wide open backdoor. Attackers can target these orphaned credentials via password spray or credential stuffing without triggering standard employee off-boarding alerts, enabling rapid lateral movement and data exfiltration.
- **Remediation:**
  1. Immediately disable the `t.morrison` user account in Active Directory.
  2. Revoke all active Kerberos TGTs and active sessions for `t.morrison`.
  3. Audit HR-to-IT off-boarding integration workflows to ensure automated disablement upon contract termination.
- **Owner:** IT Helpdesk & Identity Operations
- **Target completion:** Immediate (24 hours)

### IAM-003: Unvetted Vendor Service Account Granted Permanent Admin Access
- **Account:** `svc_helpdesk` (Row 28 in `accounts.csv`)
- **Severity:** High
- **Check:** Service account justification and privilege audit
- **Evidence:** `accounts.csv` record shows account name `svc_helpdesk`, group membership `Domain Admins`, and administrative comment note: `"required per vendor during 2024 installation; review later."`
- **Risk:** Unvetted vendor accounts with standing administrative rights bypass principle of least privilege. If the vendor's supporting infrastructure is compromised, attackers inherit unconstrained domain control.
- **Remediation:**
  1. Remove `svc_helpdesk` from the `Domain Admins` group.
  2. Assign `svc_helpdesk` exclusively to the `Helpdesk` operational group with fine-grained delegation.
  3. Verify that helpdesk automation functions continue to operate correctly with delegated permissions only, and document the verification result.
- **Owner:** Systems Administration
- **Target completion:** 7 days

### IAM-004: Privileged User Account Missing Multi-Factor Authentication
- **Account:** `j.doe` (Row 65 in `accounts.csv`)
- **Severity:** High
- **Check:** MFA enrollment verification for privileged accounts
- **Evidence:** `accounts.csv` record shows account name `j.doe`, department `IT Infrastructure`, group membership `Server Admins`, and MFA status `Disabled`.
- **Rank/Risk:** Administrative accounts lacking MFA are highly vulnerable to phishing, keylogging, and credential theft, providing direct entry points to core server infrastructure and clinical databases.
- **Remediation:**
  1. Enforce mandatory MFA enrollment for `j.doe` via Keycloak and Active Directory authentication policies.
  2. Temporarily suspend console and remote PowerShell access for `j.doe` until MFA is successfully verified.
- **Owner:** Enterprise Security Team
- **Target completion:** 7 days

### IAM-005: Stale Privileged Account with Inactive Credentials
- **Account:** `b.vance` (Row 88 in `accounts.csv`)
- **Severity:** Medium
- **Check:** Password age and last login audit for administrative accounts
- **Evidence:** `accounts.csv` record shows account name `b.vance`, group membership `Administrators`, and password age exceeding 365 days without rotation.
- **Risk:** Stale static credentials increase the probability of compromise through password reuse or offline brute-force cracking of cached hashes.
- **Remediation:**
  1. Force a mandatory password reset upon next login for `b.vance`.
  2. Enforce automated 90-day maximum password age policies across all administrative tiers.
- **Owner:** Identity Management Team
- **Target completion:** 30 days

---

## MFA Coverage Analysis

- **Total Privileged Accounts:** 45
- **Privileged Accounts with MFA Enrolled:** 32 (71.1%)
- **Privileged Accounts without MFA:** 13 (28.9%)
- **Compliance Comparison:** HIPAA Security Rule § 164.312(d) ("Person or Entity Authentication") and NIST SP 800-63B guidelines mandate unique user IDs and robust multi-factor authentication for all access to electronic Protected Health Information (ePHI). A 28.9% deficiency in privileged MFA coverage represents a critical regulatory compliance gap and a severe operational risk.

---

## Service Account Risk Summary

| Account Name | Group Membership | Documented Function | Recommendation |
|---|---|---|---|
| `svc_epic_int` | Domain Admins | None (Post-EHR migration relic) | Disable and delete within 30 days |
| `svc_helpdesk` | Domain Admins | Vendor installation requirement (unreviewed) | Demote to Helpdesk group with delegated permissions |
| `svc_backup_exec` | Server Admins | Nightly storage snapshot automation | Migrate to HashiCorp Vault JIT dynamic database credentials |
| `svc_sql_sync` | Domain Admins | Legacy database replication | Replace with managed service principal and scoped permissions |

---

## Remediation Roadmap

| Priority | Action | Owner Role | Target Completion | Success Criterion |
|---|---|---|---|---|
| 1 | Disable `svc_epic_int` and `t.morrison`; remove Domain Admin rights | Identity Operations | Immediate (24 hrs) | Accounts disabled; active sessions terminated |
| 2 | Remediate `svc_helpdesk` privileges and verify helpdesk workflows | Systems Administration | 7 days | Group membership updated; operational verification logged |
| 3 | Enforce mandatory MFA for all remaining privileged user accounts | Enterprise Security | 7 days | 100% MFA enrollment across administrative tier |
| 4 | Rotate stale passwords and implement 90-day rotation policy | IT Administration | 30 days | All admin passwords compliant with age policy |
| 5 | Deploy HashiCorp Vault database secrets engine for automated service credentials | Cloud Security Engineering | 30 days | Static administrative service accounts eliminated |

---

## Appendix: Audit Script

- **Audit Script Reference:** `audit_iam.py`
- **Generated Evidence Output:** `iam_findings.json`
- **Methodology Reference:** `/opt/meddefense/materials/iam_audit/severity_model.md` and `/opt/meddefense/materials/iam_audit/incident_identity_path.md`
