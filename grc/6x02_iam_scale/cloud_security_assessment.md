# MedDefense Cloud Security Assessment

**Classification:** Confidential  
**Assessment Date:** November 3, 2026  
**Prepared by:** Cloud Security & GRC Team  
**Reviewed by:** Helena Reyes, Cloud Security Architect  
**Approved by:** Dr. Morales, Chief Information Security Officer  

---

## Assessment Scope

This assessment evaluates the MedDefense Health Systems multi-region AWS cloud environment (`us-east-1` and `us-east-2`) against the **CIS Amazon Web Services Foundations Benchmark v3.0**. The review encompasses root account hygiene, IAM user and role privileges, multi-factor authentication (MFA) coverage, logging and monitoring posture (CloudTrail and VPC Flow Logs), and S3 bucket security configurations governing electronic Protected Health Information (ePHI) backups.

---

## Findings Table

| # | Observation Summary | CIS Control Area | Severity | Compliance Status | Remediation Action / CLI / Console Command |
|---|---|---|---|---|---|
| **1** | Root account has no MFA; root access keys active since 2022-03-15 | 1.1 / 1.2 / 1.5 | Critical | Non-Compliant | Delete root access keys via AWS Console (Account Settings); enable hardware or virtual MFA on root. |
| **2** | 3 of 7 console IAM users lack MFA | 1.4 | High | Non-Compliant | Enforce virtual MFA device creation and association for all remaining console users via IAM console. |
| **3** | 4 IAM users have long-lived keys (>22 months without rotation) | 1.3 / 1.12 | Medium | Non-Compliant | Deactivate and delete keys >90 days old; migrate applications to IAM roles or Secrets Manager. |
| **4** | Weak password policy (8 chars, no complexity, no expiration, no MFA req) | 1.8 / 1.9 / 1.10 | Medium | Non-Compliant | Update IAM password policy: min length 14, uppercase, lowercase, numbers, symbols, 90-day expiration. |
| **5** | CloudTrail disabled in `us-east-2` (DR region with clinical backups) | 3.1 / 3.2 | High | Non-Compliant | Enable CloudTrail multi-Region trail or configure trail in `us-east-2` writing to central S3 bucket. |
| **6** | S3 bucket `meddefense-clinical-backup-2022` has Block Public Access disabled and public `s3:GetObject` policy | 2.1 / 2.3 | Critical | Non-Compliant | Enable S3 Block Public Access; remove `Principal: "*"` bucket policy; enforce KMS encryption. |
| **7** | Three IAM roles carry AWS-managed `AdministratorAccess` (`Dev`, `Legacy`, `Vendor`) | 1.16 | High | Non-Compliant | Replace broad `AdministratorAccess` with least-privilege customer-managed inline/managed policies. |
| **8** | VPC Flow Logs disabled across all VPCs | 3.9 | Medium | Non-Compliant | Enable VPC Flow Logs for all active VPCs, directing logs to CloudWatch Logs or S3. |
| **9** | `MedDefenseEHRBackupRole` previously used wildcard `s3:*` on `Resource: *` | 1.16 | High | Remediation Ready | Deploy corrected `ehr_backup_policy.json` scoped strictly to `meddefense-ehr-backup-prod` and specific KMS key. |
| **10** | AWS Organizations and Service Control Policies (SCPs) not configured | 4.1 | Medium | Non-Compliant | Establish AWS Organizations root, create organizational units (OUs), and apply foundational SCPs. |

---

## Critical Findings

### Finding 1: Unsecured Root Account and Active Root Access Keys (Obs. 1)
- **CIS Control:** 1.1 (Maintain current contact details), 1.2 (Ensure security questions are registered), 1.5 (Disable and remove access keys for the AWS account root user).
- **Risk:** The AWS root account holds absolute administrative privileges over the entire cloud environment. Having active root access keys created in March 2022 with no MFA creates an immediate single point of total infrastructure compromise. If compromised, attackers can delete S3 buckets, terminate databases, and lock out legitimate administrators.
- **Remediation:** Immediately log into the root account, delete the legacy access keys (`aws iam delete-access-key`), and configure an enterprise hardware MFA device (FIDO2 security key).

### Finding 2: Publicly Accessible ePHI Backup S3 Bucket (Obs. 6)
- **CIS Control:** 2.1 (Ensure S3 Bucket Policy does not allow public access), 2.3 (Ensure S3 Block Public Access is enabled).
- **Technical & Regulatory Details:** 
  - **`Principal: "*"`**: Grants unauthenticated or public access to any AWS principal across the internet.
  - **`s3:GetObject`**: Allows any external entity to download files directly from the bucket.
  - **ePHI Exposure & HIPAA Breach Notification Rule (45 CFR 164.402)**: The bucket contains historical clinical backup archives comprising electronic Protected Health Information (ePHI). Under 45 CFR 164.402, an impermissible acquisition, access, use, or disclosure of unencrypted ePHI compromises the security or privacy of the data, creating a **presumed breach** requiring mandatory notification to affected patients, the Department of Health and Human Services (HHS), and media outlets unless a low probability of compromise is demonstrated.
- **Remediation:** 
  1. Enable Amazon S3 Block Public Access (`PutPublicAccessBlock`) at the bucket level.
  2. Immediately remove the permissive bucket policy allowing `Principal: "*"`.
  3. Restrict access exclusively to authorized backup IAM roles (`MedDefenseEHRBackupRole`).

### Finding 3: Unconstrained Administrator Access Roles (Obs. 7)
- **CIS Control:** 1.16 (Ensure IAM policies are granted least privilege).
- **Risk:** Assigning AWS-managed `AdministratorAccess` to `MedDefenseDevRole`, `MedDefenseLegacyRole`, and `MedDefenseVendorAccess` violates the principle of least privilege. A compromised developer laptop or third-party vendor integration grants full administrative takeover of the cloud estate.
- **Remediation:** Decommission unused legacy roles (`MedDefenseLegacyRole`), restrict vendor access with time-bound sessions and MFA (`MedDefenseVendorAccess`), and transition developer roles to scoped, service-specific permission sets.

---

## Remediation Priority Order

1. **Phase 1 (Immediate / 24 Hours):**
   - Address Observation 6: Enable S3 Block Public Access and remove public policies on `meddefense-clinical-backup-2022`.
   - Address Observation 1: Delete root access keys and enable root MFA.
   - Address Observation 2: Enforce MFA for the 3 non-compliant console IAM users.

2. **Phase 2 (Within 7 Days):**
   - Address Observations 7 and 9: Replace `AdministratorAccess` roles with least-privilege policies and deploy the corrected EHR backup and SIEM reader policies.
   - Address Observation 5: Enable CloudTrail in `us-east-2`.

3. **Phase 3 (Within 30 Days):**
   - Address Observations 3, 4, 8, and 10: Rotate long-lived access keys, strengthen IAM password policies, enable VPC Flow Logs across all VPCs, and configure AWS Organizations with baseline SCPs.

---

## Estimated Effort

- **Immediate Phase (Critical Fixes):** 4 engineering hours (urgent risk mitigation).
- **Secondary Phase (Policy & Logging Refinement):** 16 engineering hours (testing and validation).
- **Governance Phase (Organizations & Password Baselines):** 12 engineering hours (administrative rollout).
- **Total Estimated Effort:** 32 engineering hours.
