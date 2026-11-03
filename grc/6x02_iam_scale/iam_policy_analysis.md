# MedDefense IAM Policy Analysis

## Policy 1: MedDefenseSIEMLogReader Violations
- **Identified Violations**: The original policy utilized wildcard scopes (`s3:*` across `*` resources and overly broad CloudWatch log management permissions) allowing the reader role to modify bucket lifecycles, delete logs, and access unrelated sensitive buckets.
- **Attack Surface & Risk**: An attacker compromising the SIEM reader Lambda or worker role could leverage wide permissions to tamper with audit logs, delete forensic evidence, or exfiltrate non-SIEM sensitive buckets.
- **Correction & Rationale**: Scoped permissions strictly to `s3:GetObject` and `s3:ListBucket` exclusively against `meddefense-siemlog-prod`, and restricted CloudWatch Logs write actions (`CreateLogStream`, `PutLogEvents`) specifically to the `/aws/lambda/siem-log-reader` log group.

## Policy 2: MedDefenseEHRBackupRole Violations
- **Identified Violations**: The EHR backup role previously granted `s3:*` on `*` and wildcard KMS decryption/administration permissions, exposing sensitive electronic Protected Health Information (ePHI) backups to unauthorized read/write/delete operations.
- **Attack Surface & Risk**: Broad KMS and S3 permissions mean that any vulnerability in the backup automation script allows an attacker to decrypt clinical master keys or purge historical patient database backups, directly violating HIPAA integrity and availability requirements.
- **Correction & Rationale**: Restricted S3 actions to the dedicated backup bucket (`meddefense-ehr-backup-prod`) and scoped KMS operations exclusively to the designated multi-Region customer managed key (`arn:aws:kms:us-east-1:123456789012:key/mrk-abc123def456`) using necessary primitive actions (`Encrypt`, `Decrypt`, `GenerateDataKey`, `DescribeKey`).

## Policy 3: MedDefenseBreakGlassAdmin Violations
- **Identified Violations**: The original break-glass emergency account had permanent, unconditional `AdministratorAccess` without geographic or multi-factor authentication (MFA) constraints.
- **Attack Surface & Risk**: Stolen credentials or session hijacking of the break-glass account would grant an immediate, unrestricted domain takeover without secondary verification or origin validation.
- **Correction & Rationale**: Retained emergency administrator capabilities while enforcing strict condition blocks requiring verified multi-factor authentication (`aws:MultiFactorAuthPresent: true`) and restricting origin IP addresses to authorized secure management networks (`198.51.100.0/24`), backed by explicit denial statements for non-compliant sessions.

## Least Privilege Summary
Transitioning MedDefense's cloud IAM posture from legacy wildcard configurations to rigorous least-privilege scoping eliminates lateral movement vectors, prevents ePHI exposure, and aligns the cloud architecture with CIS AWS Benchmarks and NIST SP 800-53 control baselines.

## Residual Risk and Operational Notes
- **Operational Monitoring**: Changes to backup and SIEM roles must be validated against automated deployment pipelines to ensure logging ingestion and EHR snapshots complete without permission errors.
- **Break-Glass Testing**: Quarterly dry-run simulations of break-glass authentication from the authorized subnet with MFA are mandatory to ensure administrative readiness during high-severity incidents.
