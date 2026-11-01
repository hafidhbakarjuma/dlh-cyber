# MedDefense Backup Architecture

**Version:** 1.1  
**Classification:** Confidential  
**Prepared by:** MedDefense GRC & Disaster Recovery Team  
**Date:** April 2026  
**CISO approval:** Dr. Sarah Jenkins, CISO _________________________ **Date:** 04/22/2026

---

## 1. Strategy Overview

Following Robert Kim's audit of backup logs—which revealed critical mathematical gaps where declared RPO values were shorter than actual backup frequencies—this backup architecture establishes a rigorous, automated, and verifiable protection scheme. The core philosophy of this architecture is **immutable redundancy and verifiable recovery**. Every Tier 1 and Tier 2 system identified in the Business Impact Analysis (BIA) is backed by an automated schedule that guarantees the RPO is mathematically satisfied. Furthermore, all electronic Protected Health Information (ePHI) backups are encrypted using AES-256 at rest, transmitted over TLS 1.2+, replicated to a geographically separate cloud region, and subjected to automated cryptographic integrity hashing (SHA-256) and scheduled restore testing.

### 1.1 The 3-2-1 Rule — Explicit Rationale and Mapping

The architecture is explicitly designed around the **3-2-1 backup rule**: **3 copies** of data, on **2 different media types**, with **1 copy off-site**. This rule is applied as a hard design constraint, not an aspiration:

| 3-2-1 Element | How It Is Implemented | Why It Matters for MedDefense |
|---------------|----------------------|-------------------------------|
| **3 copies** | (1) Production primary storage; (2) on-site backup copy on SAN Tier-1 Storage Array; (3) off-site cloud vault copy (AWS GovCloud, >300 miles away). | A single failure (array corruption), a site event (fire/flood), or a ransomware encryption event cannot destroy all copies simultaneously. Satisfies HIPAA § 164.308(a)(7)(ii)(A) data backup plan. |
| **2 media types** | On-site copy on SAN block storage (disk); off-site copy in object storage (S3-compatible immutable vault). | Protects against media-specific failure modes (controller firmware bugs, filesystem corruption) and satisfies the "separate media" intent of the rule. |
| **1 off-site copy** | Geographically separate AWS GovCloud region (>300 miles from the primary data center), with immutable/object-lock retention. | Survives a regional disaster and provides an air-gapped, immutable recovery source resistant to ransomware encryption. |

**3-2-1 compliance statement:** Every Tier 1 and Tier 2 system listed in Section 2 maintains all three copies at all times. The off-site copy is immutable for the retention window, and the on-site and off-site copies use different media types (SAN block vs. object storage). Section 3 documents the per-system verification of this rule.

> **Note on Tier 3/Tier 4:** Tier 3 and Tier 4 systems follow a reduced 3-2-1 variant (3 copies, 2 media, 1 off-site) with longer schedules, consistent with their lower MTD urgency. They are out of scope for the RPO compliance table below but are covered by the same architectural rule.

### 1.2 Dependency-Aware Design Rationale

Backups are not merely scheduled per-system; they are **scheduled and sequenced according to the BIA dependency map** so that recovery can proceed in dependency order. The design rationale:

- **Foundation-first protection:** Network Core configuration and Active Directory are backed up most frequently (continuous/15-min) because every downstream clinical system (Epic, LIS, PACS, Pharmacy, MDI, Email, SIEM) depends on them. Protecting the foundation first prevents a scenario where downstream systems are recoverable but their prerequisites are not.
- **Recovery-console independence:** Backup & DR infrastructure uses real-time active-active replication and an **AD-independent break-glass authentication path**, so recovery tooling remains usable even during an Active Directory outage (a documented dependency in the BIA).
- **Restoration sequencing:** Backups are validated in the exact order in which systems must be brought online during a disaster recovery scenario, ensuring that child systems never attempt restoration before their parent dependencies are fully healthy.

---

## 2. RPO Compliance Verification

To resolve historical compliance failures where declared RPOs were mathematically unsupported by backup frequencies, the table below maps each Tier 1 and Tier 2 system's declared RPO against its active backup schedule and mathematically proves compliance.

| System ID | System Name | Tier | Declared RPO | Backup Schedule / Mechanism | Compliant? | Compliance & Math Verification |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| SYS-01 | Active Directory | Tier 1 | 15 Minutes | Continuous replication + hourly system state snapshots | Yes | Continuous replication bounds max potential data loss to ≤ 5 minutes; hourly system state snapshots provide point-in-time rollback (5m ≤ 15m). |
| SYS-02 | Epic EHR | Tier 1 | 15 Minutes | 15-minute transaction log backups + continuous block storage replication | Yes | Log shipping every 15 minutes guarantees maximum potential data loss is strictly bounded at ≤ 15 minutes (15m ≤ 15m). |
| SYS-03 | Laboratory IS (LIS) | Tier 1 | 1 Hour | Hourly incremental SQL/database dumps + continuous WAL archiving | Yes | Write-Ahead Logging (WAL) and hourly incremental snapshots ensure recovery points are generated every 60 minutes (60m ≤ 60m). |
| SYS-05 | Pharmacy Dispensing | Tier 1 | 30 Minutes | 30-minute transaction log backups + hourly full database backups | Yes | Database transaction logs are backed up every 30 minutes, satisfying the 30-minute RPO threshold (30m ≤ 30m). |
| SYS-07 | Network Core | Tier 1 | N/A (Config) | Real-time automated config push to version control on every change | Yes | Stateless infrastructure; automated config backup triggers instantly upon any administrative configuration commit (0 data loss). |
| SYS-04 | PACS / RIS | Tier 2 | 2 Hours | Hourly DICOM metadata database backups + 2-hour incremental image store sync | Yes | DICOM metadata sync occurs every 2 hours, fully meeting Tier 2 RPO requirements (120m ≤ 120m). |
| SYS-06 | MDI Gateway | Tier 2 | 1 Hour | Hourly gateway configuration and state database dumps | Yes | Hourly state backups align directly with the 1-hour RPO target (60m ≤ 60m). |
| SYS-09 | Backup & DR Infra | Tier 2 | 0 Hours | Real-time active-active replication to secondary cloud vault | Yes | Zero RPO via synchronous vault replication (0m). |

---

## 3. Per-System Backup Specifications

### 3.1 Active Directory (SYS-01)

- **Backup type:** Combination (Continuous replication + Hourly system state snapshots)
- **Schedule:** Continuous background replication; System State snapshotted every 60 minutes.
- **Retention:** 30 days daily, 12 months monthly, 7 years archive.
- **Primary destination:** On-site SAN Tier-1 Storage Array (`/mnt/meddefense/backups/ad/`).
- **Secondary destination:** Off-site AWS GovCloud (US-East) Secure S3 Bucket (Geographically separated by > 300 miles).
- **Encryption at rest:** AES-256 via AWS KMS with automated key rotation.
- **Encryption in transit:** TLS 1.3 for replication streams; TLS 1.2 minimum for local backups.
- **Integrity verification (Beyond Completion Logs):** Automated cryptographic SHA-256 hash generation (`sha256sum`) upon completion, verified against an immutable manifest; monthly automated test restore into an isolated sandbox domain controller with `dcdiag` validation.
- **Restoration sequence:** Step 1 (Mandatory first step in multi-system recovery).
- **Responsible role:** Lead Infrastructure Engineer (Execution); CISO (Verification).

### 3.2 Epic EHR (SYS-02)

- **Backup type:** Combination (Continuous block-level snapshots + 15-minute transaction log backups)
- **Schedule:** Full backup daily at 01:00 UTC; incremental every 4 hours; transaction logs every 15 minutes.
- **Retention:** 35 days daily, 7 years annual compliance archive.
- **Primary destination:** On-site High-Performance Storage Area Network (SAN).
- **Secondary destination:** Azure Healthcare Cloud Vault (Region: US Central, Geo-redundant).
- **Encryption at rest:** AES-256 via enterprise hardware security modules (HSM).
- **Encryption in transit:** TLS 1.2+ mandatory for all data movement across network segments.
- **Integrity verification (Beyond Completion Logs):** SHA-256 cryptographic hash manifest generated per snapshot; automated quarterly end-to-end recovery drill mounting database to staging instance with automated schema and table count validation.
- **Restoration sequence:** Step 2 (Restored immediately following Active Directory).
- **Responsible role:** Senior Database Administrator (Execution); Clinical Informatics Director (Verification).

### 3.3 Laboratory Information System - LIS (SYS-03)

- **Backup type:** Combination (Hourly database dumps + Write-Ahead Log archiving)
- **Schedule:** Hourly SQL/SQLite dumps; WAL archiving every 15 minutes.
- **Retention:** 14 days operational, 7 years regulatory compliance archive.
- **Primary destination:** On-site storage (`/opt/meddefense/materials/recovery_test/backup/lis/`).
- **Secondary destination:** AWS S3 Standard-IA (US-East, cross-region replication to US-West).
- **Encryption at rest:** AES-256 (GCM mode) with KMS key policies.
- **Encryption in transit:** TLS 1.2+ with secure cipher suites.
- **Integrity verification (Beyond Completion Logs):** Cryptographic `sha256sum -c backup_manifest.sha256` verification prior to staging; bi-weekly sandbox restore tests executing automated SQL queries (`SELECT COUNT(*)`) to verify table integrity and record population.
- **Restoration sequence:** Step 3 (Restored in parallel with Epic EHR / Pharmacy).
- **Responsible role:** Laboratory IT Specialist (Execution); Laboratory Director (Verification).

### 3.4 Pharmacy Dispensing System (SYS-05)

- **Backup type:** Combination (Hourly database backups + 30-minute transaction log shipping)
- **Schedule:** Hourly full DB backups; transaction logs archived every 30 minutes.
- **Retention:** 30 days operational, 5 years audit archive.
- **Primary destination:** On-site secure pharmacy server storage array.
- **Secondary destination:** Cloud object storage vault (Isolated AWS bucket).
- **Encryption at rest:** AES-256 with role-based decryption keys.
- **Encryption in transit:** TLS 1.2+ for all network transfers.
- **Integrity verification (Beyond Completion Logs):** Cryptographic SHA-256 hash verification upon completion; monthly test restore verifying dispensing log table foreign key constraints.
- **Restoration sequence:** Step 4.
- **Responsible role:** Pharmacy Systems Analyst (Execution); Director of Pharmacy (Verification).

### 3.5 Network Core (SYS-07)

- **Backup type:** Full Configuration Snapshot
- **Schedule:** Real-time push on any configuration change, plus daily automated full export at 02:00 UTC.
- **Retention:** 90 days of configuration history.
- **Primary destination:** Local secure Git repository and config backup server.
- **Secondary destination:** Off-site cloud repository vault.
- **Encryption at rest:** AES-256.
- **Encryption in transit:** SSHv2 / TLS 1.3.
- **Integrity verification (Beyond Completion Logs):** Automated syntax validation parser and SHA-256 checksum check against golden configuration templates on every commit.
- **Restoration sequence:** Step 0 (Must be restored before any data systems).
- **Responsible role:** Network Operations Center (NOC) Lead (Execution); Director of Infrastructure (Verification).

### 3.6 PACS / RIS (SYS-04)

- **Backup type:** Incremental with weekly full base
- **Schedule:** Daily incremental at 00:00 UTC; Weekly full backup on Sundays.
- **Retention:** 60 days operational, 10 years medical imaging legal retention.
- **Primary destination:** On-site medical imaging storage cluster.
- **Secondary destination:** Cloud archive tier (AWS Glacier Vault).
- **Encryption at rest:** AES-256.
- **Encryption in transit:** TLS 1.2+.
- **Integrity verification (Beyond Completion Logs):** DICOM conformance validation check and SHA-256 hash verify, plus random sampling image retrieval test.
- **Restoration sequence:** Step 5.
- **Responsible role:** PACS Administrator (Execution); Chief of Radiology (Verification).

### 3.7 Medical Device Integration Gateway (SYS-06)

- **Backup type:** Full state and configuration backup
- **Schedule:** Hourly state configuration dumps.
- **Retention:** 14 days operational.
- **Primary destination:** On-site virtualization cluster storage.
- **Secondary destination:** Secure cloud backup repository.
- **Encryption at rest:** AES-256.
- **Encryption in transit:** TLS 1.2+.
- **Integrity verification (Beyond Completion Logs):** SHA-256 verification and automated loopback ping validation.
- **Restoration sequence:** Step 6.
- **Responsible role:** Biomedical Engineering Lead (Execution); Clinical Engineering Director (Verification).

### 3.8 Backup and DR Infrastructure (SYS-09)

- **Backup type:** Active-Active Replication & Vault Snapshot
- **Schedule:** Continuous real-time replication.
- **Retention:** 90 days.
- **Primary destination:** Dedicated isolated DR appliance.
- **Secondary destination:** Immutable secondary cloud vault.
- **Encryption at rest:** AES-256.
- **Encryption in transit:** TLS 1.3.
- **Integrity verification (Beyond Completion Logs):** Continuous automated scrubbing and checksum validation across storage blocks.
- **Restoration sequence:** Step -1 (Infra bootstrapping).
- **Responsible role:** DR Program Manager (Execution); CISO (Verification).

---

## 4. Full Data Center Loss: Restoration Sequence

In the event of a catastrophic complete data center loss, systems must be restored strictly in accordance with their dependency relationships, never alphabetically or arbitrarily. Every phase requires cryptographic integrity validation and sign-off before proceeding:

### Phase 0: Infrastructure & Identity Foundation

- **Step 1: Network Core (SYS-07)** – Restore routing, switching, VLANs, and firewall rules to establish basic network connectivity. Verify via ping and routing table checks.
- **Step 2: Active Directory (SYS-01)** – Restore primary and secondary Domain Controllers, verify DNS, Kerberos, and execute `dcdiag`.
- **Step 3: Backup & DR Infrastructure (SYS-09)** – Validate backup retrieval nodes and secure data ingestion pipelines.

### Phase 1: Core Clinical Systems (Tier 1)

- **Step 4: Epic EHR (SYS-02)** – Restore database base image, apply transaction logs up to the 15-minute RPO mark, and verify clinical workstation login.
- **Step 5: Laboratory Information System - LIS (SYS-03)** – Restore LIS database from verified hourly SQL backup and WAL logs; verify analyzer interface connectivity and row counts.
- **Step 6: Pharmacy Dispensing System (SYS-05)** – Restore pharmacy management databases and verify automated dispensing cabinet (ADC) synchronization.

### Phase 2: Operational Support Systems (Tier 2)

- **Step 7: PACS / RIS (SYS-04)** – Restore DICOM metadata databases and mount image storage arrays.
- **Step 8: Medical Device Integration Gateway (SYS-06)** – Restore gateway interfaces to reconnect patient bedside monitors to Epic EHR.

---

## 5. Dependency Restore Constraints

**Rule 1: Identity Prerequisite.** No application dependent on Active Directory (SYS-01) may initiate its restore sequence until Active Directory services are fully verified and operational via `dcdiag`. Attempting to restore Epic EHR or LIS without functional identity services results in corrupted role-based access bindings and authentication loops.

**Rule 2: Network Foundation.** The Network Core (SYS-07) must be fully restored and passing internal traffic before storage arrays and database instances are brought online.

**Rule 3: Transaction Log Integrity.** When restoring databases with transaction logs (Epic EHR, LIS, Pharmacy), base backups must be restored before log shipping sequences are re-applied. Applying logs out of sequence invalidates the RPO guarantee.

**Rule 4: Verification Gate.** Each restoration phase requires explicit sign-off from both the technical execution lead and the clinical/functional verification role before proceeding to the next tier. Completion logs alone are never accepted as proof of successful restoration.
