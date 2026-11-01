# MedDefense Command-Level Recovery Runbooks
**Version:** 1.0  
**Classification:** Confidential  
**Prepared by:** MedDefense GRC & Disaster Recovery Team  
**Date:** April 2026  
**CISO approval:** _________________________ Date: _________  

---

## Runbook 1: Laboratory Information System (LIS) Recovery

### Overview
*   **System:** Laboratory Information System (LIS) — Tier 1 Critical
*   **Scenario:** Catastrophic corruption or loss of the primary LIS database instance requiring a full restore from compressed backup to a clean recovery workspace.
*   **Backup Source:** `/tmp/meddefense-dr-test/backup/lis/2026-04-21/lis_backup.sql.gz`
*   **Checksum Manifest:** `/tmp/meddefense-dr-test/backup/lis/2026-04-21/backup_manifest.sha256`
*   **Recovery Target:** `/tmp/meddefense-dr-test/recovery/lis_recovered.db`
*   **App Config:** `/tmp/meddefense-dr-test/config/app_config.env`

---

### Step-by-Step Execution Procedure

#### Step 1: Identify the Latest Recovery Target and Backup Path
*   **Command / Action:**  
    Locate and confirm the backup file and checksum manifest in the active backup directory.
    ```bash
    ls -lh /tmp/meddefense-dr-test/backup/lis/2026-04-21/
    ```
*   **Expected Output:**  
    ```text
    total 24K
    -rw-r--r-- 1 student student  145 Apr 21 02:00 backup_manifest.sha256
    -rw-r--r-- 1 student student 4.2K Apr 21 02:00 lis_backup.sql.gz
    ```
*   **Verification Check:**  
    Confirm both `lis_backup.sql.gz` and `backup_manifest.sha256` exist and have non-zero file sizes.
*   **Deviation Handling:**  
    If files are missing, verify that the backup mount point is active. If the directory path is incorrect, check `/opt/meddefense/materials/recovery_test/lab_config.env` for environment variable overrides.

---

#### Step 2: Verify Backup Integrity with SHA-256 Sum
*   **Command / Action:**  
    Verify the cryptographic integrity of the compressed SQL backup against the provided checksum manifest.
    ```bash
    cd /tmp/meddefense-dr-test/backup/lis/2026-04-21/
    sha256sum -c backup_manifest.sha256
    ```
*   **Expected Output:**  
    ```text
    lis_backup.sql.gz: OK
    ```
*   **Verification Check:**  
    Ensure the output explicitly returns `OK`.
*   **Deviation Handling:**  
    If verification fails (`FAILED`), do **not** proceed with the restore. The backup archive is corrupted. Escalate immediately to the Storage Engineering lead and retrieve the secondary backup from the AWS S3 cloud vault.

---

#### Step 3: Create the Recovery Workspace
*   **Command / Action:**  
    Ensure the destination recovery and staging directories exist with proper permissions.
    ```bash
    mkdir -p /tmp/meddefense-dr-test/recovery
    ```
*   **Expected Output:**  
    Command completes silently with exit code `0`.
*   **Verification Check:**  
    ```bash
    test -d /tmp/meddefense-dr-test/recovery && echo "Directory verified"
    ```
*   **Deviation Handling:**  
    If permission is denied, verify you are executing as the authorized recovery user (`student` or `root`) within `/tmp/meddefense-dr-test/`.

---

#### Step 4: Decompress the Backup to Staging Path
*   **Command / Action:**  
    Decompress the gzipped SQL dump into the staging recovery workspace.  
    *(Known Legacy Runbook Deviation Note: The obsolete runbook references `/recovery/lis_dump.sql`. The corrected path for this environment is `/tmp/meddefense-dr-test/recovery/lis_dump.sql`)*.
    ```bash
    gunzip -c /tmp/meddefense-dr-test/backup/lis/2026-04-21/lis_backup.sql.gz > /tmp/meddefense-dr-test/recovery/lis_dump.sql
    ```
*   **Expected Output:**  
    Command completes silently with exit code `0`.
*   **Verification Check:**  
    ```bash
    ls -lh /tmp/meddefense-dr-test/recovery/lis_dump.sql
    ```
    Must show the SQL dump file with expected uncompressed size (~15KB–50KB).
*   **Deviation Handling:**  
    If disk space is exhausted (`No space left on device`), clear non-essential logs in `/tmp` or mount supplementary scratch storage.

---

#### Step 5: Restore the SQL Dump into SQLite Database
*   **Command / Action:**  
    Execute the SQLite command to ingest the SQL dump into the target recovery database.
    ```bash
    sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db < /tmp/meddefense-dr-test/recovery/lis_dump.sql
    ```
*   **Expected Output:**  
    Command completes silently with exit code `0`.
*   **Verification Check:**  
    Verify the database file was created and contains tables:
    ```bash
    sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db ".tables"
    ```
    *Expected tables:* `patient_orders`, `lab_results`, `audit_log`.
*   **Deviation Handling:**  
    If SQLite reports syntax errors, inspect `lis_dump.sql` head lines to ensure the backup file is not truncated or corrupted.

---

#### Step 6: Check Row Count in `patient_orders`
*   **Command / Action:**  
    Query the restored database to verify table population and baseline record counts.
    ```bash
    sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db "SELECT COUNT(*) FROM patient_orders;"
    ```
*   **Expected Output:**  
    ```text
    5
    ```
*   **Verification Check:**  
    Confirm the row count matches the expected baseline count of 5 records defined in `expected_lis_records.txt`.
*   **Deviation Handling:**  
    If row count is zero, the database schema imported without data. Re-run Step 5 with a freshly extracted SQL dump.

---

#### Step 7: Confirm Critical Results for MRN-10043 and MRN-10045
*   **Command / Action:**  
    Query specific critical patient identifiers to verify clinical data integrity.
    ```bash
    sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db "SELECT mrn, test_name, result_value, status FROM patient_orders WHERE mrn IN ('MRN-10043', 'MRN-10045');"
    ```
*   **Expected Output:**  
    ```text
    MRN-10043|Serum Potassium|5.8 mmol/L|CRITICAL_HIGH
    MRN-10045|Troponin T|0.45 ng/mL|CRITICAL_POSITIVE
    ```
*   **Verification Check:**  
    Verify that abnormal/critical values match the expected clinical test records.
*   **Deviation Handling:**  
    If records are missing or mismatched, flag the database as unverified and notify the Laboratory Director immediately.

---

#### Step 8: Inspect `app_config.env` and Identify Configuration Artifacts
*   **Command / Action:**  
    Review the application configuration file to check database connection parameters.
    ```bash
    cat /tmp/meddefense-dr-test/config/app_config.env
    ```
*   **Expected Output:**  
    ```text
    DB_HOST=lis-db-prod.meddefense.internal
    DB_PORT=5432
    DB_NAME=lis_production
    ```
*   **Verification Check:**  
    Confirm `DB_HOST=lis-db-prod.meddefense.internal` is identified as a production artifact pointing to the offline/failed server.
*   **Deviation Handling:**  
    Recognize that during an isolated offline recovery test, attempting to connect to `lis-db-prod.meddefense.internal` will fail name resolution.

---

#### Step 9: Apply Local Recovery Override for Validation
*   **Command / Action:**  
    Bypass the production host configuration by applying a local path override pointing directly to the restored SQLite recovery database.
    ```bash
    export LIS_DB_PATH="/tmp/meddefense-dr-test/recovery/lis_recovered.db"
    sqlite3 $LIS_DB_PATH "SELECT 'Override Active: ' || datetime('now');"
    ```
*   **Expected Output:**  
    ```text
    Override Active: 2026-04-21 03:30:15
    ```
*   **Verification Check:**  
    Confirm the query executes successfully against the local override path.
*   **Deviation Handling:**  
    If environment export fails, prefix the validation commands explicitly with the database path.

---

#### Step 10: Record Notification Content for the Clinical Team
*   **Command / Action:**  
    Generate and log the official downtime clearance notice for nursing stations.
    ```bash
    echo "[$(date)] LIS RESTORE COMPLETED: Database recovered to /tmp/meddefense-dr-test/recovery/lis_recovered.db. Integrity verified via SHA-256. Critical results for MRN-10043 and MRN-10045 confirmed." | tee /tmp/meddefense-dr-test/recovery/clinical_clearance.log
    ```
*   **Expected Output:**  
    Logs clearance text to both stdout and `/tmp/meddefense-dr-test/recovery/clinical_clearance.log`.
*   **Verification Check:**  
    ```bash
    cat /tmp/meddefense-dr-test/recovery/clinical_clearance.log
    ```
*   **Deviation Handling:**  
    Ensure the charge nurse and LIS supervisor receive the clearance log immediately via secure messaging.

---

## Runbook 2: Active Directory Recovery (Single DC Loss with Secondary DC Available)

### Overview
*   **System:** Active Directory Domain Services (SYS-01) — Tier 1 Critical
*   **Scenario:** Confirmed unrecoverable hardware or virtualization failure of Domain Controller `DC01`, with secondary Domain Controller `DC02` operating normally and holding healthy replication partners.
*   **Environment Note:** Because the lab container is Linux-based, this Active Directory runbook is documentation-only, utilizing standard command output examples from `/opt/meddefense/materials/runbooks/command_output_examples.md`.

---

### Step-by-Step Execution Procedure

#### Step 1: Query FSMO Role Holders (`netdom query fsmo`)
*   **Command / Action:**  
    Run from surviving healthy Domain Controller (`DC02`) to identify current FSMO role distribution and verify whether failed `DC01` held operational roles.
    ```powershell
    netdom query fsmo
    ```
*   **Expected Output:**  
    ```text
    Schema master             DC02.meddefense.internal
    Domain naming master      DC02.meddefense.internal
    PDC                       DC02.meddefense.internal
    RID pool manager          DC02.meddefense.internal
    Infrastructure master     DC02.meddefense.internal
    The command completed successfully.
    ```
*   **Verification Check:**  
    Confirm that FSMO roles have either successfully transferred to `DC02` or that seizure commands (`seize pdc`, etc.) must be executed if `DC01` was holding roles at the time of failure.
*   **Deviation Handling:**  
    If roles remain assigned to dead `DC01`, use `ntdsutil` to seize the roles to `DC02`.

---

#### Step 2: Authoritative vs. Non-Authoritative Restore Decision
*   **Decision Criteria:**  
    *   *Non-Authoritative Restore (Standard):* Used when rebuilding `DC01` from backup to rejoin the existing forest. Restored data is brought up to date by inbound replication from healthy `DC02`. **(Recommended for single DC failure where `DC02` is healthy)**.
    *   *Authoritative Restore:* Used only if accidental mass deletion of objects (e.g., organizational units, user accounts) occurred across all DCs and must be rolled back authoritatively. **(Do not use for hardware loss when `DC02` is healthy)**.
*   **Action:** Select Non-Authoritative Restore for `DC01` system state restoration.

---

#### Step 3: Execute System State Recovery (`wbadmin start systemstaterecovery`)
*   **Command / Action:**  
    Restore Active Directory database and SYSVOL via Windows Backup utility in Directory Services Restore Mode (DSRM).
    ```powershell
    wbadmin start systemstaterecovery -version:04/21/2026-02:00 -backupTarget:\\backup-vault\meddefense-ad\ -authSysvol
    ```
*   **Expected Output:**  
    Prompt requests confirmation (`Y/N`), followed by progress indicators showing system state extraction and database restoration.
*   **Verification Check:**  
    Review restoration log at `C:\Windows\Logs\WindowsBackup\systemstate.log` for zero error codes.
*   **Deviation Handling:**  
    If system state recovery fails due to hardware signature mismatches, perform a clean OS rebuild of `DC01`, join as an additional domain controller, and promote via `Install-ADDSDomainController`.

---

#### Step 4: Perform Replication Health Check (`repadmin /showrepl`)
*   **Command / Action:**  
    Verify inbound and outbound replication topology between `DC01` and `DC02`.
    ```powershell
    repadmin /showrepl
    ```
*   **Expected Output:**  
    ```text
    Default-First-Site-Name\DC02
    DSA Options: IS_GC
    Site object options: (none)
    DSA object GUID: a1b2c3d4-e5f6-7890-abcd-ef0123456789
    DSA invocationID: 98765432-10fe-dcba-9876-543210fedcba

    Incoming Neighbors:
    Default-First-Site-Name\DC01
        DC via RPC
        DSA object GUID: 12345678-abcd-ef01-2345-6789abcdef01
        Last attempt @ 2026-04-21 03:45:00 was successful.
    ```
*   **Verification Check:**  
    Confirm that `Last attempt... was successful` appears for all naming contexts across all domain controllers.
*   **Deviation Handling:**  
    If replication errors occur (e.g., Error 1722: RPC server unavailable), verify DNS resolution and restart the `NTDS` service.

---

#### Step 5: Execute DCDiag Validation Sequence (`dcdiag`)
*   **Command / Action:**  
    Run comprehensive domain controller diagnostics to validate overall forest and service health.
    ```powershell
    dcdiag /s:DC02 /a /c
    ```
*   **Expected Output:**  
    ```text
    Starting test: Connectivity
        .................. DC02 passed test Connectivity
    Starting test: Replications
        .................. DC02 passed test Replications
    Starting test: NCSecDesc
        .................. DC02 passed test NCSecDesc
    Starting test: NetLogons
        .................. DC02 passed test NetLogons
    Starting test: Advertising
        .................. DC02 passed test Advertising
    ```
*   **Verification Check:**  
    Ensure every diagnostic test reports `passed test`.
*   **Deviation Handling:**  
    Investigate any failed test category (such as `Advertising` or `FrsSysVol`), resolve underlying DNS or time-sync (`W32Time`) issues, and re-run `dcdiag`.

---

#### Step 6: Recovery Declaration Criteria
*   **Criteria for Sign-off:**  
    1. FSMO roles verified and operational.  
    2. `repadmin /showrepl` reports zero synchronization failures.  
    3. `dcdiag` completes with 100% passing status across all domain controllers.  
    4. CISO and Infrastructure Director sign off on directory integrity.
