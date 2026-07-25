# MEDDEFENSE HEALTH SYSTEMS
## Cryptographic Implementation Playbook: Production Deployment  
**Status:** Operational Execution Playbook  

---

## Executive Summary
This operational playbook details the step-by-step procedures for deploying the top five highest-priority cryptographic changes across MedDefense production assets. Designed for execution by the IT infrastructure team on Monday morning, every action item outlines strict prerequisites, numbered technical commands, validation criteria, rollback plans, maintenance windows, and stakeholder communication protocols.

---

## Action #1: Patient Portal TLS Certificate Renewal & Cipher Hardening
* **Priority:** Immediate
* **System Affected:** `portal.meddefense.local`
* **Prerequisites:** Approved public CA certificate bundle, updated Nginx/Apache configuration file templates, and active backup of existing web server configurations.
* **Steps:**
  1. Transfer the new signed certificate (`portal.crt`), private key (`portal_key.pem`), and intermediate CA bundle (`ca_bundle.crt`) securely to `/etc/ssl/private/`.
  2. Update web server configuration (`/etc/nginx/sites-enabled/portal.conf`) to enforce TLS 1.2 and TLS 1.3 exclusively, disabling legacy TLS 1.0/1.1 and weak cipher suites.
  3. Test configuration syntax (`sudo nginx -t`) and reload the web service (`sudo systemctl reload nginx`).
* **Validation:**
  * Run `openssl s_client -connect portal.meddefense.local:443 -tls1_2` to confirm successful handshake, and verify with `-tls1` to ensure legacy protocols are rejected.
  * Verify 800 daily patient connections remain uninterrupted by checking HTTP 200 response rates and real-time load balancer traffic logs.
* **Rollback:**
  * Revert Nginx configuration symlink to previous backup state (`/etc/nginx/sites-enabled/portal.conf.bak`) and restore prior certificate files.
  * Maximum Acceptable Downtime: **< 2 minutes**.
* **Maintenance Window:** Overnight / Low-traffic window (02:00 AM – 03:00 AM).
* **Communication:** Notify Helpdesk and IT Operations prior to execution; broadcast success status to the Security Engineering channel post-deployment.

---

## Action #2: PostgreSQL Transparent Data Encryption (TDE) Implementation
* **Priority:** Immediate
* **System Affected:** `ehr-db-01`
* **Prerequisites:** Centralized KMS key vault initialized, database full cold backup completed and verified, and application maintenance mode scheduled.
* **Steps:**
  1. Enable maintenance mode on the EHR application tier to halt incoming database transactions.
  2. Install and configure the PostgreSQL encryption extension/module (e.g., `pg_tde` or enterprise TDE tablespace encryption packages).
  3. Initialize the master encryption key from the secure KMS vault and apply encryption settings to active EHR database tablespaces.
* **Validation:**
  * Execute database inspection queries to confirm storage-level cipher status (`SELECT * FROM pg_catalog.pg_tablespaces;`).
  * Verify application query performance and test full read/write integrity via automated EHR health checks.
* **Rollback:**
  * Stop PostgreSQL service, restore database from pre-encryption verified cold backup image, and revert configuration parameters.
  * Maximum Acceptable Downtime: **< 30 minutes**.
* **Maintenance Window:** Scheduled weekend maintenance window (Saturday 01:00 AM – 04:00 AM).
* **Communication:** Broadcast maintenance window to Clinical Care Teams and Hospital Management 48 hours in advance; confirm resolution upon completion.

---

## Action #3: NAS-01 Backup Storage Volume Encryption (LUKS)
* **Priority:** Phase 1
* **System Affected:** `NAS-01`
* **Prerequisites:** Offline storage migration of existing backups, hardware AES-NI verification, and secure out-of-band keyfile generation stored in the enterprise KMS.
* **Steps:**
  1. Unmount existing plaintext backup storage pools (`sudo umount /mnt/backups`).
  2. Format target storage block devices with LUKS encryption (`sudo cryptsetup luksFormat /dev/sdX`).
  3. Open the encrypted container (`sudo cryptsetup luksOpen /dev/sdX secure_backup_pool`), initialize an ext4 filesystem, and configure automated keyfile mounting via `/etc/crypttab`.
* **Validation:**
  * Perform a test reboot of `NAS-01` to ensure automated keyfile injection and filesystem mounting succeed without manual interruption.
  * Verify nightly backup job execution script successfully writes test archives to `/mnt/backups`.
* **Rollback:**
  * Detach encrypted mapper device, restore original unformatted partition table, and restore plaintext backup repository from secondary offline vault if mounting fails.
  * Maximum Acceptable Downtime: **< 2 hours**.
* **Maintenance Window:** Scheduled Sunday storage maintenance window (01:00 AM – 03:00 AM).
* **Communication:** Notify Backup Administrators and Infrastructure Operations before and after execution.

---

## Action #4: Billing Database TDE Implementation
* **Priority:** Phase 1
* **System Affected:** `billing-srv-01`
* **Prerequisites:** MySQL Enterprise Encryption keys provisioned in KMS, complete database mysqldump backup verified.
* **Steps:**
  1. Pause billing ingestion queues and active financial reporting batch jobs.
  2. Enable MySQL keyring plugin in `my.cnf` and configure master encryption keys.
  3. Alter existing billing tablespaces to enable encryption (`ALTER TABLE billing_records ENCRYPTION = 'Y';`).
* **Validation:**
  * Query INFORMATION_SCHEMA to confirm encryption status (`SELECT TABLE_NAME, ENCRYPTION FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = 'billing_db';`).
  * Verify transactional processing speed and financial software connectivity.
* **Rollback:**
  * Restore database tables from pre-modification `mysqldump` file and disable keyring configuration.
  * Maximum Acceptable Downtime: **< 15 minutes**.
* **Maintenance Window:** Weeknight off-peak hours (Tuesday 11:00 PM – 11:30 PM).
* **Communication:** Notify Finance Department and Billing Operations prior to maintenance; confirm system availability post-update.

---

## Action #5: Internal Database Transit Encryption (mTLS / SSL)
* **Priority:** Phase 1
* **System Affected:** `ehr-db-01` & Application Servers
* **Prerequisites:** Internal Root CA operational, server certificates distributed to database nodes.
* **Steps:**
  1. Update PostgreSQL configuration (`postgresql.conf`) to set `ssl = on` and configure paths to server certificate (`server.crt`) and private key (`server.key`).
  2. Enforce client verification parameters in `pg_hba.conf` (`hostssl all all all cert`).
  3. Restart PostgreSQL service (`sudo systemctl restart postgresql`).
* **Validation:**
  * Test database connection using explicit SSL mode (`psql "host=ehr-db-01 sslmode=verify-full dbname=ehr user=app"`) and verify handshake success.
  * Confirm application connection pooling successfully reconnects over encrypted channels.
* **Rollback:**
  * Revert `postgresql.conf` and `pg_hba.conf` to previous plaintext acceptance state and restart database service.
  * Maximum Acceptable Downtime: **< 5 minutes**.
* **Maintenance Window:** Low-traffic evening window (Thursday 10:00 PM – 10:30 PM).
* **Communication:** Notify Application Development Team and Database Administrators prior to and following policy enforcement.

---
