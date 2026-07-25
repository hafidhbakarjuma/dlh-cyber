# MEDDEFENSE HEALTH SYSTEMS
## Cryptographic Specification: Encryption Levels & Data Store Mapping  
**Status:** Engineering Standard & Asset Classification Report  

---

## Executive Summary
Selecting an appropriate cryptographic protection level requires balancing scope of protection, performance overhead, and key management complexity. Implementing the wrong encryption level either exposes sensitive Protected Health Information (PHI) to unauthorized physical or administrative threats or imposes performance bottlenecks that clinical staff will not tolerate. This specification defines the six standard encryption levels and maps them directly to MedDefense infrastructure assets.

---

## Part 1: Comparison of the Six Encryption Levels

| Level | Scope | Performance Impact | Key Management | Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Full-disk** | Entire physical or virtual disk | Minimal (hardware-accelerated, e.g., AES-NI) | Low (single volume key or TPM binding) | Protecting data at rest against physical theft of offline or decommissioned hardware. |
| **Partition** | One logical partition | Minimal block-level overhead | Low (single partition passphrase or keyfile) | Isolating boot/system partitions from user/data storage spaces on shared media. |
| **Volume** | Logical volume (may span disks) | Low to Moderate (depends on stripe depth and crypto algorithm) | Moderate (dm-crypt/LUKS keys managed via secure keyfiles or KMS) | Encrypting multi-disk storage pools, LVM groups, and backup repositories (e.g., NAS-01). |
| **File** | Individual files | Moderate (file system filter driver overhead per open/read/write) | Moderate to High (per-file or per-directory keys) | Protecting individual sensitive documents or shared home directories on multi-user servers. |
| **Database** | Entire database or tablespace | Moderate (database engine internal decryption overhead per query) | Moderate (TDE master keys stored in database keystore/HSM) | Securing relational database files at rest against unauthorized file-level extraction. |
| **Record** | Individual fields or records | High (application/database layer cryptographic transformations per row/column) | High (fine-grained keys or tokenization vaults per data type) | Protecting highly sensitive column data (e.g., SSNs, credit cards) from DBAs and insider threats. |

### One-Sentence Best Choice Justifications:
* **Full-disk:** Best choice when physical hardware theft protection is required without modifying operating system or application logic.
* **Partition:** Best choice when specific storage boundaries within a single drive must be isolated for compliance or multi-tenancy.
* **Volume:** Best choice when securing multi-disk storage arrays or backup volumes (like NAS-01) against unauthorized physical access.
* **File:** Best choice when granular protection of specific standalone documents is required across multi-user operating systems.
* **Database:** Best choice when protecting entire relational database files at rest from storage extraction without impacting application query logic.
* **Record:** Best choice when fine-grained column-level protection is required to shield sensitive data even from privileged database administrators.

---

## Part 2: MedDefense Encryption Level Map

### 1. Patient records in PostgreSQL (`ehr-db-01`)
* **Recommended Level:** **Database (Transparent Data Encryption - TDE) + Record-level for high-sensitivity fields**
* **Justification:** TDE secures the entire database filespace at rest against physical or storage-level extraction, while record-level encryption (or column-level hashing) shields highly sensitive identifiers (such as Social Security Numbers) from rogue database administrators or internal attackers with elevated database access.

### 2. Backup data on NAS-01
* **Recommended Level:** **Volume-level (LUKS / dm-crypt)**
* **Justification:** Volume-level encryption fully protects the large storage pool and backup container files at rest, ensuring that physical theft of the NAS hardware or unauthorized network access yields only unreadable ciphertext while supporting high-throughput nightly backup ingestion.

### 3. Financial records in MySQL (`billing-srv-01`)
* **Recommended Level:** **Database (TDE)**
* **Justification:** Encrypting the billing tablespaces ensures that financial transactions and billing archives comply with strict regulatory standards (PCI-DSS/HIPAA) at rest, preventing disk extraction attacks while keeping application query performance smooth.

### 4. Medical images on PACS (`pacs-srv-01`)
* **Recommended Level:** **Full-disk or Volume-level**
* **Justification:** Medical imaging files (DICOM) are massive in volume; file-level or record-level encryption would introduce intolerable latency during real-time clinician retrieval. Volume or disk-level encryption secures the entire storage subsystem with hardware acceleration, maintaining rapid PACS streaming performance.

### 5. Email data in O365
* **Recommended Level:** **File-level / Application-level Cloud Encryption (Microsoft Purview / S/MIME)**
* **Justification:** Cloud-native collaboration tools require end-to-end and item-level protection so that emails containing patient medical disclosures remain encrypted while traversing cloud infrastructure and external mail gateways.

### 6. Employee laptops
* **Recommended Level:** **Full-disk (BitLocker / FileVault)**
* **Justification:** Laptops are highly susceptible to loss or physical theft outside the secure hospital perimeter; full-disk encryption ensures complete protection of cached credentials and local patient data without impacting workstation performance.

### 7. BD Alaris pump firmware/configuration
* **Recommended Level:** **File-level / Firmware signing and container encryption**
* **Justification:** Medical IoT device firmware containers must be cryptographically verified and decrypted only within secure device memory during boot to prevent malicious firmware flashing or physical extraction of embedded network credentials.

---
