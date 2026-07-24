# MEDDEFENSE HEALTH SYSTEMS
## Cryptographic Audit & Data Protection Map
**Prepared by:** Security & Cryptographic Engineering Team  
**Reviewed by:** Sarah Park (IT Director), James Chen (CISO)  
**Date:** Week 5, Day 1  
**Status:** Official Data Protection Baseline & Gap Analysis  

---

## Executive Summary

As part of Phase 1 of the MedDefense Security Strategy roadmap, this document establishes a comprehensive **Data Protection Map** across all core data categories and operating states (At Rest, In Transit, In Use). This audit consolidates findings from vulnerability assessments (1x02), forensic investigations (1x00), and direct system inspections by IT and Security. 

The findings confirm Sarah Park's assessment: **MedDefense encrypts almost nothing that it directly controls.** While cloud-hosted services (O365 email at rest/transit) and modern perimeter tunnels (IPSec AES-256) maintain adequate baselines, internal medical data, patient records, billing databases, backups, and authentication protocols suffer from systemic cryptographic gaps, legacy fallback modes, and complete lack of protection at rest.

---

## Data Protection Matrix (7 Categories × 3 States)

| Data Category | At Rest | In Transit | In Use |
| :--- | :--- | :--- | :--- |
| **1. Patient Medical Records** *(EHR PostgreSQL)* | **Protection:** None (ext4 plaintext)<br>**Evidence:** Audit notes / 1x02<br>**Status:** 🔴 Absent | **Protection:** Partial (`hostssl` + `hostnossl`)<br>**Evidence:** `pg_hba.conf` inspection<br>**Status:** 🟡 Weak | **Protection:** None (plaintext in memory)<br>**Evidence:** Workstation GP settings<br>**Status:** 🔴 Absent |
| **2. Financial & Billing Data** *(MySQL billing-srv-01)* | **Protection:** None (ext4 plaintext)<br>**Evidence:** 1x00 Forensic Incident Report<br>**Status:** 🔴 Absent | **Protection:** Weak (plaintext MySQL protocol)<br>**Evidence:** 0.0.0.0 binding review<br>**Status:** 🔴 Absent | **Protection:** None (plaintext memory processing)<br>**Evidence:** Application review<br>**Status:** 🔴 Absent |
| **3. Medical Images** *(PACS pacs-srv-01)* | **Protection:** None (local disk plaintext)<br>**Evidence:** PACS storage analysis<br>**Status:** 🔴 Absent | **Protection:** None (cleartext DICOM ports 4242/11112)<br>**Evidence:** Network traffic analysis<br>**Status:** 🔴 Absent | **Protection:** None (local viewer unencrypted RAM)<br>**Evidence:** Windows XP workstation review<br>**Status:** 🔴 Absent |
| **4. Credentials & Authentication** *(Active Directory)* | **Protection:** NTHash (MD4) default<br>**Evidence:** AD config inspection<br>**Status:** 🔴 Absent | **Protection:** None (LDAP signing not required)<br>**Evidence:** Vulnerability Scan Finding 007<br>**Status:** 🔴 Absent | **Protection:** Kerberos RC4/DES enabled<br>**Evidence:** Vulnerability Scan Finding 018<br>**Status:** 🔴 Absent |
| **5. Backup Data** *(NAS-01)* | **Protection:** None (RAID-5 unencrypted)<br>**Evidence:** NAS configuration review<br>**Status:** 🔴 Absent | **Protection:** None (plaintext replication)<br>**Evidence:** Network architecture review<br>**Status:** 🔴 Absent | **Protection:** None (unencrypted staging)<br>**Evidence:** Backup process audit<br>**Status:** 🔴 Absent |
| **6. Email** *(Microsoft O365)* | **Protection:** BitLocker + Per-mailbox keys<br>**Evidence:** Microsoft Cloud specs<br>**Status:** 🟢 Adequate | **Protection:** TLS 1.2 for Exchange Online<br>**Evidence:** Microsoft enforced standard<br>**Status:** 🟢 Adequate | **Protection:** None (S/MIME / OME unused, PHI emailed plaintext)<br>**Evidence:** Physician workflow audit<br>**Status:** 🔴 Absent |
| **7. VPN Traffic** *(Site-to-Site Tunnels)* | **Protection:** N/A (Transit state)<br>**Evidence:** Tunnel architecture<br>**Status:** N/A | **Protection:** IPSec (AES-256, SHA-256, IKEv2)<br>**Evidence:** FortiGate configuration audit<br>**Status:** 🟢 Adequate | **Protection:** N/A<br>**Evidence:** Network architecture<br>**Status:** N/A |

*(Note: VPN traffic and certain static states are evaluated across applicable vectors; total matrix assessment comprises 21 core cell evaluations).*

---

## Detailed Category Analysis & Evidence

### 1. Patient Medical Records (EHR System: `ehr-srv-01` / `ehr-db-01`)
*   **At Rest (Absent):** PostgreSQL 14 data directory resides on an unencrypted `ext4` filesystem. Physical access to the server or drive extraction yields full plaintext patient files.
*   **In Transit (Weak):** While PostgreSQL is configured with `ssl=on`, the `pg_hba.conf` file contains `hostnossl` lines alongside `hostssl` for the `10.10.0.0/16` subnet. This permits unencrypted fallback connections, preventing verification of transit encryption integrity.
*   **In Use (Absent):** Patient records are decrypted entirely in memory on `ehr-srv-01` and displayed across nurse station terminals. Workstation Group Policy lacks screen-lock timeouts ("Never"), exposing active records to visual and physical tampering.

### 2. Financial & Billing Data (`billing-srv-01`)
*   **At Rest (Absent):** MySQL database files sit unencrypted on standard `ext4` storage. During the recent crypto-miner incident (1x00), incident responders verified that database files could be read directly from the filesystem without authentication credentials.
*   **In Transit (Absent):** MySQL binds to `0.0.0.0` without forcing SSL, transmitting sensitive financial records, SSNs, and credit card suffixes over the flat internal network in cleartext.
*   **In Use (Absent):** Billing records are processed in clear memory buffers without runtime protection or hardware-backed isolation.

### 3. Medical Images (`pacs-srv-01`)
*   **At Rest (Absent):** PACS stores DICOM files (MRI, CT, X-ray) on local disk without filesystem or volume encryption. DICOM headers embed patient identifiers (name, DOB, MRN) in plaintext readable by standard text editors.
*   **In Transit (Absent):** Traffic between Windows XP MRI workstations, radiology terminals, and PACS uses raw DICOM over ports 4242 and 11112. Although DICOM TLS (PS3.15) exists, it is completely unconfigured.
*   **In Use (Absent):** Workstations render medical imagery and patient metadata in unencrypted local memory.

### 4. Credentials & Authentication (`ad-dc-01` / `ad-dc-02`)
*   **At Rest (Absent/Weak):** Active Directory relies on NTHash (MD4) for NTLM backward compatibility, vulnerable to rapid offline cracking if database NTDS.dit files are compromised.
*   **In Transit (Absent):** LDAP signing is not enforced (Finding 007), allowing directory queries and authentication binds to occur without cryptographic integrity protection.
*   **In Use (Weak):** Kerberos supports legacy encryption types DES and RC4 (Finding 018), enabling Kerberoasting attacks and trivial decryption of service tickets.

### 5. Backup Data (`NAS-01`)
*   **At Rest (Absent):** Synology NAS stores all backups (including PostgreSQL and MySQL plaintext dumps) on an unencrypted RAID-5 array. The DSM management interface is exposed across the flat network (Finding 015).
*   **In Transit (Absent):** Backups are replicated or transferred without transport-layer encryption over internal segments.
*   **In Use (Absent):** Staging areas on the NAS process backup archives unencrypted.

### 6. Email (`O365`)
*   **At Rest (Adequate):** Microsoft manages BitLocker disk encryption and per-mailbox encryption at rest within its datacenters.
*   **In Transit (Adequate):** Exchange Online enforces TLS 1.2+ for all transit connections.
*   **In Use (Absent):** S/MIME and Office Message Encryption (OME) are disabled. Physicians routinely transmit Protected Health Information (PHI) via unencrypted email bodies despite policy prohibitions.

### 7. VPN Traffic (Site-to-Site Tunnels)
*   **In Transit (Adequate):** Central-to-Westside and Central-to-HQ tunnels utilize IPSec (AES-256, SHA-256, IKEv2, DH Group 14) via FortiGate firewalls. 
*   *Caveat:* The Westside endpoint terminates on a consumer-grade Netgear Nighthawk router with unknown firmware update history, creating a potential hardware/implementation risk.

---

## Gap Summary & Quantitative Coverage Analysis

To quantify MedDefense's current cryptographic posture, we evaluate the 21 primary matrix cells across data categories and states:

*   **Adequate Protection:** **3 cells** (O365 At Rest, O365 In Transit, VPN In Transit)
*   **Weak Protection:** **2 cells** (EHR In Transit, AD In Use/Credentials)
*   **Absent Protection:** **16 cells** (Unencrypted at rest, cleartext DICOM, unencrypted backups, unencrypted MySQL, unencrypted LDAP, etc.)

### Overall Cryptographic Coverage Metric:
$$	ext{Crypto Coverage Score} = rac{	ext{Adequate Cells}}{	ext{Total Cells}} = rac{3}{21}  pprox \mathbf{14.3\%}$$

### Key Takeaways for Phase 1 Remediation:
1. **Critical Infrastructure Vulnerability:** 76% of data states suffer from complete absence of cryptographic controls.
2. **Immediate Priorities:** 
   - Enforce database encryption at rest for PostgreSQL (`ehr-db-01`) and MySQL (`billing-srv-01`).
   - Eliminate weak TLS/SSL fallbacks (`hostnossl`) and upgrade Patient Portal TLS from TLS 1.0/1.2 to TLS 1.3 before the Let's Encrypt certificate expires in 18 days.
   - Disable legacy Kerberos ciphers (DES/RC4) and enforce LDAP signing on Active Directory.
   - Implement secure, zero-knowledge encryption for NAS backup storage (`NAS-01`).

---
