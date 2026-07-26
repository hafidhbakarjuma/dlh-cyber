# The Board Briefing & Emergency Response

### Overview
This repository contains the final capstone project for MedDefense Health Systems. It synthesizes five weeks of security architecture, vulnerability assessment, risk quantification, control strategy, and cryptographic engineering into a single Board-ready package, coupled with an immediate emergency response plan for the active **"Crimson Tide"** ransomware campaign (CISA Advisory AA26-077A).

---

## Task 0: MedDefense Impact Assessment (Crimson Tide / CISA AA26-077A)

### Phase 1 -- Initial Access
* **Advisory Description:** Exploitation of CVE-2023-27997 (FortiOS SSL-VPN pre-auth heap buffer overflow) achieving remote code execution on the firewall.
* **MedDefense Mapping:**
  * **Target System:** MedDefense Perimeter Firewall (`FortiGate 100F`, WAN interface).
  * **Vulnerability Reference:** `CVE-2023-27997` (CVSS 9.2 Critical). Running FortiOS `7.0.9`.
  * **Gap Reference:** `GAP-NET-01` (Unpatched perimeter appliances / expired support contract).
  * **Crypto Weakness:** SSL-VPN session token handling / weak cipher configurations.
  * **Current Protection:** Stateful packet inspection, but no active exploit prevention or up-to-date IPS signatures for this specific zero-day vector without firmware patch `7.0.14`.
  * **Verdict:** `EXPOSED`

### Phase 2 -- Internal Reconnaissance
* **Advisory Description:** Capture VPN credentials from memory and dump routing tables to map internal subnets from the compromised gateway.
* **MedDefense Mapping:**
  * **Target System:** Management plane of `FortiGate 100F` and internal routing tables.
  * **Vulnerability Reference:** Local credential caching in FortiOS memory (`OSINT-02` / internal admin session state).
  * **Gap Reference:** `GAP-IAM-03` (Lack of hardware token MFA for administrative access).
  * **Crypto Weakness:** Plaintext credential storage/passing in administrative sessions.
  * **Current Protection:** Basic password authentication with no anomalous session monitoring.
  * **Verdict:** `EXPOSED`

### Phase 3 -- Lateral Movement
* **Advisory Description:** Use captured credentials to move via RDP, SSH, WMI; exploit flat networks and Kerberoasting (RC4 tickets).
* **MedDefense Mapping:**
  * **Target System:** Active Directory Domain Controllers (`DC-01`, `DC-02`) and internal server VLANs.
  * **Vulnerability Reference:** `VULN-AD-01` (Kerberos encryption downgrade supporting RC4-HMAC) and `VULN-NET-02` (Flat internal network architecture).
  * **Gap Reference:** `GAP-NET-02` (Absence of internal micro-segmentation) and `GAP-IAM-01` (Weak password policies).
  * **Crypto Weakness:** RC4 encryption in Active Directory Kerberos ticket exchange.
  * **Current Protection:** None (flat network permits arbitrary east-west traffic across all zones).
  * **Verdict:** `EXPOSED`

### Phase 4 -- Data Exfiltration
* **Advisory Description:** Exfiltrate EMR databases, financial records, and employee PII (15-65 GB) using Rclone to cloud storage without database credentials.
* **MedDefense Mapping:**
  * **Target System:** Central Electronic Medical Record database server (`DB-EMR-01`).
  * **Vulnerability Reference:** `VULN-DB-01` (Unencrypted databases at rest on local filesystem).
  * **Gap Reference:** `GAP-CRYPTO-01` (Absence of Transparent Data Encryption / file-level encryption).
  * **Crypto Weakness:** Data stored in plaintext on underlying storage volumes (`AES-0` / none).
  * **Current Protection:** Perimeter egress filtering only (unmonitored HTTPS/Rclone tunneling).
  * **Verdict:** `EXPOSED`

### Phase 5 -- Backup Destruction
* **Advisory Description:** Target backup NAS/SAN devices on the same flat network, delete Volume Shadow Copies (`vssadmin`), and corrupt backup catalogs.
* **MedDefense Mapping:**
  * **Target System:** Network Attached Storage backup repository (`NAS-01`).
  * **Vulnerability Description:** `VULN-BKUP-01` (Network-accessible backup shares with write permissions from domain user accounts).
  * **Gap Reference:** `GAP-RES-01` (Online backups lacking immutability and air-gapping).
  * **Crypto Weakness:** Unencrypted backup files allowing attackers to verify contents before wiping.
  * **Current Protection:** Daily local backups residing on the same subnet as production systems.
  * **Verdict:** `EXPOSED`

### Phase 6 -- Ransomware Deployment
* **Advisory Description:** Push BlackSuit ransomware payload via Group Policy Objects (GPO) across Windows infrastructure and targeted SSH scripts on Linux.
* **MedDefense Mapping:**
  * **Target System:** All domain-joined Windows workstations, servers, and Linux research nodes.
  * **Vulnerability Reference:** `VULN-EDR-01` (Incomplete EMR/EDR coverage across legacy clinical workstations).
  * **Gap Reference:** `GAP-END-01` (Outdated endpoint protection agents).
  * **Crypto Weakness:** N/A (Payload utilizes strong AES-256-CBC with RSA-2048 encryption).
  * **Current Protection:** Legacy antivirus signatures unable to detect modified BlackSuit variants.
  * **Verdict:** `EXPOSED`

### Phase 7 -- Extortion
* **Advisory Description:** Dual extortion via Tor-based leak sites, direct emails to executive leadership (CEO/CFO), and phone calls.
* **MedDefense Mapping:**
  * **Target System:** Executive communications channel and public reputation.
  * **Vulnerability Reference:** `OSINT-EX-01` (Publicly exposed executive email addresses and direct phone lines in corporate directory).
  * **Gap Reference:** `GAP-EXEC-01` (Absence of executive communication protocols for active extortion events).
  * **Crypto Weakness:** None.
  * **Current Protection:** Standard corporate email spam/phishing filters.
  * **Verdict:** `EXPOSED`

---

## Summary Metrics & Immediate Action

* **Overall Exposure Score:** `7/7 EXPOSED`
* **Critical Finding:** MedDefense must immediately disconnect SSL-VPN access on the FortiGate 100F and isolate the backup repository (`NAS-01`) within the next 4 hours to prevent total organizational compromise.
