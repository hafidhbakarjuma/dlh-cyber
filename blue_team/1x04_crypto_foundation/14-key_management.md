# MEDDEFENSE HEALTH SYSTEMS
## Cryptographic Specification: Hardware Security & Enterprise Key Management 
**Status:** Architecture Specification & Risk Evaluation Report  

---

## Executive Summary
Encrypting MedDefense's patient records, backup repositories, and web services protects data at rest and in transit, but introduces a critical vulnerability: cryptographic key exposure. Storing keys on the same target servers or configuration files invalidates the security boundary. This specification compares hardware security technologies, designs a strict Key Management Plan across MedDefense's assets, and evaluates the financial and operational justification of deploying a Hardware Security Module (HSM).

---

## Part 1: Hardware Security Technologies Comparison

| Technology | What It Is | What It Protects | Typical Cost | Typical Deployment |
| :--- | :--- | :--- | :--- | :--- |
| **TPM** (Trusted Platform Module) | A dedicated cryptoprocessor embedded on the motherboard of a physical computer or server. | Root of trust, system integrity measurements, platform boot status, and local disk encryption keys (e.g., BitLocker). | Low ($10–$50 per chip, typically integrated into hardware). | Single-tenant physical endpoints, employee laptops, and on-premises server motherboards. |
| **HSM** (Hardware Security Module) | A hardened, tamper-evident physical appliance or certified cloud cluster dedicated to key generation and cryptographic operations. | High-value root keys, Certificate Authority (CA) private keys, database master encryption keys. | High ($5,000–$50,000+ for physical appliances; $1–$2/key/month or ~$1,000+/month for cloud HSM-as-a-Service). | Centralized enterprise datacenters, high-security cloud database architectures, and financial systems. |
| **Secure Enclave** | An isolated, hardware-enforced secure execution environment within the main CPU (e.g., Intel SGX, ARM TrustZone). | Code execution integrity and sensitive data/keys in memory from malicious host OS or kernel-level malware. | Low to Moderate (typically built into enterprise CPU licensing or hardware tiers). | Cloud workloads, containerized microservices, mobile devices, and confidential computing nodes. |
| **KMS** (Software KMS) | A software-based key management system running within standard operating system or application environments. | Application secrets, database connection strings, and standard encryption keys. | Low (software licensing or open-source solutions like HashiCorp Vault / Cloud Key Vaults). | Virtualized servers, microservices, and general cloud-native applications requiring logical separation. |

---

## Part 2: MedDefense Key Management Design

MedDefense maintains active encryption layers across the patient database (`ehr-db-01`), backup storage (`NAS-01`), portal TLS (`portal.sec`), and VPN tunnels. The lifecycle plan for each key set is structured as follows:

### 1. Key Inventory & Storage Location
* **Database Key (`ehr-db-01` TDE Master Key):** Stored inside a centralized enterprise Key Management Service (AWS KMS / Azure Key Vault or internal Vault cluster), isolated from the database server disks.
* **Backup Storage Key (`NAS-01` LUKS Master Key):** Managed via an offline wrapped keyfile loaded manually or via secure out-of-band injection during system boot; never stored persistently on `NAS-01`.
* **Portal TLS Private Key (`portal.sec`):** Stored in secure web server memory and protected filesystem storage (`chmod 600`) under `/etc/ssl/private/`, managed via ACME/CA automation.
* **VPN Tunnel Pre-Shared Keys / Certificates:** Stored securely within the firewall/VPN gateway hardware configuration profile (encrypted config store).

### 2. Role-Based Access Control (RBAC) Governance
* **Database Key:** Accessible exclusively by the **Lead Database Administrator (DBA)** and **Chief Information Security Officer (CISO)** for emergency rotation.
* **Backup Storage Key:** Managed by the **Infrastructure Lead / Storage Administrator** under dual-control authorization.
* **Portal TLS Key:** Managed by the **Security Engineering Team** via automated certificate deployment pipelines.
* **VPN Keys:** Managed by the **Network Security Administrator**.

### 3. Key Rotation Frequency & Process
* **Database TDE Keys:** Rotated **annually** (or immediately following personnel changes) via automated KMS re-keying operations where new data keys wrap existing records without downtime.
* **Backup Volume Keys:** Rotated **annually** during scheduled disaster recovery drills by re-encrypting backup blocks with a newly generated LUKS key slot.
* **Portal TLS Certificates/Keys:** Rotated **every 90 days** using automated ACME/Let's Encrypt renewal protocols.
* **VPN Keys/Credentials:** Rotated **semi-annually** or immediately upon employee offboarding.

### 4. Key Compromise Procedure (Revocation & Replacement)
1. **Immediate Revocation:** Revoke the compromised key or certificate in the KMS/CA console instantly.
2. **Isolation:** Isolate the affected asset (`ehr-db-01` or `NAS-01`) from the internal network to prevent lateral adversary access.
3. **Emergency Re-keying:** Generate a new cryptographic key hierarchy, re-encrypt underlying data storage blocks, and invalidate all active user session tokens.
4. **Audit & Reporting:** Execute forensic artifact collection to determine scope of compromise and fulfill regulatory breach notification requirements.

### 5. Key Loss Recovery Procedure (Escrow)
* **Master Escrow:** If a master encryption key is lost, data is permanently unrecoverable unless an escrow backup exists. MedDefense enforces an **M-of-N split-knowledge threshold scheme** (Shamir's Secret Sharing) where emergency recovery shards are held in offline hardware tokens stored across separate physical bank safety deposit boxes.

---

## Part 3: The HSM Investment Decision

### 1. Cost Estimation
* Utilizing cloud-based HSM-as-a-Service options (such as AWS CloudHSM or Azure Dedicated HSM), baseline pricing runs approximately **$1.20 to $1.45 per hour** per instance (translating to roughly **$1,000 per month** continuous baseline operation), plus marginal transaction fees. For MedDefense's core database tier, managing primary keys via a cloud HSM service equates to roughly $12,000 annually.

### 2. Risk Evaluation & Comparison
* Referencing the MedDefense Risk Register (`1x03`), unauthorized database extraction or ransomware attacks targeting plaintext PHI repositories carry a catastrophic impact rating (potential regulatory fines exceeding HIPAA thresholds, reputational damage, and loss of patient trust). The annualized loss expectancy (ALE) of an unmitigated database breach exceeds hundreds of thousands of dollars.

### 3. Final Recommendation: Is the Investment Justified?
* **For Current Phase (Phase 1):** A dedicated hardware HSM appliance or high-cost cloud HSM cluster **is NOT immediately justified** given MedDefense's current SME budget constraints. 
* **Alternative Solution:** MedDefense will instead deploy a **Cloud Key Management Service (KMS) with software-backed hardware isolation (FIPS 140-2 Level 2/3 validated cloud key vaults)** at a fraction of the cost (~$10–$50/month). This achieves robust cryptographic isolation and access controls without incurring the $1,000+/month overhead of dedicated single-tenant HSM appliances, deferring physical HSM acquisition until enterprise scaling reaches Phase 3.

---
