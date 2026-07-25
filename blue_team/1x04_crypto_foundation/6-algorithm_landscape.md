# MEDDEFENSE HEALTH SYSTEMS
## Cryptographic Lab: The Algorithm Landscape & Crypto Gap Analysis
**Status:** Definitive Reference Table & Compliance Audit Report  

---

## Executive Summary

To successfully navigate CompTIA Security+ Domain 1 and secure MedDefense’s healthcare infrastructure against real-world threats, engineering teams must maintain a strict, unambiguous inventory of cryptographic primitives. This reference document compiles every mandatory algorithm across symmetric ciphers, asymmetric engines, hash functions, and key derivation functions (KDFs). It pairs each with its technical parameters, current standing, and operational placement within MedDefense, culminating in a targeted Crypto Gap Analysis to remediate legacy vulnerabilities identified during initial infrastructure assessments.

---

## Part 1: The Definitive Algorithmic Reference Table

| Algorithm | Type | Key / Output Size | Primary Use Case | Status | Why Deprecated / Broken | MedDefense Usage |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **AES-128** | Symmetric | 128-bit key | Bulk data encryption for databases and file systems | Current | N/A | Standard baseline for non-critical internal file storage. |
| **AES-192** | Symmetric | 192-bit key | High-security bulk data and volume encryption | Current | N/A | Departmental data storage and internal asset encryption. |
| **AES-256** | Symmetric | 256-bit key | Maximum-security data-at-rest and transit protection | Current | N/A | Primary standard for patient database encryption and backups (`db-srv-01`). |
| **DES** | Symmetric | 56-bit key | Legacy block cipher | Broken | Exhaustive key search is trivial on modern hardware (broken in 1998). | **Prohibited:** Completely removed from all production networks. |
| **3DES** | Symmetric | 112 or 168-bit key | Legacy transition cipher (Triple DES) | Deprecated | Vulnerable to Sweet32 collision attacks due to small 64-bit block size; phased out by NIST. | **Prohibited:** Phased out across all legacy billing and EHR integrations. |
| **ChaCha20-Poly1305** | Symmetric | 256-bit key | High-performance authenticated stream encryption | Current | N/A | Utilized in modern TLS stacks for high-speed mobile client access. |
| **RC4** | Symmetric | 40 to 2048-bit key | Stream cipher for legacy web/wireless traffic | Broken | Flawed keystream generation algorithms expose biased outputs vulnerable to plaintext recovery. | **Prohibited:** Purged from all web servers and wireless configurations. |
| **Blowfish** | Symmetric | 32 to 448-bit key | Symmetric block cipher (predecessor to modern KDFs) | Deprecated | Small 64-bit block size makes it susceptible to birthday attacks on large data volumes. | **Prohibited:** Replaced entirely by AES and modern KDFs. |
| **RSA-2048** | Asymmetric | 2048-bit modulus | Digital signatures and TLS certificate exchange | Current | N/A | Baseline standard for external web certificates and legacy signatures. |
| **RSA-4096** | Asymmetric | 4096-bit modulus | Long-term high-security digital signatures | Current | N/A | Root Certificate Authority (CA) self-signed certificates. |
| **ECC P-256** | Asymmetric | 256-bit curve | Compact asymmetric key exchange & signing | Current | N/A | Standard for modern TLS handshakes and medical IoT endpoints. |
| **ECC P-384** | Asymmetric | 384-bit curve | High-security asymmetric operations | Current | N/A | Reserved for high-assurance internal communications and secure enclaves. |
| **Diffie-Hellman (DH)** | Asymmetric | 2048+ bit modulus | Over-the-network key exchange protocol | Current | N/A (when properly parameterized) | Legacy site-to-site VPN tunnels (migrating to ECDHE). |
| **ECDHE** | Asymmetric | Curve-dependent | Elliptic Curve Diffie-Hellman Ephemeral key exchange | Current | N/A | Default key exchange protocol for all modern HTTPS and TLS connections. |
| **MD5** | Hash | 128-bit output | Legacy checksums and message digests | Broken | Susceptible to rapid collision attacks via the Birthday Paradox. | **Prohibited:** Only found in legacy Active Directory NTHash artifacts. |
| **SHA-1** | Hash | 160-bit output | Legacy digital signatures and code verification | Broken | Practical collision attacks demonstrated (SHAttered); deprecated by NIST. | **Prohibited:** Blocked across code-signing and software repositories. |
| **SHA-256** | Hash | 256-bit output | Secure file integrity, certificates, and digital signatures | Current | N/A | Standard hashing algorithm for file integrity checks and signature validation. |
| **SHA-512** | Hash | 512-bit output | High-assurance cryptographic digest generation | Current | N/A | Used in high-security logging and cryptographic audit trails. |
| **SHA-3** | Hash | 224 to 512-bit output | Next-gen cryptographic hash (Keccak sponge structure) | Current | N/A | Integrated as an alternative redundancy standard for compliance frameworks. |
| **PBKDF2** | KDF | Tunable iterations | Password-based key stretching and derivation | Current | N/A (if iteration count is high) | Legacy web application login hashing and key generation. |
| **bcrypt** | KDF | Tunable cost factor | Password hashing based on Blowfish | Current | N/A | Recommended standard for web application user password storage. |
| **Argon2** | KDF | Tunable memory/time | Memory-hard password hashing (PHC Winner) | Current | N/A | Recommended primary standard for new custom application password databases. |
| **scrypt** | KDF | Tunable memory/CPU | Memory-hard key derivation function | Current | N/A | Utilized in specialized backup encryption key derivation tools. |

---

## Part 2: MedDefense Crypto Gap Analysis

A rigorous comparison between MedDefense's current infrastructure state (informed by baseline architectural diagrams and vulnerability findings from earlier assessments) and cryptographic best practices reveals several critical security gaps. 

### Identified Gaps & Remediation Recommendations

1. **Active Directory Password Storage (NTHash / MD4)**
   * **Current State:** Active Directory defaults to storing passwords as NTHashes (unsalted MD4) to support legacy NTLM authentication.
   * **The Risk:** Unsalted hashes extracted via `NTDS.dit` dumping can be cracked offline in minutes using modern GPU clusters.
   * **Recommended Replacement:** Enforce strict password length (minimum 14+ characters) and complexity policies as a compensating control, implement Group Managed Service Accounts (gMSA), and accelerate migration toward Azure AD / Entra ID cloud-hybrid authentication utilizing salted modern hashing.

2. **Legacy Kerberos Encryption (RC4 / MD5)**
   * **Current State:** Finding 018 revealed that legacy service accounts and older domain controllers still negotiate RC4-HMAC for Kerberos tickets.
   * **The Risk:** RC4 relies on broken stream cipher mathematics and internal MD5 usage, allowing ticket-granting ticket (TGT) forgery and rapid offline cracking.
   * **Recommended Replacement:** Enforce "Kerberos encryption types" Group Policy settings to disable RC4 globally, mandating **AES-128 and AES-256 encryption** for all Kerberos ticket exchanges.

3. **Legacy VPN Tunnel Key Exchange (Static Diffie-Hellman without Certificates)**
   * **Current State:** Site-to-site VPN tunnels connecting Central, Westside, and HQ rely on static or unauthenticated Diffie-Hellman parameters.
   * **The Risk:** Vulnerable to active Man-in-the-Middle (MITM) attacks where an intermediary intercepts and negotiates separate shared secrets.
   * **Recommended Replacement:** Upgrade all IPsec and VPN tunnel configurations to utilize **Authenticated Diffie-Hellman via PKI digital certificates (ECDHE with RSA/ECC signatures)** to enforce strict endpoint verification.

4. **Custom Patient Portal Password Hashing (Unsalted PBKDF2 / Low-Iteration MD5)**
   * **Current State:** Legacy modules in the patient portal web application utilize historical MD5 or low-iteration hashing for secondary user tables.
   * **The Risk:** Highly vulnerable to precomputed rainbow table lookups and rapid brute-force dictionary attacks.
   * **Recommended Replacement:** Refactor application backend code to hash all user passwords exclusively using **Argon2id** with a unique per-user salt and high memory/time cost parameters.

---
