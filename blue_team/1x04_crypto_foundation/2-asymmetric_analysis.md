## Cryptographic Lab: The Asymmetric Engine & Key Length Baseline
---

## Executive Summary

While symmetric encryption provides the heavy-lifting throughput required for bulk storage and database protection, asymmetric encryption solves the foundational key distribution dilemma. This lab explores RSA and Elliptic Curve Cryptography (ECC) key generation, exposes the strict mathematical limitations of asymmetric block size, details the hybrid encryption model used across modern internet infrastructure, and establishes the definitive compliance baseline for MedDefense's regulated healthcare environment.

---

## Part 1: RSA Key Generation and Encryption

To examine asymmetric operations, we generated an RSA-2048 key pair using standard OpenSSL commands:
```bash
openssl genrsa -out rsa_private.pem 2048
openssl rsa -in rsa_private.pem -pubout -out rsa_public.pem
```

### Encrypting and Decrypting a Small Payload
Using the public key to encrypt the patient record sample from Task 1 (`patient_record.txt`), followed by private key decryption:
```bash
# Encrypt with RSA public key (using PKCS#1 padding)
openssl pkeyutl -encrypt -in patient_record.txt -inkey rsa_public.pem -pubin -out patient_record.enc.rsa

# Decrypt with RSA private key
openssl pkeyutl -decrypt -in patient_record.enc.rsa -inkey rsa_private.pem -out patient_record.dec.rsa
```

### Attempting to Encrypt the 100MB File with RSA
When executing the same encryption command against the 100MB test payload (`testfile`), OpenSSL immediately rejects the operation:
```bash
$ openssl pkeyutl -encrypt -in testfile -inkey rsa_public.pem -pubin -out testfile.enc.rsa
Error: data greater than mod len
```

### Technical Explanation
RSA cannot encrypt data blocks larger than the key modulus minus padding overhead (e.g., max ~245 bytes for an RSA-2048 key). Because asymmetric mathematical operations involve heavy modular exponentiation over large numbers, attempting to pass a multi-megabyte file fails entirely. In real-world usage, this constraint means asymmetric algorithms are never used to encrypt bulk data, databases, or large files directly.

---

## Part 2: ECC Key Generation

To evaluate modern alternatives, we generated an Elliptic Curve Cryptography (ECC) key pair using the NIST P-256 (`prime256v1`) curve:
```bash
openssl ecparam -genkey -name prime256v1 -out ecc_private.pem
openssl ec -in ecc_private.pem -pubout -out ecc_public.pem
```

### File Size Comparison & Efficiency
*   **RSA-2048 Private Key Size:** ~1,704 bytes (PEM formatted)
*   **ECC P-256 Private Key Size:** ~227 bytes (PEM formatted)
*   **Ratio:** Approximately **7.5 : 1** storage and bandwidth reduction in favor of ECC.

### Technical Explanation
ECC achieves equivalent cryptographic strength to traditional RSA-2048 using drastically smaller parameters because its security relies on the algebraic structure of elliptic curves over finite fields rather than the difficult factorization of large composite numbers. This high strength-per-bit metric drastically reduces computational overhead, memory consumption, and energy use. For constrained medical hardware deployed at MedDefense—such as BD Alaris infusion pumps and bedside Philips patient monitors—ECC provides robust security without exhausting limited CPU and battery resources.

---

## Part 3: The Hybrid Model

Because asymmetric encryption is computationally expensive and restricted by payload size, while symmetric encryption lacks a safe mechanism for over-the-network key exchange, modern protocols implement a **hybrid model**. First, an asymmetric handshake (such as ECDHE) authenticates endpoints and securely exchanges a randomly generated, temporary symmetric session key. Once both parties possess this shared session key, asymmetric operations cease, and high-speed symmetric encryption (like AES-256-GCM) takes over for all subsequent bulk data transfer. 

This combination is superior because it marries the secure remote key distribution of asymmetric cryptography with the raw processing speed and efficiency of symmetric ciphers. Applied to MedDefense's patient portal (`web-srv-01`), when a patient connects via HTTPS, the **TLS handshake (using RSA/ECC certificates and key exchange)** establishes the trusted session and negotiates the keys, while the **bulk data encryption (AES)** handles the actual HTTP request/response payloads containing patient portal data.

---

## Part 4: The Key Length & Compliance Table

The following matrix covers the standard algorithms expected by CompTIA Security+ (Domain 1), evaluated against regulatory compliance standards (HIPAA/NIST) for MedDefense's healthcare environment:

| Algorithm | Type | Key Lengths | Equivalent Security | Status | MedDefense Usage Compliance |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **AES** | Symmetric | 128 / 192 / 256 bits | Matches key length (128 to 256-bit) | Approved | **Approved:** Standard for data at rest, databases, and backup encryption. |
| **RSA** | Asymmetric | 2048 / 4096 bits | 112 bits (2048-bit) / 128 bits (4096-bit) | Approved | **Approved:** Used for TLS certificates and legacy digital signatures. |
| **ECC** | Asymmetric | P-256 / P-384 curves | 128 bits (P-256) / 192 bits (P-384) | Approved | **Approved:** Preferred for modern TLS handshakes and IoT medical devices. |
| **DES** | Symmetric | 56 bits | 56 bits (Trivial to crack) | Deprecated | **Prohibited:** Fails all healthcare regulatory and compliance standards. |
| **3DES** | Symmetric | 112 / 168 bits | 112 bits effective security | Deprecated | **Prohibited:** Phased out by NIST (SP 800-67 Rev 2); vulnerable to Sweet32. |
| **ChaCha20-Poly1305** | Symmetric | 256 bits | 256 bits | Approved | **Approved:** High-performance stream cipher utilized in modern mobile/TLS stacks. |
| **RC4** | Symmetric | 40 to 2048 bits | < 40–80 bits (Biased output) | Deprecated | **Prohibited:** Completely broken stream cipher; prohibited across all networks. |

---
