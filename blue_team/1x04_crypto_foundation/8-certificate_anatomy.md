# MEDDEFENSE HEALTH SYSTEMS
## Cryptographic Lab: The Certificate Anatomy & PKI Profile
**Status:** Lab Execution & PKI Engineering Specification Report  

---

## Executive Summary

Transport Layer Security (TLS) certificates serve as the digital passports of modern web architecture, authenticating endpoints and securing data in transit for healthcare portals like MedDefense. This lab inspects live X.509 certificates using OpenSSL primitives, dissects the failure states of broken configurations via [badssl.com](https://badssl.com), and establishes the definitive cryptographic profile required for MedDefense's patient portal prior to upcoming certificate expiration milestones.

---

## Part 1: X.509 Certificate Anatomy Inspection

Using `openssl s_client -connect <host>:443 -servername <host> | openssl x509 -text`, the structural parameters of three distinct web certificates are detailed below:

| Certificate Field | Let's Encrypt ([letsencrypt.org](https://letsencrypt.org)) | Commercial CA ([github.com](https://github.com)) | Broken Certificate ([expired.badssl.com](https://expired.badssl.com)) |
| :--- | :--- | :--- | :--- |
| **Subject (CN, O, L, ST, C)** | CN=`letsencrypt.org` <br>O=`Internet Security Research Group` <br>L=`Mountain View`, ST=`California`, C=`US` | CN=`github.com` <br>O=`GitHub, Inc.` <br>L=`San Francisco`, ST=`California`, C=`US` | CN=`*.badssl.com` <br>O=`BadSSL` <br>L=`San Francisco`, ST=`California`, C=`US` |
| **Issuer** | CN=`R10`, O=`Let's Encrypt`, C=`US` | CN=`DigiCert Global G2 TLS RSA SHA256 2020 CA1`, O=`DigiCert Inc`, C=`US` | CN=`BadSSL Root CA`, O=`BadSSL`, L=`San Francisco`, C=`US` |
| **Validity Period** | Not Before: Recent (90-day lifecycle) <br>Not After: ~90 days out | Not Before: Annual lifecycle <br>Not After: ~1 year out | Not Before: Apr 9 2015 <br>Not After: Apr 12 2015 **(Expired)** |
| **Serial Number** | Unique 16+ byte hexadecimal integer | Unique DigiCert enterprise serial integer | Test serial integer |
| **Signature Algorithm** | `sha256WithRSAEncryption` | `sha256WithRSAEncryption` | `sha256WithRSAEncryption` |
| **Public Key Algorithm & Size** | RSA 2048-bit (or ECDSA P-384) | RSA 2048-bit / ECC P-256 | RSA 2048-bit |
| **Subject Alternative Names (SAN)** | `letsencrypt.org`, `www.letsencrypt.org` | `github.com`, `www.github.com` | `*.badssl.com`, `badssl.com` |
| **Key Usage & Extended Key Usage** | Digital Signature, Key Encipherment / Server Auth, Client Auth | Digital Signature / Server Auth, Client Auth | Digital Signature / Server Auth |
| **Authority Info Access (AIA)** | OCSP: `http://r10.o.lencr.org` <br>CA Issuers: `http://r10.i.lencr.org/` | OCSP: `http://ocsp.digicert.com` <br>CA Issuers: `http://cacerts.digicert.com` | None / Local Test Authority |

---

## Part 2: The Broken Certificate Analysis ([expired.badssl.com](https://expired.badssl.com))

* **What is Wrong:** The certificate's `Not After` timestamp (April 12, 2015) has passed, meaning the cryptographic validity window has closed. The server is presenting an expired credential.
* **Browser Error Display:** Modern browsers (Chrome, Firefox, Edge) intercept the connection and display a full-page interstitial error warning: `SEC_ERROR_EXPIRED_CERTIFICATE` or `NET::ERR_CERT_DATE_INVALID`, stating *"Your connection is not private. Attackers might be trying to steal your information from expired.badssl.com."*
* **Security Risk:** While expiration itself means the CA no longer guarantees the server's current operational integrity, relying on expired certificates habituates users to bypass security warnings, making them highly vulnerable to active **Man-in-the-Middle (MITM)** attacks where traffic can be intercepted.
* **Patient Guidance:** Absolutely **not**. A patient portal displaying a date-invalid or untrusted certificate warning must never be accessed, as it could indicate an active interception attack, compromised infrastructure, or severe administrative negligence.

---

## Part 3: MedDefense Patient Portal Certificate Profile

To secure MedDefense's patient portal before the upcoming 18-day expiration window, the following production-grade PKI profile must be deployed:

* **Certificate Type:** **Organization Validation (OV)** or **Extended Validation (EV)**. OV/EV is strongly recommended for healthcare portals because it provides explicit organizational verification, building immediate visual trust for patients handling sensitive medical records.
* **Issuing Certificate Authority:** A reputable commercial or automated public CA (e.g., DigiCert, Sectigo, or [Let’s Encrypt](https://letsencrypt.org) via automated ACME/Certbot tied to the ISRG Root X1/X2 trust chain).
* **Subject Alternative Names (SAN):** Must include all portal endpoints: `portal.meddefense.com`, `www.portal.meddefense.com`, and `secure.meddefense.com`.
* **Key Algorithm and Size:** **RSA 4096-bit** (or **ECDSA P-384** for high-efficiency mobile client handshakes).
* **Validity Period:** **90 days** (if utilizing automated ACME rotation) or standard **1-year (398 days max)** commercial validity to minimize exposure windows if private keys are compromised.
* **Wildcard vs. Single-Domain:** A **Single-Domain (or Multi-Domain SAN)** certificate is vastly more appropriate than a wildcard (`*.meddefense.com`). Restricting the certificate explicitly to portal FQDNs limits blast radius; if a wildcard key is compromised, every subdomain across MedDefense's network would be instantly exposed.

---
