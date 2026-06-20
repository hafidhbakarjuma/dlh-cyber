# 🛡️ Project Security & Risk Analysis

This repository contains security threat models and architectural risk analyses for three core business systems:

* Healthcare Mobile App
* IoT Smart Thermostat
* Financial Trading Platform

---

## 1. Healthcare Mobile App (Patient Data)

Focuses on securing **PHI (Protected Health Information)** during patient-provider interactions.

### Key Asset

* Patient Medical Records (PHI)

### STRIDE Focus

Messaging features are vulnerable to:

* Spoofing
* Tampering
* Information Disclosure

### Core Controls

* Multi-Factor Authentication (MFA)
* End-to-End Encryption
* Immutable Audit Logging

---

## 2. IoT Smart Thermostat

Focuses on securing hardware boundaries and persistent physical access threats.

### Key Threats

* Hardware interface exposure (UART/JTAG)
* Lack of hardware-based root of trust
* Insecure default credentials

### Physical Attack Chain

Reconnaissance of PCB headers → Firmware extraction → Backdoor injection

### OTA Security Requirements

* Code Signing
* Secure Boot
* Anti-rollback protection

---

## 3. Financial Trading Platform

Focuses on high-availability, low-latency performance alongside strict regulatory compliance.

### Critical Component

* Integrity is the most important security property
* Prevents irreversible financial loss

### Automated Trading Risks

* Logic manipulation
* Unauthorized execution
* Race conditions

### Defense-in-Depth Controls

* Context-aware authentication
* Velocity limits
* Service segregation
* Immutable audit logs

---

## 4. Checkout Process Security Analysis

| STRIDE Category        | Threat Description                         | Potential Impact   | Suggested Mitigation                           |
| ---------------------- | ------------------------------------------ | ------------------ | ---------------------------------------------- |
| Tampering              | User modifies price in client-side request | Revenue loss       | Server-side validation; recalculate on backend |
| Information Disclosure | Interception of PII/payment tokens         | Data breach        | Enforce TLS 1.3 and HSTS                       |
| Elevation of Privilege | Using another user's session token         | Fraudulent charges | Strict authorization; validate session ID      |

---

## 5. Sources

* Healthcare Mobile App Threat Model conversation
* IoT Smart Thermostat Security conversation
* Financial Trading Platform Risk Analysis conversation
* STRIDE Threats for the Checkout Process
