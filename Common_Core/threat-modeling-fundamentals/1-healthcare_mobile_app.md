# Healthcare Mobile App Threat Model

This healthcare mobile app environment involves highly sensitive Protected Health Information (PHI), making security and privacy the top architectural priorities.

Here is the threat analysis and security prioritization.

## 1. Critical Asset Analysis

The most critical asset is the Patient Medical Record (PHI).

### Applying the CIA Triad

**Confidentiality:**
If compromised (e.g., unauthorized data leak), patients lose privacy, and the organization faces massive legal/regulatory penalties (HIPAA).

**Integrity:**
If altered (e.g., incorrect medication dosages or diagnosis records are injected), the result can be direct physical harm or death to the patient.

**Availability:**
If the records are inaccessible during an emergency (e.g., ransomware), the healthcare provider cannot deliver necessary care, potentially leading to critical health outcomes.

## 2. STRIDE Analysis: "Message Healthcare Providers" Feature

| STRIDE Category        | Threat Description                                                                                                |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Spoofing               | An attacker masquerades as a healthcare provider to solicit sensitive info from a patient.                        |
| Tampering              | A man-in-the-middle (MITM) attacker modifies the content of a message (e.g., changing medication instructions).   |
| Repudiation            | A user claims they never sent a specific message or order, leading to a lack of accountability in medical advice. |
| Information Disclosure | Unencrypted messages are intercepted by unauthorized third parties during transit.                                |
| Elevation of Privilege | An attacker gains access to a provider’s portal and sends messages to patients as an "authorized" professional.   |

## 3. Prioritized Security Controls

When protecting PHI, we focus on Defense in Depth.

Here are the five prioritized controls:

**Identity & Access Management (MFA):**
Highest priority. Standard passwords are insufficient for healthcare. Multi-Factor Authentication ensures that even if credentials are stolen, the patient account remains secure.

**End-to-End Encryption (Encryption in Transit/At Rest):**
Data must be unreadable to anyone without the decryption key. This ensures that even if a database is breached or a network is intercepted, the PHI remains protected.

**Role-Based Access Control (RBAC):**
Ensures "Principle of Least Privilege." Only authorized staff can view specific parts of a record, limiting the "blast radius" of an internal compromise.

**Immutable Audit Logging:**
Every time a record is accessed, edited, or messaged, an unchangeable log entry must be created. This is vital for accountability, forensic investigation, and HIPAA compliance.

**Data Masking and Anonymization:**
For development and analytics, PII/PHI should be masked. This reduces the risk of accidental exposure during internal system processes.

## Summary of Trust Boundaries

In this architecture, your primary trust boundaries are:

**The Client Boundary:**
    Between the mobile device (untrusted) and the REST API.

**The Integration Boundary:**
    Between your API and the external Hospital Systems (legacy systems often lack modern security).

**The Cloud Boundary:**
    Between your application layer and the managed Cloud Database.
