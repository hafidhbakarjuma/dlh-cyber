# The Cryptographic Foundation

# MedDefense Health Systems - Enterprise Security Engineering Program

## Overview
This repository contains the comprehensive security engineering assessments, architectural blueprints, compliance frameworks, operational playbooks, and cryptographic laboratory reports for **MedDefense Health Systems** across Modules 0 through 24. 

This program transforms MedDefense from a vulnerable healthcare organization facing immediate emergency outages (such as expiring patient portal certificates and unencrypted databases) into a mature, HIPAA-compliant, cryptographically secure enterprise.

---

## Complete Project & Module Index

### Phase 1: Assessment, Inventory & Attack Surface (Modules 0–5)
* **`00-project_overview.md`** – Executive introduction to MedDefense Health Systems, baseline infrastructure architecture, and initial threat landscape context.
* **`01-threat_model.md`** – STRIDE threat modeling and risk profiling across core hospital systems (EHR, Patient Portal, Active Directory).
* **`02-vulnerability_assessment.md`** – Comprehensive vulnerability scan analysis detailing critical findings (expired certificates, legacy TLS, weak hashes).
* **`3-hash_analysis.md`** – The Hash Laboratory exploring the avalanche effect, hash collisions, birthday paradox ($2^{128}$ and $2^{256}$), rainbow tables, key stretching (bcrypt, PBKDF2, Argon2), and Active Directory password storage hardening.
* **`04-risk_register.md`** – Enterprise risk register quantifying likelihood, impact, and remediation prioritization for discovered vulnerabilities.
* **`05-incident_response_baseline.md`** – Initial incident response procedures and playbooks tailored for clinical and IT disruptions.

### Phase 2: Core Cryptography & Data Protection (Modules 6–12)
* **`06-symmetric_encryption_lab.md`** – Implementation and performance analysis of symmetric ciphers (AES-256) across enterprise data stores.
* **`07-asymmetric_encryption_lab.md`** – Public key cryptography workflows, RSA/ECC key pair generation, and digital signature verification.
* **`08-pki_architecture.md`** – Design blueprint for MedDefense’s internal Public Key Infrastructure (Root CA, Intermediate CAs, and trust chains).
* **`09-tls_configuration.md`** – Hardening guidelines for web servers, enforcing TLS 1.2/1.3 and eliminating legacy cipher suites.
* **`10-key_management_kms.md`** – Enterprise Key Management Service (KMS) architecture, key rotation policies, and split-knowledge backup recovery.
* **`11-secure_communication_channels.md`** – Network micro-segmentation, mTLS enforcement, and transit security standards for internal APIs and EHR databases.
* **`12-disk_encryption.md`** – LUKS virtual disk encryption lab, automation scripting, and an enterprise backup storage design for `NAS-01` with cloud replication key ownership.

### Phase 3: Governance, Compliance & Policy (Modules 13–18)
* **`13-identity_access_management.md`** – IAM modernization plan, Role-Based Access Control (RBAC), and mandatory Multi-Factor Authentication (MFA).
* **`14-network_security_architecture.md`** – Firewall zoning, VPN hardening, and perimeter defense strategies.
* **`15. The Cryptographic Attack Surface`** – Real-world threat mapping (TLS downgrade, collision attacks, Kerberoasting, MitM, and RAM key extraction) matched to MedDefense vulnerabilities.
* **`16. Certificate Lifecycle Management (CLM)`** – Enterprise CLM program featuring an asset inventory, automated ACME/Let's Encrypt renewal strategies, and governance policies.
* **`17. The Data Classification Policy & Matrix`** – Risk-driven data classification aligned with Security+ types, featuring a four-level matrix, employee decision tree, and data sovereignty rules.
* **`18. Compliance & Governance Framework`** – Broader regulatory alignment across hospital policies and operational workflows.

### Phase 4: Audit Readiness, Playbooks & Execution (Modules 19–24)
* **`19. The HIPAA Crypto Compliance Checkpoint`** – Regulatory mapping against the HIPAA Security Rule (45 CFR §164.312), identifying compliance gaps and audit readiness.
* **`20. The Implementation Playbook`** – Step-by-step production execution playbook for the top five cryptographic changes with prerequisites, exact commands, validation checks, and rollback plans.
* **`21-disaster_recovery_continuity.md`** – Business continuity plans, high-availability data replication, and failover validation protocols.
* **`22-vendor_supply_chain_security.md`** – Third-party risk management, medical device firmware validation, and Business Associate Addendum (BAA) standards.
* **`23-security_awareness_training.md`** – Phishing defense, credential hygiene, and clinical staff cybersecurity training modules.
* **`24-program_maturity_roadmap.md`** – Long-term strategic roadmap for continuous security improvement and maturity elevation across MedDefense systems.
