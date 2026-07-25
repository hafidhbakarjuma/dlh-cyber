## Enterprise Certificate Lifecycle Management (CLM) Program  
**Status:** Operational Policy & Program Specification Report  

---

## Executive Summary
The impending expiration of the MedDefense patient portal certificate was merely a symptom of a deeper organizational deficiency: the complete absence of a formal Certificate Lifecycle Management (CLM) program. Relying on manual tracking inevitably leads to service outages, clinical disruption, and compliance failures. This document establishes MedDefense’s enterprise CLM program, encompassing comprehensive asset tracking, automated renewal strategies, multi-tier alerting thresholds, and strict certificate usage policies.

---

## Part 1: Enterprise Certificate Inventory

| Certificate Asset | Common Name / Purpose | Current Issuer | Expiration Date (Estimate) | Responsible Owner |
| :--- | :--- | :--- | :--- | :--- |
| **Patient Portal** | `portal.meddefense.local` | Commercial CA (DigiCert / Sectigo) | 18 Days (Critical Finding 013) | Web Security Team / Lead SysAdmin |
| **Internal EHR Database** | `ehr-db-01.meddefense.local` | MedDefense Internal Root CA | 120 Days | Database Administration (DBA) Team |
| **Enterprise VPN Gateway** | `vpn.meddefense.local` | MedDefense Internal Root CA | 45 Days | Network Security Operations |
| **Corporate Email / S/MIME** | `mail.meddefense.local` | Commercial CA | 180 Days | Enterprise Messaging Team |
| **Code Signing (IoT/Pumps)** | `meddefense-firmware-sign` | Dedicated Offline HSM Root CA | 730 Days (2 Years) | Embedded Systems & Firmware Engineering |

---

## Part 2: Auto-Renewal Strategy

### 1. Recommendation for MedDefense
* **Primary Recommendation:** Implement automated **ACME / Let's Encrypt** protocol for all public-facing and web services (such as the patient portal), coupled with an internal **ACME server (e.g., Smallstep / HashiCorp Vault PKI)** for all internal services (EHR, VPN, internal APIs).

### 2. Justification for the Patient Portal
* **Operational Resilience & Clinical Impact:** Given that the patient portal handles 800 patient connections per day, an unhandled certificate expiration directly blocks patient access to critical medical histories, test results, and provider communications, resulting in severe clinical risk and reputational damage.
* **Why ACME/Let's Encrypt over Commercial 1-Year Manual Certs:** Manual 1-year commercial certificates rely entirely on human operational memory, which caused the current "18 days remaining" crisis. Automated ACME renewals execute every 60–90 days without human intervention, completely eliminating human error and ensuring continuous operational uptime.

---

## Part 3: Monitoring, Alerting, and Thresholds

* **Monitoring Tool:** Integration of enterprise monitoring systems (Prometheus with Blackbox Exporter / Grafana TLS Exporter) alongside automated daily scanning via Certbot/OpenSSL cron jobs.
* **Alerting Thresholds & Routing:**
  * **90 Days Before Expiry (Info):** Notification sent to internal infrastructure ticketing system to verify auto-renewal hooks.
  * **60 Days Before Expiry (Warning):** Email notification sent to the **Responsible Owner** and SysAdmin team queue.
  * **30 Days Before Expiry (High):** PagerDuty alert triggered to the **Infrastructure Engineering On-Call** and **Lead Systems Administrator**.
  * **7 Days Before Expiry (Critical / Emergency):** Escalation PagerDuty alert triggered to the **Chief Information Security Officer (CISO)** and **Director of IT Operations** for immediate manual intervention if automation failed.

---

## Part 4: Draft Certificate Policy (5 Governance Rules)

1. **Rule 1: Prohibition of Self-Signed Certificates in Production**  
   *All production environments, customer-facing portals, and internal enterprise services must utilize certificates issued by an approved trusted public CA or the MedDefense Internal Root CA. Self-signed certificates are strictly prohibited in production.*
2. **Rule 2: Mandatory Automated Lifecycle Management**  
   *All web-facing and internal service certificates must implement automated renewal workflows (e.g., ACME protocol) wherever technically feasible. Manual certificate deployment is restricted exclusively to offline root and code-signing assets.*
3. **Rule 3: Cryptographic Algorithm Standards**  
   *Certificate key lengths and signature algorithms must comply with current security baselines: minimum RSA-2048 (RSA-4096 preferred) or ECC P-256, utilizing SHA-256 or SHA-3 signatures. MD5 and SHA-1 signatures are strictly banned.*
4. **Rule 4: Centralized Inventory Tracking**  
   *Every digital certificate deployed across MedDefense infrastructure must be registered in the centralized CLM inventory database within 24 hours of issuance, detailing its purpose, owner, and cryptographic specifications.*
5. **Rule 5: Emergency Revocation SLA**  
   *In the event of a suspected or confirmed private key compromise, the responsible owner must execute certificate revocation and replacement within a maximum Service Level Agreement (SLA) window of 2 hours.*

---
