# Indicators of Compromise (IOC) Extraction Report

**Analyst:** SOC Team  
**Date:** 2026-04-17  
**Scope:** Extraction, classification, and quality assessment of Indicators of Compromise (IOCs) derived from the MedDefense Health Systems phishing investigation (Emails E2, E3, E5, E7, and threat intel from E8).

---

## 1. Structured IOC Table

| IOC Type | IOC Value (Defanged) | Source Email | Context | Confidence | Recommended Action |
|---|---|---|---|---|---|
| **Domain** | `meddefense-portal[.]com` | E2 | Phishing domain impersonating internal IT portal; clicked by D. Marsh | HIGH | Block |
| **IP Address** | `91.234.99[.]107` | E2 | External VPS sending IP for E2 | HIGH | Block |
| **URL** | `https://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1` | E2 | Credential harvesting landing path | HIGH | Block / Monitor |
| **Email Address** | `noreply@meddefense-portal[.]com` | E2 | Visible and return-path sender address | MEDIUM | Block |
| **Domain** | `outlook-protection[.]com` | E3 | Lookalike domain impersonating Microsoft security notifications | HIGH | Block |
| **IP Address** | `51.38.42[.]17` | E3 | External WordPress-backed sending IP for E3 | HIGH | Block / Monitor |
| **URL** | `https://outlook-protection[.]com/verify` | E3 | M365 credential harvesting link | HIGH | Block |
| **Email Address** | `security@outlook-protection[.]com` | E3 | Visible and return-path sender address | MEDIUM | Block |
| **Domain** | `medequip-supplies[.]net` | E5 | Malicious vendor domain used for financial fraud/BEC | HIGH | Block |
| **IP Address** | `185.176.43[.]22` | E5 | External sending IP for E5 | HIGH | Block / Monitor |
| **URL** | `https://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891` | E5 | External payment/harvesting link | HIGH | Block |
| **Email Address** | `invoices@medequip-supplies[.]net` | E5 | Visible sender address for invoice lure | MEDIUM | Block |
| **File Hash (SHA-256)** | `2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1fxx` | E5 | Metadata signature/hash extracted from `INV-2026-04891.pdf` | HIGH | Alert / Block |
| **Domain** | `meddefense-benefits[.]org` | E7 | Lookalike domain impersonating internal HR open enrollment | HIGH | Block |
| **IP Address** | `164.90.218[.]73` | E7 | External WordPress-backed sending IP for E7 | HIGH | Block / Monitor |
| **URL** | `https://meddefense-benefits[.]org/enroll` | E7 | HR portal phishing destination link | HIGH | Block |
| **Email Address** | `hr-notifications@meddefense-benefits[.]org` | E7 | Visible sender address for HR lure | MEDIUM | Block |
| **Tool / Infrastructure** | `PHPMailer 6.6.0` | E2, E3, E5, E7 | Shared script-based mailer tool signature | MEDIUM | Context Only |
| **HC3 Pattern** | Newly registered `.com`/`.net`/`.org` domains (<30 days old) using "portal", "benefits", "supplies" | E8 | Regional healthcare sector threat brief indicators | MEDIUM | Monitor / Alert |

---

## 2. IOCs Categorized by Attack Phase

### Delivery Phase (Sender & Infrastructure)
* `91.234.99[.]107` (E2 External Sending IP)
* `51.38.42[.]17` (E3 External Sending IP)
* `185.176.43[.]22` (E5 External Sending IP)
* `164.90.218[.]73` (E7 External Sending IP)
* `noreply@meddefense-portal[.]com`, `security@outlook-protection[.]com`, `invoices@medequip-supplies[.]net`, `hr-notifications@meddefense-benefits[.]org`

### Credential Harvesting & Action Phases (URLs & Domains)
* `meddefense-portal[.]com` (`https://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1`)
* `outlook-protection[.]com` (`https://outlook-protection[.]com/verify`)
* `medequip-supplies[.]net` (`https://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891`)
* `meddefense-benefits[.]org` (`https://meddefense-benefits[.]org/enroll`)

### Attachment & Lure Artifacts
* `INV-2026-04891.pdf` (Embedded PDF attachment referencing a $24,716.38 invoice)
* SHA-256 Hash string: `2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1fxx`

### Infrastructure Signatures
* `PHPMailer 6.6.0` framework header across multiple unrelated sending domains.

### Context-Only Indicators
* Generic cloud/VPS provider hosting network ranges and general registrar metadata patterns mentioned in the HC3 alert (E8).

---

## 3. IOC Quality Assessment

* **High-Confidence Indicators (Safe to Block):** Lookalike domains (`meddefense-portal[.]com`, `outlook-protection[.]com`, `medequip-supplies[.]net`, `meddefense-benefits[.]org`) and specific full URLs are high-confidence indicators. Because these domains are explicitly registered for malicious impersonation and have zero legitimate enterprise association, blocking them at the web proxy and email gateway carries minimal risk of false positives.
* **Medium-Confidence Indicators (Monitor / Alert):** Sending IP addresses (`91.234.99[.]107`, `185.176.43[.]22`, etc.) and specific file hashes are strong indicators of past malicious activity. However, because attackers frequently rotate budget VPS hosting nodes, blocking raw IPs permanently can lead to collateral damage if hosting providers reassign those IPs to legitimate tenants later. These should be set to alert or temporary block status.
* **Low-Confidence / Context-Only Indicators (Do Not Block Alone):** Software tool signatures like `PHPMailer 6.6.0` or general hosting provider networks (e.g., DigitalOcean, Hostinger pricing tiers) must **not** be blocked or alerted on standalone criteria. PHPMailer is widely used for legitimate web applications; blocking it outright would cause massive operational disruption across corporate web development platforms.

---

## 4. HC3-Ready Summary

* **Target Campaign Indicator:** Coordinated regional healthcare phishing campaign impersonating internal portals, vendor supply chains, and HR benefits.
* **Malicious Domains:** `meddefense-portal[.]com`, `outlook-protection[.]com`, `medequip-supplies[.]net`, `meddefense-benefits[.]org`
* **Malicious URLs:** 
  - `https://meddefense-portal[.]com/verify/staff`
  - `https://outlook-protection[.]com/verify`
  - `https://medequip-supplies[.]net/invoices/pay`
  - `https://meddefense-benefits[.]org/enroll`
* **Sending IPs:** `91.234.99[.]107`, `51.38.42[.]17`, `185.176.43[.]22`, `164.90.218[.]73`
* **Sender Addresses:** `noreply@meddefense-portal[.]com`, `security@outlook-protection[.]com`, `invoices@medequip-supplies[.]net`, `hr-notifications@meddefense-benefits[.]org`
