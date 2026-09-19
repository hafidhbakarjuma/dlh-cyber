# URL and Attachment Autopsy Report

**Analyst:** SOC Team  
**Date:** 2026-04-17  
**Scope:** Safe extraction, defanging, and analysis of URLs, domains, and attachment indicators found in suspicious emails E2, E3, E5, E6, and E7.

---

## Indicator 1

- **Source email:** E2
- **Original value:** `https://meddefense-portal.com/verify/staff?id=dmarsh&token=a8f3e2d1`
- **Defanged value:** `https://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1`
- **Domain or IP:** `meddefense-portal.com`
- **Indicator type:** Phishing URL / Credential Harvesting Link
- **Evidence from email:** Sent by an unauthorized external IP (`91.234.99.107`) impersonating internal MedDefense IT security, demanding 24-hour re-verification; **clicked by user Diane Marsh**.
- **Safe investigation method:** `whois meddefense-portal.com`, `dig meddefense-portal.com +noall +answer`, `curl -I hxxps://meddefense-portal[.]com`, or searching via URLhaus / urlscan.io.
- **Finding:** The domain uses a typosquatted lookalike pattern mimicking the organization's name to capture credentials via a fake verification path.
- **Risk rating:** HIGH (P1-URGENT)

---

## Indicator 2

- **Source email:** E3
- **Original value:** `https://outlook-protection.com/verify`
- **Defanged value:** `https://outlook-protection[.]com/verify`
- **Domain or IP:** `outlook-protection.com`
- **Indicator type:** Phishing URL / Lookalike Brand Impersonation
- **Evidence from email:** Sent from external server `51.38.42.17` using a WordPress-backed script (`wp-admin.outlook-protection.com`), warning of a fake login attempt from Lagos, Nigeria.
- **Safe investigation method:** `whois outlook-protection.com`, `dig outlook-protection.com`, checking reputation status on VirusTotal or urlscan.io.
- **Finding:** The domain imitates Microsoft/Outlook protection mechanisms to deceive recipients into entering corporate credentials under duress.
- **Risk rating:** HIGH

---

## Indicator 3

- **Source email:** E5
- **Original value:** `https://medequip-supplies.net/invoices/pay?id=INV-2026-04891`
- **Defanged value:** `https://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891`
- **Domain or IP:** `medequip-supplies.net`
- **Indicator type:** Financial Phishing URL / External Payment Link
- **Evidence from email:** Accompanied by an attached PDF (`INV-2026-04891.pdf`) referencing a $24,716.38 invoice with an embedded PDF link pointing to `https://medequip-supplies.net/invoices/pay?id=INV-2026-04891`.
- **Safe investigation method:** `whois medequip-supplies.net`, metadata and string extraction from the raw attachment source (e.g., inspecting PDF object mappings and SHA-256 hashes such as `2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1fxx`), or querying Hybrid Analysis.
- **Finding:** The domain and attachment construct a high-pressure vendor financial fraud scheme designed to redirect payment or capture authentication tokens.
- **Risk rating:** HIGH

---

## Indicator 4

- **Source email:** E7
- **Original value:** `https://meddefense-benefits.org/enroll`
- **Defanged value:** `https://meddefense-benefits[.]org/enroll`
- **Domain or IP:** `meddefense-benefits.org`
- **Indicator type:** Phishing URL / HR Impersonation Link
- **Evidence from email:** Sent from external host `164.90.218.73` via a WordPress portal script (`wp-portal.meddefense-benefits.org`), demanding completion of open enrollment by tomorrow under threat of coverage lapse.
- **Safe investigation method:** `whois meddefense-benefits.org`, `dig meddefense-benefits.org`, reputation verification via VirusTotal.
- **Finding:** Utilizes a lookalike domain blending the enterprise name with benefits terminology to exploit seasonal HR pressures.
- **Risk rating:** HIGH

---

## Indicator 5

- **Source email:** E6
- **Original value:** `http://203.0.113.228/shop?ref=pwhite`
- **Defanged value:** `hxxp://203.0[.]113[.]228/shop?ref=pwhite`
- **Domain or IP:** `203.0.113.228`
- **Indicator type:** Direct IP URL / Spam Link
- **Evidence from email:** Embedded in bulk pharmaceutical spam advertising discounted medications (`deals@canadian-pharma-discount.org`) with a high spam score (9.8). Note: `203.0.113.0/24` is part of standard documentation/TEST-NET ranges per RFC 5737.
- **Safe investigation method:** `whois 203.0.113.228`, checking gateway blocklists or URLhaus telemetry.
- **Finding:** Direct IP addressing bypassing domain infrastructure, associated with generic low-priority spam rather than a targeted enterprise APT.
- **Risk rating:** LOW (Spam / Noise)
