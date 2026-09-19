# Phishing Campaign Investigation Report: MedDefense Health Systems

**Analyst:** SOC Team  
**Date:** 2026-04-17  
**Classification:** TLP:AMBER / RESTRICTED INTERNAL  
**Scope:** Investigation of 8 reported emails, user click impact analysis, and campaign attribution benchmarking against federal threat intelligence (HHS HC3).

---

## 1. Executive Summary
MedDefense Health Systems experienced a coordinated, multi-vector phishing campaign targeting clinical, financial, and human resources personnel between April 14 and April 16, 2026. The campaign utilized sophisticated lookalike domains, budget VPS hosting nodes, and role-specific pretexts to harvest credentials and induce financial fraud. A clinical staff member (Diane Marsh) successfully navigated to a malicious portal-verification link, representing a potential exposure event that warrants immediate precautionary identity and session remediation. Out of eight evaluated emails, four were identified as active malicious threats, one as bulk spam, and three as legitimate communications (including an official federal alert). Immediate technical and credential containment measures have been outlined to secure enterprise infrastructure and prevent secondary access.

---

## 2. Investigation Timeline
* **Email Collection Window:** April 14, 2026 07:22 CDT — April 16, 2026 15:22 CDT (~57 hours).
* **Email 2 Delivery (Portal Phishing):** April 14, 2026 14:47:52 CDT.
* **User Click Timestamp (Diane Marsh / WS-NURSE-04):** April 14, 2026 15:02:33 CDT (approx. 15 minutes post-delivery).
* **Email 3 Delivery (M365 Phishing):** April 15, 2026 09:13:44 CDT.
* **Email 4 Delivery (Internal IT Announcement):** April 15, 2026 10:00:12 CDT.
* **Email 5 Delivery (Invoice Fraud Lure):** April 16, 2026 11:28:39 CDT.
* **Email 6 Delivery (Pharmaceutical Spam):** April 16, 2026 13:04:22 CDT.
* **Email 7 Delivery (HR Benefits Phishing):** April 16, 2026 15:22:07 CDT.
* **Email 8 Delivery (HC3 Threat Briefing):** April 16, 2026 08:47:02 CDT.
* **Investigation Scope:** Analysis of 8 raw SMTP headers, authentication records, attachment metadata, user click telemetry, and federal threat intelligence advisories.

---

## 3. Email-by-Email Analysis

| Email | Final Classification | Confidence | Key Evidence |
|---|---|---|---|
| **E1** | LEGITIMATE | HIGH | Passes all auth checks (SPF, DKIM, DMARC); valid newsletter infrastructure (`healthcare-education-weekly.com`). |
| **E2** | PHISHING-TARGETED | HIGH | Fails all auth checks; lookalike domain (`meddefense-portal.com`); high urgency; confirmed user click by Diane Marsh (`WS-NURSE-04`). |
| **E3** | PHISHING-OPPORTUNISTIC | HIGH | Passes auth for third-party domain (`outlook-protection.com`), but domain is an external lookalike impersonating Microsoft M365 security alerts. |
| **E4** | LEGITIMATE | HIGH | Internal Exchange hub origin (`meddefense.local`), valid internal DKIM signature, aligns with standard IT announcement policies. |
| **E5** | PHISHING-TARGETED | HIGH | Auth softfail/fail; external VPS sending source (`185.176.43.22`); high-value invoice pretext ($24,716.38) targeting Accounts Payable with malicious PDF attachment links. |
| **E6** | SPAM | HIGH | High spam score (9.8), pharmaceutical marketing lure, gateway quarantine action triggered, direct IP link (`203.0.113.228`). |
| **E7** | PHISHING-TARGETED | HIGH | Fails auth checks; lookalike domain (`meddefense-benefits.org`); exploits annual HR open enrollment urgency targeting Linda Patterson. |
| **E8** | LEGITIMATE | HIGH | Official federal threat intelligence advisory from U.S. HHS Health Sector Cybersecurity Coordination Center with valid government auth (`hhs.gov`). |

---

## 4. Campaign Analysis
* **Coordination of E2, E5, and E7:** Emails 2, 5, and 7 are definitively connected by shared script infrastructure (`PHPMailer 6.6.0`), unauthenticated budget VPS hosting, structural reliance on high-pressure psychological deadlines, and tailored role-based targeting (clinical staff, accounts payable, and human resources).
* **Correlation with Email 8 (HC3 Advisory):** The findings align flawlessly with regional healthcare threat data provided by HHS HC3. The advisory warned of newly registered `.com`/`.net`/`.org` domains incorporating keywords like "portal," "supplies," and "benefits," sent via PHPMailer scripts on budget hosting tiers with 24–48 hour deadlines.
* **Interpretation of Email 3:** Email 3 represents an opportunistic brand impersonation attack. Although technical authentication checks (SPF, DKIM, DMARC) successfully passed, they authenticated the attacker's registered domain (`outlook-protection.com`) rather than legitimate Microsoft infrastructure (`microsoft.com`), underscoring that valid authentication does not equate to message safety.

---

## 5. Click Incident Assessment
* **Known Facts:** User Diane Marsh (`dmarsh@meddefense.com` on workstation `WS-NURSE-04`, IP `10.10.2.15`) received Email 2 and actively clicked the malicious verification link (`https://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1`) on April 14, 2026, at 15:02:33 CDT.
* **Key Unknowns:** The available evidence batch confirms the click event but does not prove whether credentials were actually entered into the phishing portal, whether authentication tokens were successfully harvested by the attacker, or if local endpoint execution occurred.
* **Recommended Safe Actions:** Because credential entry cannot be ruled out from telemetry alone, treat the event as a potential exposure. Recommended actions are limited to a proactive password reset, forced session token revocation, a direct user interview with Diane Marsh, and reviewing authentication/endpoint logs.

---

## 6. IOC Summary
* **Domains:** `meddefense-portal[.]com`, `outlook-protection[.]com`, `medequip-supplies[.]net`, `meddefense-benefits[.]org`
* **IP Addresses:** `91.234.99[.]107`, `51.38.42[.]17`, `185.176.43[.]22`, `164.90.218[.]73`
* **URLs:** 
  - `https://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1`
  - `https://outlook-protection[.]com/verify`
  - `https://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891`
  - `https://meddefense-benefits[.]org/enroll`
* **Sender Addresses:** `noreply@meddefense-portal[.]com`, `security@outlook-protection[.]com`, `invoices@medequip-supplies[.]net`, `hr-notifications@meddefense-benefits[.]org`
* **File Hash (SHA-256):** `2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1fxx` (Attachment metadata hash from `INV-2026-04891.pdf`)

---

## 7. Detection and Control Gaps
* **Control Gaps:** Inbound mail gateway filters permitted unauthenticated external emails utilizing lookalike corporate domains to reach user inboxes because DMARC policies for those spoofed external spaces defaulted to `action=none`. Endpoint web proxies did not block navigation to newly registered external domains.
* **Improvement & Detection Ideas:** 
  - Implement strict email gateway quarantines or rejections for inbound external emails failing DMARC alignment when the header domain closely mimics internal nomenclature (Lookalike Sound-Alike / Cousin Domain blocking).
  - Deploy URL filtering rules to block external domains registered less than 30 days ago that contain sensitive keywords (`portal`, `login`, `benefits`, `secure`).
  - Create SIEM detection rules alerting on inbound emails matching external lookalike strings combined with `PHPMailer` headers.

---

## 8. Recommendations
* **Immediate (Next 24 Hours):**
  1. Force a password reset and revoke all active cloud/local session tokens for Diane Marsh (`dmarsh@meddefense.com`).
  2. Block all malicious domains, URLs, and sending IP addresses identified in the IOC summary at the email gateway and web proxy.
  3. Conduct a targeted interview with Diane Marsh to confirm interaction details and check for credential input.
* **Short-Term (Next 7 Days):**
  1. Review Active Directory and M365 authentication logs for anomalous external logins associated with `dmarsh` or originating from sending IP `91.234.99.107`.
  2. Audit enterprise mailboxes for unauthorized inbox forwarding rules or delegation changes.
  3. Submit extracted IOCs to HHS HC3 to contribute to the regional healthcare threat advisory.
* **Medium-Term (Next 30 Days):**
  1. Implement advanced cousin-domain monitoring and automated defensive rules for newly registered lookalike domains matching organizational assets.
  2. Conduct enterprise-wide security awareness refresher training focusing on urgency-based pretexts, lookalike domain identification, and reporting procedures.
  3. Tune email gateway policies to enforce stricter quarantine handling for unaligned external messages impersonating internal administrative workflows.
