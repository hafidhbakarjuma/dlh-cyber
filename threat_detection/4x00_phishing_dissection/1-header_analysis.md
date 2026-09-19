# SMTP Header Analysis Report

**Analyst:** SOC Team  
**Date:** 2026-04-17  
**Scope:** Deep-dive SMTP header analysis for suspicious emails E2, E3, E5, and E7.

---

## Email 2 — meddefense-portal.com

### Header Evidence
- **From:** `"MedDefense IT Security" <noreply@meddefense-portal.com>`
- **Return-Path:** `<noreply@meddefense-portal.com>`
- **Sending IP:** `91.234.99.107`
- **X-Mailer:** `PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)`
- **Message-ID:** `<PHP-5D7E2F4A@meddefense-portal.com>`

### Received Chain Summary
1. `localhost (localhost [127.0.0.1])` by `mail.meddefense-portal.com (PHPMailer 6.6.0)` — Message generated locally via script.
2. `mail.meddefense-portal.com ([91.234.99.107])` by `mx01.meddefense.com` — External relaying hop from a budget VPS provider.
3. `mx01.meddefense.com ([10.10.1.20])` by `inbound-relay.meddefense.com` — Internal MedDefense gateway reception.

### Anomalies
- **[HIGH] Authentication Failure:** SPF fails (`sender IP not authorized`) and DMARC fails. DKIM is completely absent (`none`).
- **[HIGH] Infrastructure Mismatch:** The sending IP (`91.234.99.107`) belongs to an external hosting provider rather than authorized enterprise mail infrastructure.
- **[MEDIUM] Mass-Mailing Framework:** Utilizes `PHPMailer`, common in automated phishing kits, despite purporting to be an official internal IT security notification.

### Conclusion
Email 2 is an unauthenticated external phishing attempt. It uses a lookalike domain (`meddefense-portal.com`) and generic script-based infrastructure to impersonate internal IT security, driving users toward a malicious credential harvesting page under severe time pressure.

---

## Email 3 — outlook-protection.com

### Header Evidence
- **From:** `"Microsoft Account Protection" <security@outlook-protection.com>`
- **Return-Path:** `<security@outlook-protection.com>`
- **Sending IP:** `51.38.42.17`
- **X-Mailer:** `PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)`
- **Message-ID:** `<PHP-9F2D7E1B@outlook-protection.com>`

### Received Chain Summary
1. `wp-admin.outlook-protection.com (localhost [127.0.0.1])` by `mail.outlook-protection.com (PHPMailer 6.6.0)` — Generated via WordPress backend script.
2. `mail.outlook-protection.com ([51.38.42.17])` by `mx01.meddefense.com` — Inbound transfer from external mail server.
3. `mx01.meddefense.com ([10.10.1.20])` by `inbound-relay.meddefense.com` — Internal relay hop.

### Anomalies
- **[HIGH] Brand Impersonation via Lookalike Domain:** The email successfully passes SPF and DKIM checks, but it authenticates for `outlook-protection.com`—a deceptive third-party domain—rather than official Microsoft infrastructure (`microsoft.com`).
- **[MEDIUM] WordPress/PHP Origin:** The local submission host (`wp-admin.outlook-protection.com`) and `PHPMailer` header indicate a compromised or attacker-controlled WordPress site acting as the mailer.
- **[MEDIUM] Deceptive Pretexting:** Leverages an urgent security alert (unauthorized login from Lagos, Nigeria) to prompt immediate credential verification.

### Conclusion
Email 3 demonstrates a classic "auth-passing lookalike" tactic. While technical authentication validly passes for the sender's registered domain (`outlook-protection.com`), the domain itself is a malicious impersonation setup designed to trick recipients into believing Microsoft sent the warning.

---

## Email 5 — medequip-supplies.net

### Header Evidence
- **From:** `"MedEquip Supplies Billing" <invoices@medequip-supplies.net>`
- **Return-Path:** `<invoices@medequip-supplies.net>`
- **Sending IP:** `185.176.43.22`
- **X-Mailer:** `PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)`
- **Message-ID:** `<PHP-7C2D4E1A@medequip-supplies.net>`

### Received Chain Summary
1. `billing-svc.medequip-supplies.net (localhost [127.0.0.1])` by `mail.medequip-supplies.net (PHPMailer 6.6.0)` — Script execution on billing subdomain.
2. `mail.medequip-supplies.net ([185.176.43.22])` by `mx01.meddefense.com` — External delivery hop.
3. `mx01.meddefense.com ([10.10.1.20])` by `inbound-relay.meddefense.com` — Relay to internal inbox.

### Anomalies
- **[HIGH] Authentication Deficit:** SPF results in a `softfail` and DMARC fails. DKIM signatures are completely missing (`none`).
- **[MEDIUM] External VPS Sending Source:** The sending IP (`185.176.43.22`) originates from commercial VPS hosting rather than verified supplier infrastructure.
- **[MEDIUM] High-Pressure Financial Lure:** Features a high-dollar invoice ($24,716.38) combined with an attachment and external links designed to force hasty accounts payable processing.

### Conclusion
Email 5 is a financial pretexting and invoice fraud attempt. The failure of SPF/DMARC alongside the use of `PHPMailer` from an unverified hosting provider indicates an external attacker masquerading as a legitimate medical supplier.

---

## Email 7 — meddefense-benefits.org

### Header Evidence
- **From:** `"MedDefense HR Benefits" <hr-notifications@meddefense-benefits.org>`
- **Return-Path:** `<hr-notifications@meddefense-benefits.org>`
- **Sending IP:** `164.90.218.73`
- **X-Mailer:** `PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)`
- **Message-ID:** `<PHP-2E4A7B1C@meddefense-benefits.org>`

### Received Chain Summary
1. `wp-portal.meddefense-benefits.org (localhost [127.0.0.1])` by `mail.meddefense-benefits.org (PHPMailer 6.6.0)` — Local script generation via WordPress portal.
2. `mail.meddefense-benefits.org ([164.90.218.73])` by `mx01.meddefense.com` — External inbound transmission.
3. `mx01.meddefense.com ([10.10.1.20])` by `inbound-relay.meddefense.com` — Final internal delivery relay.

### Anomalies
- **[HIGH] Authentication Failure:** SPF fails and DMARC fails completely; sending IP (`164.90.218.73`) lacks authorization for the domain. DKIM is absent.
- **[MEDIUM] Lookalike Domain Infrastructure:** Uses a deceptive external domain (`meddefense-benefits.org`) mimicking internal human resources services.
- **[MEDIUM] Automated Bulk Scripting:** Generated via `PHPMailer` from a WordPress staging/portal path (`wp-portal`).

### Conclusion
Email 7 is a targeted credential harvesting lure mimicking internal HR benefits enrollment. The header anomalies confirm that it is an external, unauthenticated phishing email utilizing a lookalike domain to exploit open-enrollment panic.
