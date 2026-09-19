# Email Authentication Analysis Report

**Analyst:** SOC Team  
**Date:** 2026-04-17  
**Scope:** Validation and technical interpretation of SPF, DKIM, and DMARC results for all 8 collected emails (E1 through E8).

---

## Email 1 — healthcare-education-weekly.com
- **SPF:** Pass (sender IP `198.51.100.42` is authorized for `healthcare-education-weekly.com`).
- **DKIM:** Pass (`header.d=healthcare-education-weekly.com`, valid cryptographic signature).
- **DMARC:** Pass (`action=none`, aligning domain matches the visible From header).
- **Authentication verdict:** Fully authenticated. The sending infrastructure matches the domain owner's published records.
- **Investigation meaning:** Authentication supports the apparent legitimacy of the newsletter, confirming it is an authorized external mailing.

---

## Email 2 — meddefense-portal.com
- **SPF:** Fail (`91.234.99.107` is not authorized for `meddefense-portal.com`).
- **DKIM:** None (message is completely unsigned).
- **DMARC:** Fail (`action=none`, policy fails due to lack of valid SPF/DKIM alignment).
- **Authentication verdict:** Unauthenticated. The sender fails all technical validation checks.
- **Investigation meaning:** Authentication contradicts the claimed identity, reinforcing that the email is an external phishing attempt spoofing an internal portal.

---

## Email 3 — outlook-protection.com
- **SPF:** Pass (`51.38.42.17` is authorized for `outlook-protection.com`).
- **DKIM:** Pass (`header.d=outlook-protection.com`, valid signature for that specific domain).
- **DMARC:** Pass (`action=none`, aligning with `outlook-protection.com`).
- **Authentication verdict:** Technically authenticated for its own domain, but functionally deceptive.
- **Investigation meaning:** This email highlights a key limitation of email authentication: a pass result only proves that the infrastructure controls the sending domain (`outlook-protection.com`), *not* that the domain itself belongs to the brand being impersonated. The domain `outlook-protection.com` is a lookalike entity and is entirely distinct from official Microsoft domains like `microsoft.com` or `outlook.com`. Passing authentication checks does not make the email legitimate because the underlying domain is a malicious third-party registration designed for brand impersonation.

---

## Email 4 — meddefense.com
- **SPF:** Pass (`10.10.1.15` is an internal Exchange hub).
- **DKIM:** Pass (`header.d=meddefense.com`, valid internal signature).
- **DMARC:** Pass (`action=none`, fully aligned internal domain).
- **Authentication verdict:** Fully authenticated internal communication.
- **Investigation meaning:** Authentication strongly supports the legitimacy of the internal IT announcement from the organization's own exchange environment.

---

## Email 5 — medequip-supplies.net
- **SPF:** Softfail (`185.176.43.22` is not strictly authorized or is flagged as a softfail for `medequip-supplies.net`).
- **DKIM:** None (message lacks a signature).
- **DMARC:** Fail (`action=none`, alignment fails).
- **Authentication verdict:** Failed authentication. The message lacks cryptographic integrity and IP authorization.
- **Investigation meaning:** Contradicts the legitimacy of the supplier invoice, confirming an external unauthenticated actor is attempting financial pretexting.

---

## Email 6 — canadian-pharma-discount.org
- **SPF:** Softfail (sender IP lacks strict authorization).
- **DKIM:** None (no signature present).
- **DMARC:** Fail (`action=quarantine`, policy dictates quarantining unaligned messages).
- **Authentication verdict:** Failed authentication, triggering automated gateway policy.
- **Investigation meaning:** Supports the classification of the email as bulk spam/unauthorized marketing, corroborated by gateway rejection mechanics.

---

## Email 7 — meddefense-benefits.org
- **SPF:** Fail (`164.90.218.73` is not authorized for `meddefense-benefits.org`).
- **DKIM:** None (message is unsigned).
- **DMARC:** Fail (`action=none`).
- **Authentication verdict:** Unauthenticated external transmission.
- **Investigation meaning:** Contradicts the appearance of an official HR benefits notice, proving it is a lookalike domain phishing lure.

---

## Email 8 — hhs.gov
- **SPF:** Pass (`134.174.47.82` is authorized for `hhs.gov`).
- **DKIM:** Pass (`header.d=hhs.gov`, valid government cryptographic signature).
- **DMARC:** Pass (`action=none`, fully aligned federal domain).
- **Authentication verdict:** Fully authenticated official government communication.
- **Investigation meaning:** Authentication strongly supports the authenticity of the threat intelligence advisory from the U.S. Department of Health and Human Services.
