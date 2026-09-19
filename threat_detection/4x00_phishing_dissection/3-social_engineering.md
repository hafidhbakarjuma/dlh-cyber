# Social Engineering Analysis Report

**Analyst:** SOC Team  
**Date:** 2026-04-17  
**Scope:** Psychological manipulation, pretexting, and targeting analysis for suspicious emails E2, E3, E5, and E7.

---

## Email 2 — Portal re-verification lure
- **Psychological lever:** Urgency, Fear, Authority (impersonating IT Security)
- **Pretext:** An urgent security policy update requires staff portal re-verification within 24 hours, or the user will lose access to scheduling, EHR gateways, and shift swaps.
- **Requested action:** Click the verification link (`VERIFY MY ACCESS NOW`) and log in.
- **Targeting level:** SEMI-TARGETED
- **Content red flags:** Threat of severe operational lockout under a short deadline, generic ticket reference (`INC-2026-04-14-7741`), use of an external lookalike domain (`meddefense-portal.com`).
- **Attacker knowledge required:** Knowledge of healthcare operational roles (scheduling, EHR access), employee email addressing conventions (`dmarsh@meddefense.com`), and internal portal terminology.
- **Conclusion:** A high-pressure internal impersonation lure designed to exploit operational panic and force immediate credential submission.

---

## Email 3 — Microsoft 365 sign-in alert
- **Psychological lever:** Fear, Urgency, Authority (impersonating Microsoft Account Protection)
- **Pretext:** An unrecognized sign-in attempt was detected from a remote location (Lagos, Nigeria) on an unknown device, threatening account lock within 48 hours unless verified.
- **Requested action:** Click the `Verify account` link and follow prompts.
- **Targeting level:** GENERIC (though tailored with the victim's email address)
- **Content red flags:** Geographic anomaly alert (`Lagos, Nigeria`), strict account lockout deadline, use of an unauthorized external domain (`outlook-protection.com` instead of `microsoft.com`).
- **Attacker knowledge required:** Victim's corporate email address (`rmendez@meddefense.com`) and basic awareness of standard corporate account security notification templates.
- **Conclusion:** A common credential harvesting pretext leveraging fear of unauthorized account access to bypass security skepticism.

---

## Email 5 — Invoice lure
- **Psychological lever:** Financial Pressure, Authority, Urgency
- **Pretext:** Accounts Payable must review and settle an attached medical supply invoice (`INV-2026-04891`) for $24,716.38 within 7 days to avoid delivery suspension and late fees.
- **Requested action:** Open the PDF attachment, click the external payment link, or log into an external billing portal.
- **Targeting level:** TARGETED
- **Pretext details:** Specifically addresses Accounts Payable, references a concrete delivery date (April 9, 2026), cites a realistic medical equipment supplier name (`medequip-supplies.net`), and includes an attachment with a dynamic link.
- **Content red flags:** Unsolicited high-value invoice demanding rapid payment, external payment URLs differing from standard vendor procedures, and authentication softfails/failures.
- **Attacker knowledge required:** Identification of Accounts Payable personnel (`arivera@meddefense.com`), knowledge of active supply chain vendors used by healthcare organizations, and standard invoice formatting.
- **Conclusion:** A sophisticated business email compromise (BEC) / invoice fraud lure designed to manipulate financial workflows and induce fraudulent wire transfers or document interaction.

---

## Email 7 — HR benefits open enrollment notice
- **Psychological lever:** Urgency, Fear of Loss, Authority (impersonating HR)
- **Pretext:** Open enrollment closes at midnight tomorrow, and failing to act will cause current health coverage to lapse and default to a basic plan until November.
- **Requested action:** Click the `COMPLETE ENROLLMENT` button on an external portal.
- **Targeting level:** SEMI-TARGETED
- **Content red flags:** Extreme deadline pressure ("tomorrow"), severe negative consequences regarding healthcare/benefits continuity, and use of an external lookalike domain (`meddefense-benefits.org`).
- **Attacker knowledge required:** Knowledge of corporate HR cycles (annual open enrollment windows in spring/fall), employee email mapping (`lpatterson@meddefense.com`), and internal terminology.
- **Conclusion:** A timing-sensitive administrative lure designed to exploit seasonal corporate processes, rushing recipients past normal security checks during high-stress periods.
