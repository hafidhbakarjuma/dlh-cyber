# Campaign Thread Analysis

**Analyst:** SOC Team  
**Date:** 2026-04-17  
**Scope:** Correlation and infrastructure analysis connecting Emails 2, 5, and 7 to determine whether they represent a coordinated phishing campaign against MedDefense Health Systems, benchmarked against federal threat intelligence (Email 8).

---

## Campaign Thread Analysis

### Shared Indicators
A deep-dive comparison of Emails E2, E5, and E7 reveals a tight cluster of overlapping technical, architectural, and operational indicators that tie them to a common threat actor or shared tooling framework:
* **Infrastructure & Tooling:** All three emails were generated using `PHPMailer 6.6.0` (`X-Mailer: PHPMailer 6.6.0`), pointing to automated script-based distribution rather than legitimate corporate mail servers.
* **Hosting & Network Profiles:** Each email originated from unauthenticated external VPS hosting providers running custom mail setups rather than authorized domain infrastructure.
* **Authentication Failures:** All three emails failed DMARC and either failed or soft-failed SPF with zero valid cryptographic signatures (DKIM `none`), demonstrating a complete lack of legitimate domain authorization.
* **Psychological Pressure:** Each message employs strict deadlines (24-hour verification cutoffs, 7-day payment windows, or "tomorrow" deadlines) designed to induce panic and bypass critical thinking.
* **Impersonation Strategy:** The emails leverage lookalike or brand-mimicking domains (`meddefense-portal.com`, `medequip-supplies.net`, `meddefense-benefits.org`) tailored to mirror internal or trusted supply chain entities.

### Targeting Map
The attacker executed a structured, role-specific targeting strategy across different functional departments within MedDefense Health Systems:
* **Email 2:** Targeted **Clinical Staff** (specifically Diane Marsh, `WS-NURSE-04`, Nursing) using an urgent IT security portal re-verification pretext to harvest credentials.
* **Email 5:** Targeted **Finance / Accounts Payable** (Angela Rivera, Accounts Payable) using a high-value medical supply invoice ($24,716.38) and an attached PDF document link to induce financial fraud or business email compromise (BEC).
* **Email 7:** Targeted **Human Resources / Administrative Staff** (Linda Patterson, Billing/Administration) using an annual benefits open enrollment deadline warning to capture authentication tokens.

### Timing Map
The delivery timeline extracted from the raw evidence batch demonstrates a calculated multi-day cadence rather than a single bulk blast:
* **April 14, 2026 (14:47:52 CDT):** Email 2 arrives, targeting clinical operations; clicked by Diane Marsh approximately 15 minutes later (15:02:33 CDT).
* **April 16, 2026 (11:28:39 CDT):** Email 5 arrives, shifting vector to financial and accounts payable operations.
* **April 16, 2026 (15:22:07 CDT):** Email 7 arrives hours later, targeting administrative and benefits systems.

### Comparison With HC3 Alert
The findings map directly to the warnings issued by the U.S. Department of Health and Human Services (HHS) Health Sector Cybersecurity Coordination Center (HC3) in Email 8:
* **Lookalike Domains:** HC3 explicitly warned of newly registered `.com`/`.net`/`.org` domains incorporating terms like `portal`, `benefits`, or `supplies`—matching `meddefense-portal.com`, `medequip-supplies.net`, and `meddefense-benefits.org`.
* **Infrastructure:** HC3 highlighted the use of PHPMailer-based sending infrastructure deployed on budget VPS tier hosting, perfectly mirroring the technical headers of E2, E5, and E7.
* **Urgency & Role-Based Pretexts:** The federal advisory noted 24–48 hour deadlines and role-specific lures targeting clinical, billing, and HR personnel, which precisely matches the observed targeting map at MedDefense.

### Attribution Assessment
* **What can be inferred:** The evidence confirms a disciplined, multi-vector phishing campaign orchestrated by an external adversary with prior knowledge of healthcare operational roles, administrative structures, and seasonal corporate workflows (e.g., benefits open enrollment). The use of shared tooling (`PHPMailer 6.6.0`) and sequential delivery indicates a single adversary or an organized threat group leveraging a modular phishing kit.
* **What cannot be proven:** Specific attribution to a named advanced persistent threat (APT) group, criminal syndicate, or nation-state actor cannot be definitively proven from email headers and basic OSINT alone, as commercial VPS infrastructure and open-source mailers are widely shared and easily spoofed.

### Conclusion
The convergence of shared script tooling, synchronized role-based targeting across clinical, financial, and HR departments, and structural alignment with the HHS HC3 regional healthcare threat brief conclusively demonstrates that **Emails 2, 5, and 7 are part of a single, coordinated phishing campaign** targeting MedDefense Health Systems rather than isolated, random spam incidents.
