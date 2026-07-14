# The Human Vector — MedDefense Social Engineering Analysis

## Project Goal

Analyze social engineering attack scenarios targeting the MedDefense healthcare environment. The objective is to identify the attack vector, understand why employees may be vulnerable, recognize psychological manipulation techniques, identify warning signs, and recommend technical and administrative controls.

Social engineering attacks exploit human behavior rather than technical vulnerabilities. In healthcare environments, attackers target employees because staff members regularly handle sensitive information, respond to urgent requests, and have access to critical systems.

---

# Scenario 1: Fake FortiGate Support Email

## Vector Type

**Phishing**

## Target

**Sarah Park — IT Director**

Sarah is targeted because she has administrative responsibility for network infrastructure and security systems. Attackers know IT staff are more likely to receive security alerts and may respond quickly to urgent vulnerability notifications.

## Psychological Lever

**Urgency + Fear**

The attacker creates pressure by claiming a critical vulnerability exists and that failure to patch within 24 hours will cause service termination.

## Red Flags

- Sender domain is `fortinet-support.net` instead of the official Fortinet domain.
- The message creates unrealistic urgency with a 24-hour deadline.
- The email asks the user to download a patch from an external link.

## Technical Control

Implement secure email filtering with anti-phishing protection, domain reputation checks, and attachment/link sandboxing.

## Administrative Control

Require a security verification process where all vendor security notifications are validated through official vendor channels before action is taken.

---

# Scenario 2: Fake CEO Wire Transfer Request

## Vector Type

**Business Email Compromise (BEC)**

## Target

**Robert Kim — CFO**

The CFO is targeted because financial employees have authority to approve payments and handle confidential transactions. Attackers exploit their responsibility and access to financial systems.

## Psychological Lever

**Authority + Urgency**

The attacker impersonates the CEO and creates pressure by requesting a confidential emergency payment.

## Red Flags

- Sender email address contains a subtle spelling difference.
- Request bypasses normal approval procedures.
- The message demands secrecy and refuses normal communication channels.

## Technical Control

Implement email authentication protections such as SPF, DKIM, and DMARC to reduce spoofed email attacks.

## Administrative Control

Require verbal confirmation and dual approval for large financial transactions or unusual payment requests.

---

# Scenario 3: Fake IT Support Phone Call

## Vector Type

**Vishing**

## Target

**Nurse at MedDefense Central**

Clinical staff are vulnerable because they are focused on patient care and are trained to cooperate with IT and support teams when systems have problems.

## Psychological Lever

**Authority + Helpfulness**

The attacker pretends to be IT staff performing a security audit to convince the nurse to provide credentials.

## Red Flags

- Caller requests a password.
- Caller creates a false emergency situation.
- Caller cannot verify their identity through official channels.

## Technical Control

Implement Multi-Factor Authentication (MFA) so stolen passwords alone cannot provide access.

## Administrative Control

Create a policy stating that IT staff will never request passwords from employees by phone, email, or chat.

---

# Scenario 4: Fake Parking Permit SMS

## Vector Type

**Smishing**

## Target

**All MedDefense Employees**

Employees are targeted because parking and HR-related messages appear familiar and affect daily activities, increasing the chance that someone clicks without thinking.

## Psychological Lever

**Urgency + Fear**

The attacker threatens towing or loss of parking access if employees do not act immediately.

## Red Flags

- Unexpected SMS containing a link.
- The message creates immediate consequences.
- The website requests Active Directory credentials.

## Technical Control

Deploy mobile security protections and web filtering to block known malicious domains.

## Administrative Control

Create employee awareness training explaining that HR, parking, and IT services will not request credentials through text messages.

---

# Scenario 5: Compromised Healthcare Association Website

## Vector Type

**Watering Hole Attack**

## Target

**MedDefense Physicians and Clinical Staff**

Doctors are targeted because they regularly visit healthcare industry websites for continuing medical education (CME) and professional resources.

## Psychological Lever

**Familiarity + Trust**

The attacker compromises a website that employees already trust, making the malicious content appear legitimate.

## Red Flags

- Website behavior changes unexpectedly.
- Browser redirects occur without user action.
- Security warnings or unusual download prompts appear.

## Technical Control

Maintain updated browser security controls, endpoint protection, and web filtering.

## Administrative Control

Require regular security awareness training explaining that trusted websites can also become compromised.

---

# Scenario 6: Fake MedDefense Patient Portal

## Vector Type

**Brand Impersonation + Typosquatting**

## Target

**Patients and MedDefense Employees**

The attacker targets users searching for the patient portal because they trust the MedDefense brand and may not carefully inspect website addresses.

## Psychological Lever

**Familiarity + Trust**

The fake website uses MedDefense branding to appear legitimate.

## Red Flags

- Domain name is slightly different (`meddefence-portal.com`).
- Website appears through paid advertisements instead of the official portal.
- Login page requests credentials on an unfamiliar domain.

## Technical Control

Implement domain monitoring to detect fake domains and use DMARC protections against brand abuse.

## Administrative Control

Publish official portal URLs clearly and educate users to avoid accessing portals through search advertisements.

---

# Scenario 7: Fake Hospital Employee Tailgating

## Vector Type

**Impersonation**

## Target

**MedDefense IT Department Staff**

IT staff are targeted because they work in restricted areas containing valuable infrastructure and sensitive systems.

## Psychological Lever

**Helpfulness + Familiarity**

The attacker uses hospital clothing, equipment, and a friendly request to convince employees to allow access.

## Red Flags

- Person does not have a visible valid badge.
- Visitor badge is expired or hidden.
- Individual follows another employee through a secured door.

## Technical Control

Use badge access monitoring with door alerts and security cameras covering restricted areas.

## Administrative Control

Enforce a strict tailgating policy requiring employees to challenge unknown individuals entering restricted areas.

---

# Pattern Assessment

The main weakness exploited by social engineering attacks at MedDefense is the organization's dependence on human trust and urgency-based decision making.

Healthcare employees operate in a high-pressure environment where helping others quickly is part of their daily responsibility. Attackers exploit this behavior by creating fake emergencies, impersonating authority figures, and abusing familiar healthcare workflows.

These scenarios connect to existing MedDefense gaps:

1. **G-002 — Lack of administrative detective processes**

MedDefense lacks proactive processes such as phishing simulations, security reviews, and regular testing of employee behavior.

2. **G-004 / GAP-005 — Weak logging and monitoring**

Without centralized monitoring and behavioral analysis, compromised accounts may remain undetected.

3. **GAP-012 — Security awareness training has low completion and no phishing simulation program**

Employees remain vulnerable because security awareness is not reinforced through realistic testing.

The organization must treat employees as part of the security defense strategy by combining technical controls with continuous security awareness programs.

---

# Recommended Security Improvements

1. Implement phishing simulation campaigns.
2. Deploy email security filtering and DMARC protection.
3. Enforce MFA for all accounts.
4. Create verification procedures for financial requests.
5. Train employees to identify phishing, vishing, and smishing attacks.
6. Monitor and remove malicious domains impersonating MedDefense.
7. Improve physical security awareness and anti-tailgating procedures.
8. Establish a security culture where employees can verify suspicious requests without pressure.
