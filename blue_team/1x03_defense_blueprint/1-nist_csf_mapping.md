# NIST Cybersecurity Framework (CSF) 2.0 Current Profile
## MedDefense Health Systems
### Project 0x03 – The Defense Blueprint

---

# Executive Summary
This document outlines MedDefense Health Systems' cybersecurity maturity using the **NIST CSF 2.0** six-function model. This assessment is the culmination of our previous work, grounding our strategy in the reality of our actual environment, known threats, and current vulnerabilities.

**Maturity Scale:**
* **Partial (Tier 1):** Ad-hoc, reactive, inconsistent.
* **Risk Informed (Tier 2):** Policies exist but are not fully implemented.
* **Repeatable (Tier 3):** Documented, consistent, and organization-wide.
* **Adaptive (Tier 4):** Metrics-driven, continuous improvement, automated.

---

# Function 1: GOVERN (GV)
## Current Level: Partial
**Evidence:** We currently lack a formal security policy structure. Security duties are managed informally by a two-person team without Board-level reporting or defined risk acceptance procedures.
**Key Gaps:** Lack of security policies, formal roles, and risk management processes.
**Target Level: Repeatable**
**Justification:** Within 6 months, we will implement a NIST-aligned strategy, define clear roles, and establish a repeatable risk register process for Board review.

---

# Function 2: IDENTIFY (ID)
## Current Level: Partial
**Evidence:** We have successfully built our first asset inventory. However, we still lack continuous discovery and automated risk assessment.
**Key Gaps:** No centralized, automated inventory or vulnerability management lifecycle.
**Target Level: Repeatable**
**Justification:** We will implement a schedule for vulnerability scanning and threat intelligence integration, ensuring our security decisions are data-driven rather than reactive.

---

# Function 3: PROTECT (PR)
## Current Level: Partial
**Evidence:** Our vulnerability assessment (1x02) highlighted critical failures: flat network architecture, missing MFA, and default medical device credentials.
**Key Gaps:** Insufficient preventive controls (MFA, segmentation, patch management).
**Target Level: Repeatable**
**Justification:** We will prioritize MFA deployment, VLAN segmentation, and centralized patch management as our "must-haves" for a defensible clinical environment.

---

# Function 4: DETECT (DE)
## Current Level: Not Implemented
**Evidence:** We have zero visibility. Without a SIEM, centralized logging, or alert correlation, an attacker could operate undetected for months.
**Key Gaps:** Complete absence of monitoring, alerting, and security operations.
**Target Level: Partial**
**Justification:** A full SOC is out of scope for our current staffing. We will prioritize centralized logging and basic SIEM alerting for our most critical assets.

---

# Function 5: RESPOND (RS)
## Current Level: Not Implemented
**Evidence:** There is no Incident Response Plan. A ransomware event today would result in chaotic, undocumented scrambling rather than a structured recovery.
**Key Gaps:** Lack of documented response playbooks and communication procedures.
**Target Level: Repeatable**
**Justification:** We will develop a core Incident Response Plan and conduct at least one tabletop exercise to ensure the team knows how to react under pressure.

---

# Function 6: RECOVER (RC)
## Current Level: Partial
**Evidence:** Backups exist but are not isolated or rigorously tested. They are currently vulnerable to being encrypted by the same threat actors they are meant to protect against.
**Key Gaps:** Lack of immutable storage and lack of formal recovery objectives (RTO/RPO).
**Target Level: Repeatable**
**Justification:** We will transition to immutable backups and formalize our RTO/RPO objectives, ensuring we can actually recover patient care systems when needed.

---

# Current Profile Summary

| NIST CSF Function | Current | Target (6mo) |
|---|---|---|
| Govern | Partial | Repeatable |
| Identify | Partial | Repeatable |
| Protect | Partial | Repeatable |
| Detect | Not Implemented | Partial |
| Respond | Not Implemented | Repeatable |
| Recover | Partial | Repeatable |

---

# Strategic Conclusion
MedDefense is currently operating on "hope" rather than a security program. Our fragmented activities leave us dangerously exposed in Detection and Incident Response. By targeting **Repeatable** maturity across the board, we are moving from a state of reactive firefighting to a defensible, risk-managed environment. This approach respects our limited staff and budget while providing the governance necessary to satisfy the Board and healthcare regulators.
