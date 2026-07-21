# Comprehensive Security Architecture & Quantitative Analysis: MedDefense Health Systems

## Executive Summary

This document creates a traceability chain between MedDefense's identified security gaps, technical vulnerabilities, threat scenarios, and security frameworks.
Gap → Vulnerability → Threat → NIST CSF Function → CIS Control → Recommended Action
Framework alignment:
NIST CSF 2.0 defines the cybersecurity outcome required.
CIS Controls v8 defines the technical implementation approach.

---

## Traceability Summary Table

| Gap | Vulnerability | Threat | NIST Function | CIS Control | Action |
|---|---|---|---|---|---|
| GAP-015 Missing MFA | Weak authentication | Ransomware affiliates | Protect | CIS 6 Access Control | Deploy MFA |
| GAP-012 Flat Network | Excessive network exposure | BlackReef ransomware | Protect | CIS 12 Network Management | Implement segmentation |
| GAP-011 Patch Management | Critical CVEs | Exploit attackers | Identify / Protect | CIS 7 Vulnerability Management | Deploy patch lifecycle |
| GAP-010 Backup Weakness | Recovery weakness | Ransomware operators | Recover | CIS 11 Data Recovery | Implement immutable backups |
| GAP-013 No IR Plan | No response process | Ransomware / insiders | Respond | CIS 17 Incident Response | Build IR program |
| GAP-001 Medical Devices | Device security weakness | Healthcare attackers | Protect | CIS 1 Asset Inventory | Secure medical devices |
| GAP-008 Shared PACS Login | Weak identity controls | Insider / stolen credentials | Protect | CIS 5 Account Management | Enforce unique accounts |
| GAP-009 Rogue Raspberry Pi | Unknown asset | Insider / attacker | Identify | CIS 1 Asset Inventory | Remove unauthorized assets |

---

## Quantitative Risk Analysis (ALE Calculations & Rationales)

To ensure transparency, every quantitative loss calculation below includes explicit justifications for Asset Value (AV), Exposure Factor (EF), Annualized Rate of Occurrence (ARO), and the critical sensitivity factors that could alter the outcome.

### 1. RISK-001: Ransomware & Backup Destruction (BlackReef Attack)
* **Asset Value (AV)**: $1,675,000 (Based on total enterprise server infrastructure replacement cost and core EHR database reconstruction value).
* **Exposure Factor (EF)**: 85% (Assuming total operational paralysis, extensive data corruption, and comprehensive recovery overhead).
* **Single Loss Expectancy (SLE)**: $1,423,750 ($1,675,000 $\times$ 0.85).
* **Annualized Rate of Occurrence (ARO)**: 0.33 (Estimated at roughly once every 3 years given current flat network exposure and active healthcare threat actor targeting).
* **Annualized Loss Expectancy (ALE)**: $469,837.50 ($1,423,750 $\times$ 0.33).
* **Rationale & Assumptions**: 
  * *Why this AV/ARO*: AV reflects full hardware/data recovery expenses. ARO is high because flat networks and lack of network segmentation expose backups to direct lateral movement.
  * *Sensitivity Factor*: The primary variable that would change this ALE is the successful implementation of air-gapped immutable backups, which would drop the EF from 85% down to 10% (reducing downtime to simple restore operations).

### 2. RISK-002: Remote Access Credential Compromise (VPN Exfiltration)
* **Asset Value (AV)**: $950,000 (Value of intellectual property, patient identity records, and administrative network boundaries).
* **Exposure Factor (EF)**: 40% (Partial compromise involving unauthorized access to perimeter systems and secondary lateral movement).
* **Single Loss Expectancy (SLE)**: $380,000 ($950,000 $\times$ 0.40).
* **Annualized Rate of Occurrence (ARO)**: 0.50 (Once every 2 years, driven by the absolute absence of MFA and credential stuffing susceptibility).
* **Annualized Loss Expectancy (ALE)**: $190,000 ($380,000 $\times$ 0.50).
* **Rationale & Assumptions**:
  * *Why this ARO*: High probability due to standard credential brute-forcing targeting hospital perimeter gateways. Confidence is moderate since external attack frequency depends on active scanning volume.
  * *Sensitivity Factor*: Deploying multi-factor authentication (MFA) immediately reduces ARO to 0.05, effectively neutralizing the vector.

### 3. RISK-003: Core EHR Lateral Movement & Database Lockout
* **Asset Value (AV)**: $2,100,000 (Direct valuation of core clinical patient databases and high-availability clinical systems).
* **Exposure Factor (EF)**: 50% (Partial data destruction and extended emergency care diversion costs).
* **Single Loss Expectancy (SLE)**: $1,050,000 ($2,100,000 $\times$ 0.50).
* **Annualized Rate of Occurrence (ARO)**: 0.25 (Once every 4 years once an initial perimeter breach occurs).
* **Annualized Loss Expectancy (ALE)**: $262,500 ($1,050,000 $\times$ 0.25).
* **Rationale & Assumptions**:
  * *Why this EF*: Selected because flat network architecture allows attackers to pivot directly from administrative workstations to clinical database nodes without encountering internal firewall barriers.
  * *Sensitivity Factor*: Introducing internal VLAN segmentation isolates the clinical database, lowering EF to 5% by trapping intruders in outer segments.

### 4. RISK-004: Negligent Insider Data Leak (Lack of DLP)
* **Asset Value (AV)**: $800,000 (Regulatory exposure under HIPAA and direct notification/reputational costs).
* **Exposure Factor (EF)**: 25% (Scope limited to departmental records rather than enterprise-wide structural collapse).
* **Single Loss Expectancy (SLE)**: $200,000 ($800,000 $\times$ 0.25).
* **Annualized Rate of Occurrence (ARO)**: 1.00 (Expected at least once per year given staff turnover, lack of USB controls, and zero Data Loss Prevention tooling).
* **Annualized Loss Expectancy (ALE)**: $200,000 ($200,000 $\times$ 1.00).
* **Rationale & Assumptions**:
  * *Why this ARO*: High frequency because human error and accidental unencrypted data transfers via removable media are routine occurrences without active prevention controls.
  * *Sensitivity Factor*: Scope of breach notification significantly shifts regulatory fines; targeted user security training and policy enforcement lower ARO to 0.30.

### 5. RISK-005: Undetected Malware Dwell Time (Lack of 24/7 SOC)
* **Asset Value (AV)**: $1,200,000 (Total operational exposure across enterprise endpoints).
* **Exposure Factor (EF)**: 30% (Moderate propagation before discovery via manual log reviews).
* **Single Loss Expectancy (SLE)**: $360,000 ($1,200,000 $\times$ 0.30).
* **Annualized Rate of Occurrence (ARO)**: 0.40 (Once every 2.5 years based on current detection lag).
* **Annualized Loss Expectancy (ALE)**: $144,000 ($360,000 $\times$ 0.40).
* **Rationale & Assumptions**:
  * *Why this ARO*: Without a continuous monitoring solution or 24/7 SOC, malware remains resident for weeks, multiplying lateral infiltration windows.
  * *Sensitivity Factor*: Confidence is moderate because costs depend heavily on the exact dwell time length before manual detection catches anomalous traffic.

---

## The Governance Architecture: MedDefense Health Systems

Project 0x03 – The Defense Blueprint

### Part 1: RACI Matrix

| Activity | CEO | Deputy CISO (James) | IT Director (Sarah) | Dept Heads | Security Analyst |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Security budget approval | A | C | R | I | I |
| Vulnerability remediation | I | R | A | I | R |
| Incident response execution | I | A | R | I | R |
| Security policy approval | A | R | C | C | C |
| Risk acceptance decisions | A | R | C | C | C |
| Security awareness training | I | A | R | R | R |
| Vendor risk assessment | I | R | C | I | R |
| Audit coordination | I | A | C | C | R |

Key: R = Responsible, A = Accountable, C = Consulted, I = Informed

### Part 2: Role Definitions

| Role | Position | Definition | Justification |
| :--- | :--- | :--- | :--- |
| Data Owner | Dept Heads | Ultimately responsible for the data's integrity and classification. | As medical experts, they best understand the clinical criticality of patient records. |
| Data Controller | CEO | Decides the purpose and means of data processing. | As the entity head, the CEO bears the ultimate legal and fiscal responsibility for HIPAA compliance. |
| Data Processor | IT Director | Manages the systems that store and process the data. | IT manages the underlying infrastructure where clinical data resides. |
| Data Custodian / Steward | Security Analyst | Implements the security controls to protect the data. Acts as a data **steward** to oversee data quality, labeling, and day-to-day governance compliance. | The Security Analyst ensures technical safeguards are operational and manages everyday data protection. |

### Part 3: The CISO Question

#### Consequences of a Vacant CISO Position
The absence of a full-time CISO creates a "governance vacuum" where security strategy is relegated to tactical, reactive firefighting rather than proactive risk management. Without a dedicated CISO, MedDefense lacks the authoritative voice required to hold Department Heads accountable for risk, fails to bridge the gap between technical operations and Board-level risk appetite, and remains exposed to significant liability in the event of a HIPAA audit or catastrophic ransomware incident.

#### Recommendation: vCISO
MedDefense should outsource this function to a virtual CISO (vCISO). Given severe budget constraints (only $15,000 remaining from the $120,000 allocation), hiring a full-time CISO is financially unfeasible. A vCISO provides strategic oversight, policy development, and Board reporting capability for a fraction of the cost, allowing the limited remaining budget to be directed toward high-impact technical remediation rather than executive salary overhead.
