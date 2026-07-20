# 1. Gap-to-Framework Bridge
## MedDefense Health Systems
### Project 0x03 – The Defense Blueprint

---

# Executive Summary

This document creates a traceability chain between MedDefense's identified security gaps, technical vulnerabilities, threat scenarios, and security frameworks[cite: 3].

**Gap → Vulnerability → Threat → NIST CSF Function → CIS Control → Recommended Action**

Framework alignment[cite: 3]:

- **NIST CSF 2.0** defines the cybersecurity outcome required.
- **CIS Controls v8** defines the technical implementation approach.

---

# Traceability Summary Table

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

# 2. The Governance Architecture: MedDefense Health Systems

# Part 1: RACI Matrix

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

# Part 2: Role Definitions

| Role | Position | Definition | Justification |
| :--- | :--- | :--- | :--- |
| **Data Owner** | Dept Heads | Ultimately responsible for the data's integrity and classification. | As medical experts, they best understand the clinical criticality of patient records. |
| **Data Controller** | CEO | Decides the purpose and means of data processing. | As the entity head, the CEO bears the ultimate legal and fiscal responsibility for HIPAA compliance. |
| **Data Processor** | IT Director | Manages the systems that store and process the data. | IT manages the underlying infrastructure where clinical data resides. |
| **Data Custodian** | Security Analyst | Implements the security controls to protect the data. | The Security Analyst ensures technical safeguards are operational. |

# Part 3: The CISO Question

### Consequences of a Vacant CISO Position
The absence of a full-time CISO creates a "governance vacuum" where security strategy is relegated to tactical, reactive firefighting rather than proactive risk management[cite: 5]. Without a dedicated CISO, MedDefense lacks the authoritative voice required to hold Department Heads accountable for risk and fails to bridge the gap between technical operations and Board-level risk appetite[cite: 5].

### Recommendation: vCISO
MedDefense should outsource this function to a **virtual CISO (vCISO)**. Given severe budget constraints (only $15,000 remaining from the $120,000 allocation), hiring a full-time CISO is financially unfeasible[cite: 5]. A vCISO provides strategic oversight, policy development, and Board reporting for a fraction of the cost, allowing limited funds to be directed toward high-impact technical remediation[cite: 5].

---

# 3. Quantitative Risk Analysis: MedDefense Health Systems

## Scenario: Billing Ransomware
- **AV (Asset Value)**: $473,000.00[cite: 6]
- **SLE (Single Loss Expectancy)**: $473,000.00[cite: 6]
- **ARO (Annualized Rate of Occurrence)**: 0.28[cite: 6]
- **ALE (Annualized Loss Expectancy)**: $132,440.00[cite: 6]

## Scenario: Patient Data Breach
- **AV (Asset Value)**: $9,075,000.00[cite: 6]
- **SLE (Single Loss Expectancy)**: $9,075,000.00[cite: 6]
- **ARO (Annualized Rate of Occurrence)**: 0.33[cite: 6]
- **ALE (Annualized Loss Expectancy)**: $2,994,750.00[cite: 6]

## Scenario: Insider Data Theft
- **AV (Asset Value)**: $120,000.00[cite: 6]
- **SLE (Single Loss Expectancy)**: $120,000.00[cite: 6]
- **ARO (Annualized Rate of Occurrence)**: 2.5[cite: 6]
- **ALE (Annualized Loss Expectancy)**: $300,000.00[cite: 6]

## Scenario: Medical Device (Aggregate)
- **AV (Asset Value)**: $5,455,000.00[cite: 6]
- **SLE (Single Loss Expectancy)**: $5,455,000.00[cite: 6]
- **ARO (Annualized Rate of Occurrence)**: 0.03[cite: 6]
- **ALE (Annualized Loss Expectancy)**: $163,650.00[cite: 6]

## Scenario: VPN Compromise (Gateway)
- **AV (Asset Value)**: $9,548,000.00[cite: 6]
- **SLE (Single Loss Expectancy)**: $9,548,000.00[cite: 6]
- **ARO (Annualized Rate of Occurrence)**: 0.33[cite: 6]
- **ALE (Annualized Loss Expectancy)**: $3,150,840.00[cite: 6]
