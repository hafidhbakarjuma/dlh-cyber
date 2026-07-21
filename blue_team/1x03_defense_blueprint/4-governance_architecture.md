# The Governance Architecture: MedDefense Health Systems

Project 0x03 – The Defense Blueprint

---

## Part 1: RACI Matrix

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

---

## Part 2: Role Definitions

| Role | Position | Definition | Justification |
| :--- | :--- | :--- | :--- |
| Data Owner | Department Heads | The business-side individual accountable for classifying data, deciding who may access it, and approving exceptions. | As medical experts, they best understand the clinical criticality of patient records (e.g., Dr. Patel for Cardiology). |
| Data Controller | CEO / Board | The legal entity that determines why and how patient data is processed overall. | Holds ultimate legal and regulatory responsibility as the HIPAA Covered Entity. |
| Data Processor | Third-Party Vendors | Entities that handle MedDefense data under contract (e.g., MedTech, Microsoft, Siemens). | They act only on the Controller's instructions and have no independent right to choose data usage. |
| Data Custodian / Steward | IT Director & Security Analyst | Implements and maintains technical safeguards and data quality to execute the Data Owner's classification rules. | Sarah manages infrastructure custody while the analyst oversees day-to-day data governance. |

---

## Part 3: The CISO Question

### Consequences of a Vacant CISO Position

The absence of a full-time CISO creates a governance vacuum where security strategy is relegated to tactical firefighting rather than proactive risk management. Without a dedicated CISO, MedDefense lacks the authoritative voice required to hold Department Heads accountable for risk, fails to bridge technical operations and Board-level risk appetite, and remains exposed to significant liability in the event of a HIPAA audit or ransomware incident. Left unresolved, this vacant state leads to slower incident response and inconsistent risk acceptance.

### Recommendation: vCISO

MedDefense should outsource this function to a virtual CISO (vCISO) rather than making a full-time executive hire. Given severe budget constraints, a full-time hire would consume the majority of the $120,000 technical remediation budget, leaving insufficient funds for critical fixes like network segmentation and backup isolation. A vCISO provides necessary strategic oversight, policy approval, and Board-level reporting for a fraction of the cost, preserving resources for technical execution.
