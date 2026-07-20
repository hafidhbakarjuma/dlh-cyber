# The Governance Architecture: MedDefense Health Systems
## Project 0x03 – The Defense Blueprint

---

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

*Key: R = Responsible, A = Accountable, C = Consulted, I = Informed*

---

# Part 2: Role Definitions

| Role | Position | Definition | Justification |
| :--- | :--- | :--- | :--- |
| **Data Owner** | Dept Heads | Ultimately responsible for the data's integrity and classification. | As medical experts, they best understand the clinical criticality of patient records. |
| **Data Controller** | CEO | Decides the purpose and means of data processing. | As the entity head, the CEO bears the ultimate legal and fiscal responsibility for HIPAA compliance. |
| **Data Processor** | IT Director | Manages the systems that store and process the data. | IT manages the underlying infrastructure where clinical data resides. |
| **Data Custodian** | Security Analyst | Implements the security controls to protect the data. | The Security Analyst ensures technical safeguards (firewalls, encryption) are operational. |

---

# Part 3: The CISO Question

### Consequences of a Vacant CISO Position
The absence of a full-time CISO creates a "governance vacuum" where security strategy is relegated to tactical, reactive firefighting rather than proactive risk management. Without a dedicated CISO, MedDefense lacks the authoritative voice required to hold Department Heads accountable for risk, fails to effectively bridge the gap between technical operations and Board-level risk appetite, and remains exposed to significant liability in the event of a HIPAA audit or catastrophic ransomware incident.

### Recommendation: vCISO
MedDefense should outsource this function to a **virtual CISO (vCISO)**. Given the severe budget constraints (only $15,000 remaining from the $120,000 allocation), hiring a full-time CISO is financially unfeasible. A vCISO provides the necessary strategic oversight, policy development, and Board reporting capability for a fraction of the cost, allowing the limited remaining budget to be directed toward high-impact technical remediation rather than executive salary overhead.
