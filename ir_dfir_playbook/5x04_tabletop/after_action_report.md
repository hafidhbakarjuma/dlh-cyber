# After-Action Report: Nexus Supply Chain Compromise Tabletop

**Exercise date:** 2026-10-25  
**Report date:** 2026-10-26  
**Facilitator:** Incident Response Lead  
**Participants:** James Chen (SOC Lead), Sarah Park (IT Director), Dr. Patricia Morales (CEO), Helena Reyes (General Counsel), Marcus Webb (Third-Party Risk), Robert Kim (Database Administrator), Clinical Director representative  
**Classification:** Internal - Exercise Use Only  

---

## Executive summary

The Nexus Supply Chain Compromise tabletop exercise successfully stress-tested MedDefense's executive leadership, security, legal, and clinical teams under simulated pressure from an active Business Associate compromise. The exercise evaluated eight core capabilities spanning supply chain detection, vendor communication, business continuity trade-offs, PHI scoping, HIPAA breach posture, and crisis communication. 

The most significant gaps identified were the initial hesitation of teams when confronting cryptographically signed vendor updates, the procedural deadlock between security containment and clinical scheduling continuity, and the lack of pre-established audit checklists for data integrity across Epic FHIR API integrations. The single most important recommended action is to co-author an emergency SaaS shutdown protocol and clinical downtime procedure with explicit executive decision thresholds within 14 days.

---

## Findings table

| ID | Inject | Capability tested | Gap description | Severity | Recommended action | Owner role | Deadline | Validation method |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| F-001 | INJ-01 | supply_chain_detection | Team hesitated to isolate host systems because the malicious update package carried a valid cryptographic signature from Nexus. | P1 | Update software supply chain incident playbook to mandate immediate host isolation whenever a vendor issues a build pipeline compromise bulletin. | IR Lead / IT Director | 10 days | Playbook review + policy sign-off |
| F-002 | INJ-03 | business_continuity_decision | Severe operational deadlock occurred between security containment and clinical scheduling due to the absence of a pre-approved downtime protocol. | P1 | Co-author a mandatory clinical downtime procedure defining exact fallback steps and emergency SaaS disconnect decision thresholds. | Clinical Director / IT Director | 14 days | SOP sign-off + table simulation |
| F-003 | INJ-04 | hipaa_notification_posture | Compliance and legal teams initially assumed third-party vendor breaches insulate MedDefense from direct HIPAA notification duties. | P1 | Revise HIPAA Incident Response SOP to clarify that covered entities maintain independent breach assessment and notification obligations. | Legal Counsel / Privacy Officer | 7 days | Compliance review + sign-off |
| F-004 | INJ-05 | data_integrity_response | Response team suffered confidentiality tunnel vision, failing to investigate data integrity risks and appointment record modifications. | P2 | Incorporate database integrity auditing and clinical schedule verification checkpoints into API compromise response checklists. | Database Administrator / Clinical Director | 10 days | Checklist audit |
| F-005 | INJ-02 | vendor_communication | Organization lacked an established escalation path for third-party security breaches, relying on routine support channels. | P2 | Establish a dedicated third-party security incident escalation checklist within the BAA management framework. | Third-Party Risk Manager | 21 days | Vendor escalation test |
| F-006 | INJ-07 | executive_briefing_under_pressure | Executive brief focused on raw technical logs rather than business risk, and team caved to vendor pressure to reconnect prematurely. | P2 | Establish a mandatory Board-level executive summary template and strict go/no-go vendor reconnection gate requiring independent security sign-off. | IR Lead / Executive Sponsor | 7 days | Template review |

---

## P1 Finding narratives

### F-001: Hesitation in Responding to Signed Supply Chain Updates
During INJ-01, when confronted with an active C2 beaconing alert stemming from a software update distributed by Nexus, participants exhibited hesitation and slowed containment actions because the binary carried a valid cryptographic signature from the vendor. This observed behavior demonstrates a dangerous assumption flaw: trusting that code-signing certificates cannot be compromised by an APT group. In a real incident, this delay allows threat actors lateral movement across internal networks. The recommended action is to update the software supply chain incident playbook to mandate immediate host isolation and certificate revocation checks whenever a vendor issues a build pipeline compromise bulletin, regardless of cryptographic signature validity.

### F-002: Operational Deadlock Between Security Isolation and Clinical Continuity
During INJ-03, security's recommendation to immediately isolate Nexus agent hosts caused an intense operational deadlock with the Clinical Director, who argued that halting automated appointment processing for 3,500 weekly patients created severe patient safety risks. Because MedDefense lacked a pre-approved emergency downtime protocol or predefined decision thresholds for third-party SaaS disconnects, leadership was forced to negotiate basic operational procedures under active incident pressure. The recommended action is to co-author a mandatory clinical downtime procedure with the Clinical Director that defines exact paper-based fallback steps and clear decision-making authority for emergency SaaS disconnects.

### F-003: Misunderstanding of Covered Entity HIPAA Notification Obligations
During INJ-04, upon discovering an unencrypted CSV export and a 1.2 GB outbound exfiltration transfer, legal and compliance participants initially questioned whether MedDefense needed to initiate breach scoping independently or wait for Nexus to self-report. This revealed a critical misunderstanding of regulatory posture: the assumption that a Business Associate breach shields the Covered Entity from direct notification duties. Under the HIPAA Breach Notification Rule, MedDefense holds independent 60-day reporting obligations. The recommended action is to revise the HIPAA Incident Response SOP to explicitly clarify independent regulatory notification clocks and assessment duties regardless of vendor self-reporting timelines.

---

## What worked

* **Executive Incident Command & Ownership:** Dr. Patricia Morales (CEO) and James Chen (SOC / IR Lead) established clear incident command rapidly during INJ-00, formally declaring SEV-2/SEV-1 severity levels and assigning roles within the required initial windows.
* **Rapid Epic API Token Revocation:** Upon discovering that the Nexus FHIR API service account held excessive direct write permissions during INJ-02, the Database Administrator and IR lead acted swiftly to revoke API secrets and halt external write access before further schedule tampering occurred.
* **Effective Crisis Public Relations Response:** During INJ-06, the Communications Director and Legal Counsel successfully drafted, vetted, and released a precise holding statement within the reporter's 30-minute deadline while maintaining operational transparency and avoiding premature vendor naming or unverified leakage metrics.

---

## Exercise design feedback

* **Shift Data Integrity Awareness to Earlier Inject:** Modify INJ-01 situation text to include secondary indicators regarding anomalous timestamp modifications in automated FHIR write logs, ensuring data integrity risks inform early business continuity decisions.
* **Clarify BAA Escalation Contacts in Scenario Materials:** Update `exercise_scenario.md` and `nexus_vendor_profile.md` to explicitly separate routine vendor account management contacts from emergency BAA and legal escalation pathways, eliminating procedural confusion during inject execution.
* **Tighten Evaluation Criteria for Crisis Holding Statements:** Update `evaluation_criteria.yaml` under INJ-06 to explicitly require that pass criteria include a formal legal assessment of BAA confidentiality clauses regarding naming third-party vendors during active public media inquiries.
