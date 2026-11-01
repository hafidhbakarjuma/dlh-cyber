# NIST CSF 2.0 Gap Assessment: MedDefense Health Systems

**Assessment date:** 2026-11-01

**Assessor:** Security Analyst / Compliance Officer

**Framework version:** NIST CSF 2.0

**Regulatory context:** HIPAA Security Rule, 45 CFR Part 164

## Gap Assessment Matrix

| **CSF Function** | **Subcategory** | **Title (abbreviated)** | **Status** | **Evidence Reference** | **Gap Severity** | **Gap Description** | 
| **GOVERN** | GV.OC-01 | Org risk strategy established | Partial | `risk_register_updates.yaml` | High | Risk register exists post-incident; no board-approved risk appetite statement or formal governance charter exists. | 
| **GOVERN** | GV.PO-01 | Cybersecurity policy established | Not Implemented | None | Critical | No written Acceptable Use Policy or Data Classification Policy exists; legacy policies unreviewed since 2021. | 
| **GOVERN** | GV.SC-04 | Suppliers inventoried by criticality | Not Implemented | None | High | Vendor inventory is informal; ePHI-adjacent vendors such as CloudVault Medical are not catalogued or risk-tiered. | 
| **GOVERN** | GV.SC-07 | Supplier risks in risk register | Not Implemented | None | High | CloudVault backup risks and supply chain exposures are not documented in the formal risk register. | 
| **IDENTIFY** | ID.AM-01 | Asset inventory maintained | Partial | `endpoint_hardening_baseline.md` | Medium | Workstation hardening baseline covers clinical endpoints, but network devices, cloud assets, and medical IoT remain uninventoried. | 
| **IDENTIFY** | ID.RA-01 | Vulnerabilities identified and recorded | Implemented | `risk_register_updates.yaml`; `forensic_findings_summary.md` | None | Root cause vulnerability analysis and technical weaknesses documented post-incident in risk register and forensic report. | 
| **IDENTIFY** | ID.RA-06 | Risk responses tracked | Partial | `risk_treatment_plan.md` | Medium | Post-incident risk treatment plan defines mitigation steps, but lacks formal ongoing review cadence and executive governance sign-off. | 
| **PROTECT** | PR.AA-01 | Identity and credential management | Partial | `endpoint_hardening_baseline.md`; `ir_playbook_index.md` | High | LAPS and credential dump protections are active on endpoints, but no organization-wide IAM policy or periodic access review exists. | 
| **PROTECT** | PR.AA-05 | Access permissions reviewed | Not Implemented | None | High | Access rights were assigned ad-hoc during system deployment without scheduled user access recertifications. | 
| **PROTECT** | PR.AT-01 | Security awareness training conducted | Partial | `security_awareness_training_status.md` | Critical | Phishing and compliance training completion rates fall significantly short of mandated targets, specifically within clinical departments. | 
| **PROTECT** | PR.DS-01 | Data-at-rest protected | Implemented | `endpoint_hardening_baseline.md` | None | BitLocker full-disk encryption enforced on all clinical endpoints with AES-256 and central recovery key escrow. | 
| **PROTECT** | PR.PS-01 | Configuration baselines maintained | Implemented | `endpoint_hardening_baseline.md` | None | Documented enterprise baseline applied via GPO for Windows clinical workstations, disabling insecure protocols. | 
| **PROTECT** | PR.PS-04 | Log delivery to SIEM maintained | Implemented | `sigma_detection_catalog.md` | None | Windows Event Logs, Sysmon, and PowerShell logs are centrally ingested into SIEM with active Sigma detection coverage. | 
| **DETECT** | DE.CM-01 | Network and host logs monitored | Implemented | `sigma_detection_catalog.md` | None | Centralized logging active across endpoints; automated Sigma rules monitor for LSASS dumping, credential access, and unauthorized execution. | 
| **DETECT** | DE.CM-06 | Service provider monitoring | Not Implemented | None | High | CloudVault Medical log integration into local SIEM is unconfigured; vendor activity is completely unmonitored. | 
| **DETECT** | DE.AE-02 | Adverse events analyzed | Implemented | `forensic_findings_summary.md`; `sigma_detection_catalog.md` | None | Incident forensics performed and detection rules tuned to detect known adversary techniques (T1003, T1059). | 
| **RESPOND** | RS.MA-01 | Incident response playbooks executed | Implemented | `ir_playbook_index.md` | None | Formal playbooks established and tested for ransomware, credential exposure, and clinical workstation isolation. | 
| **RESPOND** | RS.AN-03 | Forensic analysis executed | Implemented | `forensic_findings_summary.md` | None | Root cause forensic investigation completed post-incident, documenting timeline, artifacts, and attacker TTPs. | 
| **RESPOND** | RS.CO-02 | Stakeholders notified during IR | Partial | `ir_playbook_index.md` | Medium | IR playbooks detail internal escalation paths, but lack formal procedures for regulatory breach notification to HHS OCR. | 
| **RECOVER** | RC.RP-01 | Recovery plan executed | Partial | `recovery_validation_summary.md` | High | Recovery validation script executed for endpoint restoration, but enterprise BC/DR plan and RTO/RPO targets are unwritten. | 
| **RECOVER** | RC.CO-01 | Recovery communications managed | Partial | `recovery_validation_summary.md` | Medium | Technical recovery status communicated to IT leadership during incident; formal executive and public communication plans are absent. | 

## Summary

**Implementation counts:**

* **Implemented:** 7

* **Partial:** 8

* **Not Implemented:** 6

**Top 3 pre-audit priorities:**

1. **GV.PO-01 (Critical):** Formalize and enforce core security governance policies (Acceptable Use, Data Classification, Vendor Management) prior to auditor arrival.

2. **PR.AT-01 (Critical):** remediate security awareness training gaps across clinical personnel to comply with mandatory HIPAA administrative safeguards.

3. **GV.SC-04 / GV.SC-07 (High):** Perform a structured vendor risk assessment for CloudVault Medical, execute a Business Associate Agreement (BAA), and record findings in the risk register.

**Connection to upcoming governance work:**

The Critical and High gaps identified in this matrix highlight a systemic issue: MedDefense possesses strong technical security controls (such as endpoint baselines, Sigma detection rules, and incident response playbooks), but lacks the formal governance framework required to prove compliance to external auditors. Without written, executive-approved policies, documented vendor risk assessments, and enforceable training mandates, technical controls cannot survive an OCR desk audit. The subsequent deliverables in this project—specifically drafting the missing security policies, performing the CloudVault vendor assessment, and assembling the CISO briefing package—will directly resolve these foundational gaps.