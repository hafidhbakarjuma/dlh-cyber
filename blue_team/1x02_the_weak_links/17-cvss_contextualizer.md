# 17. The CVSS Contextualizer: Environmental Priorities

## Finding 001
* **CVSS Base Score**: 9.8
* **Asset Criticality**: FortiGate 100F (CIA: High)
* **Kill Chain Position**: Initial Access
* **Exploitability**: 5 (CISA KEV: Yes)
* **Compensating Controls**: None
* **Environmental CVSS (Adjusted)**: 10.0
* **Final Priority**: Critical
* **Final Justification**: As an internet-facing initial access point with a known CISA KEV exploit, the lack of compensating controls makes this a top-tier threat, justifying an increase from its base score.

---
## Finding 002
* **CVSS Base Score**: 10.0
* **Asset Criticality**: Domain Controller (DC-01) (CIA: Critical)
* **Kill Chain Position**: Lateral Movement/Persistence
* **Exploitability**: 5 (CISA KEV: Yes)
* **Compensating Controls**: Internal segmentation (Partial)
* **Environmental CVSS (Adjusted)**: 9.6
* **Final Priority**: Critical
* **Final Justification**: The asset is mission-critical; however, partial segmentation slightly lowers the risk of immediate global propagation, keeping the score critical but recognizing minor mitigation.

---
## Finding 003
* **CVSS Base Score**: 9.8
* **Asset Criticality**: EHR-SRV-01 (CIA: Critical)
* **Kill Chain Position**: Final Target
* **Exploitability**: 5 (CISA KEV: Yes)
* **Compensating Controls**: None
* **Environmental CVSS (Adjusted)**: 10.0
* **Final Priority**: Critical
* **Final Justification**: EHR compromise represents the highest potential impact for data breach; with no effective controls, the score remains at the absolute maximum.

---
## Finding 004
* **CVSS Base Score**: 9.8
* **Asset Criticality**: Workstation-RAD-01 (CIA: High)
* **Kill Chain Position**: Lateral Movement
* **Exploitability**: 4
* **Compensating Controls**: None
* **Environmental CVSS (Adjusted)**: 9.2
* **Final Priority**: High
* **Final Justification**: While RCE on a radiology workstation is high-risk, its role as a pivot point rather than a target lowers the immediate urgency slightly compared to the EHR/DC.

---
## Finding 006
* **CVSS Base Score**: 8.8
* **Asset Criticality**: Medical-IoT-Gateway (CIA: High)
* **Kill Chain Position**: Initial Access
* **Exploitability**: 3
* **Compensating Controls**: None
* **Environmental CVSS (Adjusted)**: 9.1
* **Final Priority**: High
* **Final Justification**: Hard-coded credentials on an IoT gateway provide an unauthenticated backdoor into the internal network, significantly raising the risk profile beyond the base score.

---
## Finding 008
* **CVSS Base Score**: 7.5
* **Asset Criticality**: BD-Alaris-01 (CIA: Critical)
* **Kill Chain Position**: Final Target
* **Exploitability**: 4
* **Compensating Controls**: None
* **Environmental CVSS (Adjusted)**: 9.4
* **Final Priority**: Critical
* **Final Justification**: The patient safety impact elevates this vulnerability's priority far beyond the standard IT-based base CVSS score.

---
## Finding 009
* **CVSS Base Score**: 7.5
* **Asset Criticality**: BD-Alaris-02 (CIA: Critical)
* **Kill Chain Position**: Final Target
* **Exploitability**: 4
* **Compensating Controls**: None
* **Environmental CVSS (Adjusted)**: 9.4
* **Final Priority**: Critical
* **Final Justification**: Similar to 008, the direct patient safety risk justifies a major upward adjustment from the base CVSS.

---
## Finding 031
* **CVSS Base Score**: 9.8
* **Asset Criticality**: EHR-SRV-01 (CIA: Critical)
* **Kill Chain Position**: Final Target
* **Exploitability**: 5
* **Compensating Controls**: None
* **Environmental CVSS (Adjusted)**: 9.8
* **Final Priority**: Critical
* **Final Justification**: This confirms the Ghostcat impact already identified in finding 003; the base score accurately reflects the critical risk to the organization.

---

## Priority Comparison Table

| Finding | Base Score | Adjusted Priority | Change Direction |
| --- | --- | --- | --- |
| 001 | 9.8 | Critical | Higher |
| 002 | 10.0 | Critical | Lower |
| 003 | 9.8 | Critical | Higher |
| 004 | 9.8 | High | Lower |
| 006 | 8.8 | High | Higher |
| 008 | 7.5 | Critical | Higher |
| 009 | 7.5 | Critical | Higher |
| 031 | 9.8 | Critical | Same |
