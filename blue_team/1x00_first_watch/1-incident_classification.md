# MedDefense — Incident Classification Using the CIA Triad

**Source:** Marcus Webb's Incident Log, Last 6 Months (from onboarding packet)
**Framework:** Confidentiality / Integrity / Availability

| Incident | Date | Primary Pillar | Justification | Secondary Pillar | Justification |
|---|---|---|---|---|---|
| A — Ransomware on billing-srv-01 | Jan 15 | Availability | The finance team was unable to process insurance claims for 4 days because the billing server was encrypted and inaccessible. | None | The log confirms encryption and downtime, but does not indicate any data was altered in a way that affected accuracy, or that data was exfiltrated — the evidenced impact is loss of access, not a second confirmed pillar. |
| B — Patient portal IDOR | Feb 2 | Confidentiality | A broken access control allowed an authenticated patient to view another patient's lab results by modifying a URL parameter — PHI was accessed by someone with no authorization to see it. | None | No system or data was modified, and no service went down; the impact is isolated to unauthorized disclosure. |
| C — Pharmacy dosage bug | Mar 18 | Integrity | A faulty database update script altered dosage values so they no longer matched the correct reference data, for approximately 6 hours across all three sites. | None | The system remained accessible throughout (a pharmacist was able to view and catch the error); the failure is in data accuracy, not access. |
| D — Website defacement | Apr 5 | Integrity | The homepage content was replaced without authorization with a political message. | Availability | The legitimate site was non-functional/untrustworthy for the ~2-hour window until restoration from backup, representing a secondary loss of accessible, correct service. |
| E — EHR migration outage | May 22 | Availability | The EHR system was inaccessible for 9 hours due to an over-running planned migration with an untested rollback procedure, forcing a shift to paper records. | None | The migration was an authorized, planned action; there is no evidence of unauthorized access or data modification, only a loss of access. |
| F — Intern laptop on internal network | Jun 10 | Confidentiality | An unmanaged personal device sat on the internal network (same segment as the HR file share) for 3 weeks, meaning any data on that segment was exposed to a device MedDefense never approved or controlled. | None | The log confirms the device's presence and its outward file-sharing activity, but does not confirm that HR or patient data itself was actually accessed or exfiltrated — the evidenced impact stops at exposure, not confirmed compromise. |

## Notes on Method

- Primary pillar reflects the CIA property that was actually broken by the incident's observed outcome, not the mechanism that caused it. Incident C shows this clearly: a bug, not an attacker, still produces an Integrity classification, because CIA classification is outcome-based, not intent-based.
- Secondary pillar is only assigned where the log provides direct evidence of a second impact (Incident D is the only case that meets this bar). Incidents A and F both have plausible paths to a second pillar — exfiltration before encryption, or malware spreading from the laptop — but the log does not confirm either occurred, so only the single evidenced pillar is rated for each. Overstating secondary impact based on what could have happened would misrepresent the actual incident.
- Incidents A and E both center on Availability but have different root causes (malicious attack vs. authorized-but-poorly-executed change) — a reminder that CIA classification categorizes impact, while root cause and control failure are separate layers of analysis, addressed in later tasks.
