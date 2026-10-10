# MedDefense Severity Matrix

## Purpose

Provides a standardized severity language for all MedDefense incidents. Applied from first alert through closure to align technical response with patient safety.

## Severity Matrix

| Level | Patient Safety Impact | Data Exposure | Service Availability | Max Response Time | Decision Authority |
|-------|----------------------|---------------|---------------------|-------------------|-------------------|
| SEV1 | high | confirmed_broad | full_outage | 15 min | CISO |
| SEV2 | moderate | confirmed_limited | partial_outage | 30 min | IR Commander |
| SEV3 | low | suspected | degraded | 60 min | SOC Lead |
| SEV4 | none | none | none | 240 min | SOC Analyst |

## Level Definitions

### SEV1

- Ransomware affecting clinical systems across multiple sites
- Confirmed exfiltration of patient records at scale
- Patient monitoring system offline during active care

### SEV2

- Confirmed compromise of a clinical-access account
- Malware confirmed on a single workstation at a clinical site
- Suspected exfiltration under investigation

### SEV3

- Isolated malware detection neutralized by EDR on a non-clinical workstation
- Unauthorized access attempt blocked on an internal admin portal
- Anomalous outbound traffic pattern from a single test server

### SEV4

- Phishing email reported with no user interaction or credential submission
- Low-risk vulnerability scan finding on an internal non-critical host
- Automated policy violation warning with no malicious intent identified

## Escalation Rule

Severity is actively reviewed and formally re-assessed at every status update cycle during an active incident (every 15–30 minutes for SEV1/SEV2, and hourly for SEV3/SEV4). Movement between levels follows strict operational criteria:

### Upward Escalation Triggers

- **SEV4 to SEV3:** Escalates when initial analysis shows a low-risk finding (such as a reported phishing email) involved actual user interaction, credential entry, or unauthorized access attempts.
- **SEV3 to SEV2:** Escalates when scope expands beyond an isolated non-clinical host to confirmed lateral movement, active credential abuse, or suspected data staging inside production networks.
- **SEV2 to SEV1:** Escalates immediately if ransomware spreads across clinical sites, patient monitoring systems are disrupted during care, or suspected data exposure is confirmed as broad exfiltration of patient records at scale.
- **Time-Based Escalation:** If an incident exceeds its defined Max Response Time without verified containment progress or root-cause identification, it automatically escalates one severity tier higher.

### Downward Re-Classification and Closure Criteria

Severity can only decrease following verified, multi-point technical containment (e.g., compromised accounts revoked, network segments isolated and verified clean via EDR and forensic imaging), elimination of all active persistence mechanisms, and formal written approval from the IR Commander (or CISO for SEV1).

Re-classification is strictly incremental (step-by-step downward) and requires consensus among the technical lead and decision authority during a formal incident bridge review.
