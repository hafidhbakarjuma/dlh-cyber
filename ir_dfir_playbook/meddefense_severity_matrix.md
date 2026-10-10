# MedDefense Severity Matrix

## Purpose

Common severity language for all MedDefense incidents. Applied from first alert through closure.

## Severity Matrix

| Level | Patient Safety Impact | Data Exposure | Service Availability | Max Response Time | Decision Authority |
| :--- | :--- | :--- | :--- | :--- | :--- |
| SEV1 | high | confirmed_broad | full_outage | 15 min | CISO |
| SEV2 | moderate | confirmed_limited | partial_outage | 30 min | IR Commander |
| SEV3 | low | suspected | degraded | 60 min | SOC Lead |
| SEV4 | none | none | none | 240 min | SOC Analyst |

## Level Definitions

### SEV1

* Ransomware affecting clinical systems across multiple sites
* Confirmed exfiltration of patient records at scale
* Patient monitoring system offline during active care

### SEV2

* Confirmed compromise of a clinical-access account
* Malware confirmed on a single workstation at a clinical site
* Suspected exfiltration under investigation

### SEV3

* Isolated malware detection neutralized by EDR on a non-clinical workstation
* Unauthorized access attempt blocked on an internal admin portal
* Anomalous outbound traffic pattern from a single test server

### SEV4

* Phishing email reported with no user interaction or credential submission
* Low-risk vulnerability scan finding on an internal non-critical host
* Automated policy violation warning with no malicious intent identified

## Escalation Rule

Severity is reviewed at every status update. It increases when new evidence raises patient safety, data exposure, or service availability to the next tier. It decreases only after confirmed containment and IR Commander approval.