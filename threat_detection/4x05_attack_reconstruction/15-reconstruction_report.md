# INCIDENT RECONSTRUCTION REPORT: HEALTHBANE CAMPAIGN
**Target Organization:** MedDefense Health Systems  
**Author:** Security Operations & Incident Response Team  
**Reviewer:** James Chen (Director of Information Security)  
**Presented To:** Dr. Patricia Morales (Chief Executive Officer) & Board of Directors  
**Classification:** STRICTLY CONFIDENTIAL - ATTORNEY-CLIENT PRIVILEGE  
**Date:** February 2024 / Published October 2026  

---

## 1. Executive Summary

### What Happened
Between February 1 and February 12, 2024, MedDefense Health Systems was targeted by a sophisticated, targeted cyber intrusion designated the **HEALTHBANE** campaign. The threat actor gained initial access via a highly targeted spearphishing email sent to staff members, resulting in credential harvesting for user Diane on workstation `WS-RECV-03`. Utilizing valid credentials and custom malware payloads disguised as legitimate administrative updates (`svchost_update.exe`), the attacker established an encrypted HTTPS command-and-control (C2) channel, escalated privileges, dumped credentials from LSASS memory (`svc_healthsync`), and pivoted laterally across the internal network via SMB Admin Shares (`PsExec`) and WinRM to access core database infrastructure (`SRV-HEALTH-DB`). Once inside, the adversary queried patient records, staged 34.4 MB of compressed data locally, and prepared for external exfiltration.

### How Far the Attacker Got
- **Systems Compromised:** 5 hosts (`WS-RECV-03`, `SRV-HEALTH-DB`, `SRV-INS-DB`, `SRV-FILE-01`, `SRV-DC-01`).
- **Data at Risk:** Critical Patient Health Information (PHI) and billing metadata (~3,200 patient records accessed and staged).
- **Exfiltration Status:** **Interrupted.** Data staging archives were successfully created on `WS-RECV-03`, but bulk external exfiltration was cut off prior to completion due to timely threat hunt detection and emergency isolation.

### How It Was Stopped
The intrusion was uncovered on February 12, 2024, during a proactive SIEM threat hunt (`4x04`) that flagged anomalous `PsExec` activity and unauthorized credential dumping on `WS-RECV-03`. The Incident Response team immediately triggered the emergency containment playbook, isolating `WS-RECV-03` within 1.75 hours of detection and seizing volatile memory and disk images for forensic analysis.

### What Happens Next
MedDefense is executing an immediate remediation plan encompassing credential rotation, network segmentation tightening around health databases, endpoint detection sensor hardening, and mandatory HIPAA breach notifications to regulatory authorities and affected individuals.

### Key Metrics
- **Total Dwell Time:** 11 days (from phishing delivery on Feb 01 to containment on Feb 12).
- **Breakout Time:** 76 hours (initial access to first lateral pivot on Feb 05).
- **ATT&CK Coverage Improvement:** Expanded from **40%** (intelligence baseline) to **96%** (comprehensive IR reconstruction).

---

## 2. Methodology

### Evidence Sources Used
The reconstruction integrates 11 primary evidence files across analytical domains:
1. **Phishing Analysis (`4x00_phishing_summary.txt`)**: Email headers, malicious links, and SPF/DKIM validation failures.
2. **Network Forensics (`4x01_network_timeline.txt`)**: PCAP traffic analysis and 5-minute C2 beacon patterns.
3. **Threat Intelligence (`4x02_attack_mapping.json`)**: Initial adversary profiling and 40% ATT&CK mapping.
4. **Malware Triage (`4x03_malware_summary.txt`)**: Static/sandbox analysis of droppers, RATs, and exfiltration tools.
5. **Threat Hunting (`4x04_hunting_report.txt`)**: 14-day SIEM query logs revealing lateral movement and LSASS dumping.
6. **Memory Forensics (`memory_artifacts.txt`)**: Volatile RAM capture from `WS-RECV-03` showing active processes and network connections.
7. **Disk Forensics (`disk_forensics_report.txt`)**: Recovered deleted files, database query results, and NTFS master file table timelines.
8. **Firewall Logs (`firewall_sessions_ws_recv_03.json`)**: Stateful session logs capturing inbound/outbound connections and byte counts.
9. **IR Team Notes (`ir_team_notes.txt`)**: Initial analyst observations and hypotheses.
10. **Reference Databases (`healthbane_ioc_master.json`, `meddefense_asset_inventory.txt`, `network_topology.txt`)**: Enterprise asset mappings and consolidated IOC registers.

### Analytical Approach
- **Cross-Evidence Correlation:** Findings from isolated domains were cross-referenced into a correlation matrix to identify convergences, single-source anomalies, and contradictions.
- **Timeline Reconstruction:** Chronological sequencing was normalized across log sources, resolving a 4-second clock skew between network PCAP sensors and stateful firewalls.
- **Confidence Assessment Framework:** Every event and technique was evaluated and assigned a confidence rating (`CONFIRMED`, `PROBABLE`, or `POSSIBLE`) based on independent source corroboration.

---

## 3. Attack Reconstruction

### Stage 1: Initial Access (Phishing)
- **Timeline:** February 01, 2024 (08:14 UTC - 09:23 UTC).
- **Narrative:** Phishing emails impersonating IT security updates were delivered to 8 staff members. Diane (`WS-RECV-03`) clicked a spearphishing link (`T1566.001`) leading to a credential harvesting portal, submitting her domain credentials (`T1078`).
- **Evidence:** `4x00` email batch analysis and initial PCAP POST request logs.
- **Confidence:** **CONFIRMED** (Converged across email headers and network sessions).

### Stage 2: C2 Establishment
- **Timeline:** February 01, 2024 (10:55 UTC onwards).
- **Narrative:** Approximately 1.5 hours after credential harvest, `WS-RECV-03` initiated outbound HTTPS connections to C2 IP `198.51.100.45:443` (`T1071.001`, `T1573.001`) operating on a strict 300-second beacon interval. A secondary C2 IP (`203.0.113.88`) appeared later on Feb 06 as backup infrastructure.
- **Evidence:** `4x01` PCAP analysis and `IR-FW` firewall session logs (with 4s clock skew resolved).
- **Confidence:** **CONFIRMED**.

### Stage 3: Malware Deployment & Persistence
- **Timeline:** February 04 - 06, 2024.
- **Narrative:** The attacker deployed custom loader `svchost_update.exe` (`T1204.002`), injected payloads into memory, and established persistence via a scheduled task (`T1053.005`) executing at system startup (`Feb 06 01:47`). LSASS memory was dumped (`T1003.001`) using custom tooling to harvest the `svc_healthsync` service account credential.
- **Evidence:** `4x03`, `IR-MEM` loaded modules, and `IR-DISK` registry/Prefetch artifacts.
- **Confidence:** **CONFIRMED**.

### Stage 4: Lateral Movement and Data Staging
- **Timeline:** February 05 - 11, 2024.
- **Narrative:** Using compromised service credentials (`svc_healthsync`), the attacker pivoted from `WS-RECV-03` to `SRV-HEALTH-DB` via `PsExec` (`T1021.002`) on Feb 05. On Feb 10, database queries extracted patient health records (`query_results.csv`, 8.4 MB; `T1005`), which were transferred back to `WS-RECV-03` and compressed into staging archives (`staging_export_001.zip`, 14.2 MB; `staging_export_002.zip`, 11.8 MB; `T1560.001`, `T1074.001`). Event logs were cleared (`T1070.001`) to hamper investigation.
- **Evidence:** `4x04` threat hunt findings, `IR-DISK` file artifacts, and `IR-FW` session logs.
- **Confidence:** **CONFIRMED**.

---

## 4. Unified Timeline

| # | Timestamp (UTC) | Event Description | ATT&CK ID | Conf | Evidence Sources |
|---|----------------|-------------------|-----------|------|------------------|
| 01 | 2024-02-01 08:14 | Spearphishing emails sent | T1566.001 | CONF | `4x00` |
| 02 | 2024-02-01 09:22 | Diane clicks credential link | T1566.001 | CONF | `4x00` |
| 03 | 2024-02-01 09:23 | Credentials submitted | T1078 | CONV | `4x00`, `4x01` |
| 04 | 2024-02-01 10:55 | First C2 beacon initiated | T1071.001 | CONV | `4x01`, `IR-FW` |
| 05 | 2024-02-04 01:23 | Credential dump (LSASS) | T1003.001 | CONV | `4x04`, `IR-MEM` |
| 06 | 2024-02-05 02:14 | Lateral pivot to `SRV-HEALTH-DB` | T1021.002 | CONV | `4x04`, `IR-FW` |
| 07 | 2024-02-06 01:47 | Scheduled task persistence created | T1053.005 | CONV | `IR-MEM`, `IR-DISK` |
| 08 | 2024-02-06 02:12 | Secondary C2 channel active | T1071.001 | PROB | `IR-FW` |
| 09 | 2024-02-10 14:22 | Database query results exported | T1005 | CONF | `IR-DISK` |
| 10 | 2024-02-10 15:07 | First staging archive created | T1560.001 | CONF | `IR-DISK` |
| 11 | 2024-02-11 01:08 | Second staging archive created | T1560.001 | CONF | `IR-DISK` |
| 12 | 2024-02-12 01:44 | Last anomalous PsExec activity | T1021.002 | CONF | `4x04` |
| 13 | 2024-02-12 09:30 | Threat hunt detection reported | --- | CONF | `4x04` |
| 14 | 2024-02-12 11:15 | Emergency IR host isolation | --- | CONF | `IR` team |

### Temporal Metrics & Gaps
- **Total Dwell Time:** 11 days.
- **Breakout Time:** 76 hours.
- **Detection to Containment:** 1.75 hours.
- **Timeline Gaps:** A dormant period (Feb 01 - Feb 04) where the attacker maintained silent C2 beaconing while waiting for operational timing.

---

## 5. ATT&CK Analysis

### Coverage Evolution
- **Post-4x02 (Intelligence):** ~40% (12/29 techniques).
- **Post-4x03 (Malware Triage):** ~55% (16/29 techniques).
- **Post-4x04 (Threat Hunting):** ~80% (23/29 techniques).
- **Post-4x05 (Reconstruction):** **~96% (28/29 techniques)**.

### Newly Identified & Upgraded Techniques
- **Upgraded (`INFERRED` -> `CONFIRMED`):** `T1021.002` (Remote Services: SMB/Admin Shares) confirmed via threat hunt and IR firewall logs.
- **New (from IR Evidence):** `T1053.005` (Scheduled Task), `T1074.001` (Local Data Staging), `T1560.001` (Archive Collected Data), `T1070.001` (Clear Windows Event Logs), and `T1005` (Data from Local System).
- **Remaining Gap:** `T1048.003` (Exfiltration Over Alternative Protocol: DNS) remains a recognized malware capability from `4x03`, but observed execution during this incident was unconfirmed.

---

## 6. Impact Assessment

### Data Exposure Summary
- **Patient Health Records (PHI):** **CONFIRMED ACCESSED & STAGED.** Approximately 3,200 patient records were queried on `SRV-HEALTH-DB` and compressed into local archives (`34.4 MB`).
- **Insurance / Billing Data:** **PROBABLE ACCESS** via compromised `svc_healthsync` credentials.
- **Employee Records:** **NOT EXPOSED** (no HR system traversal detected).

### Exfiltration Determination & Regulatory Implications
- **Exfiltration Status:** Bulk external exfiltration was **interrupted** prior to completion by emergency host isolation on Feb 12.
- **HIPAA Assessment:** **MET threshold for reportable data breach** under 45 CFR § 164.402 due to confirmed unauthorized access, querying, and local staging of PHI.
- **Recommendation:** Proceed immediately with mandatory breach notifications to HHS/OCR, state regulators, and affected patients, supported by mitigating factors (rapid containment and encrypted storage at rest).

---

## 7. Defensive Posture Evaluation

- **What Worked:** Proactive SIEM threat hunting (`4x04`) successfully caught behavioral anomalies that static prevention missed; rapid incident response containment severed network access within 1.75 hours of reporting.
- **What Failed:** Perimeter defenses failed to block sophisticated spearphishing; administrative tools (`PsExec`, WinRM) blended seamlessly with normal IT operations, causing a 76-hour breakout window before detection.
- **Structural Lessons:** Detection-only security is insufficient against living-off-the-land techniques; proactive hunting and forensic readiness are mandatory operational necessities.

---

## 8. Remediation Plan

1. **Immediate Actions (Completed / Ongoing):**
   - Isolate compromised endpoints (`WS-RECV-03`, database segments).
   - Global password and service account credential rotation (`svc_healthsync`).
2. **Short-Term Actions (30 Days):**
   - Implement strict network segmentation restricting database server access (`SRV-HEALTH-DB`) solely to authorized application servers.
   - Deploy Endpoint Detection and Response (EDR) behavioral blocking rules for `PsExec` and LSASS memory dumping.
3. **Medium-Term Actions (90 Days):**
   - Roll out mandatory phishing-resistant Multi-Factor Authentication (MFA) across all employee accounts.
   - Establish automated log collection pipelines and continuous threat hunting baselines.

---

## 9. Conclusions
Module 4 demonstrated that analyzing investigations in isolation creates blind spots that only comprehensive cross-evidence reconstruction can resolve. Proactive hunting and forensic readiness transformed isolated anomalies into a definitive, defensible narrative, empowering MedDefense to navigate regulatory obligations with absolute clarity.

---

## 10. Appendices

### Appendix A: IOC Summary Table
| Indicator | Type | Sources | Status |
|---|---|---|---|
| `meddefense-secure.com` | Domain | `4x00`, `4x02` | CONVERGED (Phishing) |
| `198.51.100.45` | IP Address | `4x01`, `4x02`, `4x03`, `IR-FW` | CONVERGED (C2 Primary) |
| `203.0.113.88` | IP Address | `IR-FW` | SINGLE-SOURCE (C2 Backup) |
| `svchost_update.exe` | File Name | `4x03`, `IR-MEM`, `IR-DISK` | CONVERGED (Malware Dropper) |
| `svc_healthsync` | Account | `4x04`, `IR-MEM`, `IR-DISK` | CONVERGED (Compromised Service) |
| `staging_export_001.zip` | File Name | `IR-DISK` | SINGLE-SOURCE (Data Staging) |

### Appendix B: Evidence Citation Index
- **`4x00_phishing_summary.txt`**: Initial phishing batch and URL analysis.
- **`4x01_network_timeline.txt`**: PCAP packet flows and beacon intervals.
- **`ir_evidence/firewall_sessions_ws_recv_03.json`**: Stateful firewall audit records.
- **`ir_evidence/memory_artifacts.txt`**: Volatile process and connection dumps.
- **`ir_evidence/disk_forensics_report.txt`**: Recovered staging archives and database query exports.

### Appendix C: ATT&CK Navigator Reference
Comprehensive mapping available in `reference/attck_navigator_80pct.json` (updated to 96% coverage following IR integration).
