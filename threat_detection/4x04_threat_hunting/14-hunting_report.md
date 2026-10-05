# THREAT HUNTING REPORT: HEALTHBANE Stage 4 (LOLBin Lateral Movement)
**Classification:** TLP:AMBER  
**Organization:** MedDefense Health Systems  
**Prepared by:** Threat Intelligence & Detection Engineering Team  
**Date:** October 2026  

---

## 1. Executive Summary

Following the release of HC3 Advisory `HEALTHBANE-ADV-2026-004`, MedDefense initiated a proactive threat hunt to answer a critical operational question: *Did HEALTHBANE Stage 4 occur in our environment during the last 14 days?*

Our current automated detection posture sits at **55% ATT&CK coverage**. However, because Stage 4 relies exclusively on Living Off The Land Binaries (LOLBins)—such as PsExec, WMI, and PowerShell Remoting—combined with stolen service account credentials, traditional alert-based detection failed to fire. 

### Key Findings
* **POSITIVE FINDING:** HEALTHBANE Stage 4 lateral movement **did occur** within the MedDefense network during the 14-day analysis window.
* **Compromised Pivot Host:** `WS-RECV-03` was utilized as the operational pivot point.
* **Stolen Credentials:** The domain service account `MEDDEFENSE\svc_healthsync` was compromised via LSASS memory dumping (`T1003.001`) and abused for unauthorized lateral authentication (`T1078.002`).
* **Target Impact:** Attackers successfully reached critical infrastructure, including `SRV-HEALTH-DB`, `SRV-INS-DB`, and `SRV-DC-01`, utilizing PsExec (`T1021.002`), WMI (`T1047`), and PowerShell Remoting (`T1021.006`).

### Remediation Status
Through hypothesis-driven hunting and baseline comparison, we closed critical detection gaps, deployed five new high-fidelity detection rules, and improved our observed ATT&CK coverage from **55% to approximately 80%**. Immediate incident response containment has been initiated for `WS-RECV-03`.

---

## 2. Hunt Methodology
Professional threat hunting bridges the gap between known intelligence and automated blind spots.
1. **Intelligence Integration:** Extracted TTPs from HC3 advisory regarding off-hours LOLBin abuse and service account impersonation.
2. **Gap Analysis:** Mapped uncovered lateral movement and credential access techniques against our 4x03 ATT&CK matrix.
3. **Baseline Establishment:** Profiled legitimate IT administrator Robert Kim (`WS-ADMIN-01`, business hours `08:00–18:00`, named account usage only) to establish an immutable false-positive filter.
4. **Targeted SIEM Querying:** Searched Wazuh alerts and raw Sysmon event logs across a 14-day window for contextual anomalies.

---

## 3. Findings per Hypothesis

* **H1: PsExec Lateral Movement (T1021.002)**
  * *Status:* **POSITIVE - HIGH CONFIDENCE**
  * *Evidence:* PsExec executions launched from `WS-RECV-03` targeting database servers during off-hours (`02:14 UTC`).
* **H2: LSASS Credential Access (T1003.001)**
  * *Status:* **POSITIVE - HIGH CONFIDENCE**
  * *Evidence:* Non-system process (`C:\Windows\Temp\debug_tool.exe`) accessing `lsass.exe` with access mask `0x1010` on workstation `WS-RECV-03`.
* **H3: WMI Remote Execution (T1047)**
  * *Status:* **POSITIVE - HIGH CONFIDENCE**
  * *Evidence:* Remote WMI process creation (`WmiPrvSE.exe` spawning command-line utilities) targeting core servers outside maintenance windows.
* **H4: PowerShell Remoting / Staging (T1021.006)**
  * *Status:* **POSITIVE - HIGH CONFIDENCE**
  * *Evidence:* Remote PowerShell sessions and file transfers (`Copy-Item`) used to stage payloads on database servers.
* **H5: Service Account Abuse (T1078.002)**
  * *Status:* **POSITIVE - CRITICAL CONFIDENCE**
  * *Evidence:* Service account `svc_healthsync` (authorized exclusively for `SRV-HEALTH-DB`) authenticated interactively from workstation `WS-RECV-03`.

---

## 4. Reconstructed Attack Timeline

* **[CREDENTIAL ACCESS]** — `WS-RECV-03` executed unauthorized memory access against `lsass.exe`, extracting domain credentials for `svc_healthsync`.
* **[LATERAL MOVEMENT]** — Utilizing the stolen service account, attackers initiated unauthorized sessions from `WS-RECV-03` to `SRV-HEALTH-DB` via PsExec.
* **[RECONNAISSANCE]** — Executed WMI remote queries to enumerate system configuration and active processes on target servers.
* **[STAGING]** — Established PowerShell Remoting sessions to stage operational files and scripts.
* **[EXPANSION]** — Pivoted further across the network, reaching `SRV-INS-DB` and `SRV-DC-01`.
* **Dwell Time:** Approximately 3 hours and 42 minutes of unauthorized off-hours activity.

---

## 5. ATT&CK Coverage Update

* **Before Hunt:** 16 / 29 techniques covered (**55%**). Key lateral movement LOLBins and LSASS access were unmonitored.
* **After Hunt:** Coverage expanded to **~80%** following the implementation of behavioral context rules for administrative tools.

---

## 6. Detection Improvements

Four Wazuh-style rules and one network signature were drafted to ensure automatic detection of these patterns moving forward:
1. **[Rule 100100] PsExec from Non-Admin Workstation:** Alerts when PsExec originates outside `WS-ADMIN-01` or during off-hours.
2. **[Rule 100101] LSASS Memory Access from Non-System Process:** Detects unauthorized memory reads on `lsass.exe`.
3. **[Rule 100102] Service Account Interactive Logon from Workstation:** Flags service account usage originating from non-service hosts.
4. **[Rule 100103] WMI Remote Child Process Anomaly:** Detects suspicious child processes spawned by `WmiPrvSE.exe`.
5. **[Rule 9000030] SMB Lateral Movement (PsExec Service Installation):** Network rule catching remote service installation patterns.

---

## 7. Remaining Gaps & Recommendations

* **Immediate Actions (Module 5 Bridge):** Isolate workstation `WS-RECV-03`, terminate active sessions, and initiate forensic disk imaging.
* **Short-Term Actions:** Immediately rotate compromised service account passwords (`svc_healthsync`, `svc_insurance`) and audit all domain privileged groups.
* **Medium-Term Actions:** Deploy full Sysmon logging configurations across all endpoints and integrate user-entity behavior analytics (UEBA) to flag context anomalies automatically.
* **Uncovered Gaps (Remaining 20%):** Advanced stealth techniques such as direct API injection and encrypted pass-the-ticket maneuvers require EDR memory protection deployment.

---

## 8. Lessons Learned

1. **The Coverage Illusion:** A 55% ATT&CK coverage score creates a false sense of security if coverage metrics measure theoretical presence rather than contextual rule validation.
2. **The Failure of Static Detection:** Relying on file hashes and malware signatures is ineffective against Living Off The Land attacks where attackers abuse legitimate administrative utilities.
3. **Proactive Hunting as an Operational Discipline:** Automated detection waits for known rules; threat hunting searches for abnormal context. Regular hypothesis-driven hunts must remain a core operational discipline for MedDefense
