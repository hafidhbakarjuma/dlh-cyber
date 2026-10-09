# 4x04 — Threat Hunting

*Hypothesis-driven hunt for HEALTHBANE Stage 4: living-off-the-land lateral movement*

![Track](https://img.shields.io/badge/Track-Threat%20Hunting%20%2F%20SOC-blue)
![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)
![Data](https://img.shields.io/badge/Data-Wazuh%20%2B%20Sysmon%20(14%20days)-informational)
![TLP](https://img.shields.io/badge/TLP-AMBER-orange)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)

> *Absence of alerts is not absence of attackers.*

**Program:** DLH Cybersecurity Academy — SOC Analyst / Penetration Testing track
**Author:** [hafidhbakarjuma](https://github.com/hafidhbakarjuma)
**Scenario:** MedDefense Health Systems, HC3 advisory `HEALTHBANE-ADV-2026-004`

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Scenario](#scenario)
3. [Learning Objectives](#learning-objectives)
4. [Hunt Design](#hunt-design)
5. [Findings](#findings)
6. [Detection Improvements](#detection-improvements)
7. [Repository Structure](#repository-structure)
8. [Deliverables Index](#deliverables-index)
9. [Data Sources](#data-sources)
10. [Getting Started](#getting-started)
11. [Skills Demonstrated](#skills-demonstrated)
12. [Project Series](#project-series)

---

## Executive Summary

HC3 advisory `HEALTHBANE-ADV-2026-004` describes Stage 4 of the campaign: lateral movement using only built-in administrative tools (PsExec, WMI, PowerShell Remoting), stolen service account credentials and off-hours activity. Tools like these carry no malware signature, so MedDefense's alert-driven detection, at **55% ATT&CK coverage (16 of 29 techniques)**, was blind to them.

This project asks one question: **did Stage 4 happen in our environment during the last 14 days?**

**Answer: yes.** Hypothesis-driven analysis of 14 days of Wazuh alerts and raw Sysmon telemetry, filtered against a documented admin baseline, produced positive findings for all five hypotheses. The pivot host was `WS-RECV-03`, the abused account was `svc_healthsync`, and the attacker reached `SRV-HEALTH-DB`, `SRV-INS-DB` and `SRV-DC-01`. Estimated off-hours dwell: about **3 hours 42 minutes**.

---

## Scenario

The security team receives the HC3 advisory and a 14-day SIEM export. No alert fired. The task is to turn the advisory into testable hypotheses, define in advance what a positive finding looks like, compare activity against what legitimate administrators do, and convert confirmed behavior into new detections.

---

## Learning Objectives

By the end of this project, you are expected to be able to explain to anyone, without the help of Google:

### Threat Hunting Methodology
- The difference between alert-driven detection and hypothesis-driven threat hunting
- How to derive hunt hypotheses from an advisory and ATT&CK gap analysis
- How to define a positive finding before running the query
- Why hunting requires a documented baseline
- Why absence of SIEM alerts does not prove absence of threat activity

### Living Off The Land Detection
- Why PsExec, WMI and PowerShell Remoting are hard to detect with static IOCs
- How legitimate tools become suspicious through source host, user, target and time context
- How service account misuse reveals credential compromise
- How off-hours activity can identify adversary operations

### Baseline Analysis
- How to profile legitimate administrator behavior
- How to use an authorized schedule as a false-positive filter
- How to validate service account authentication against an authorization matrix
- How to separate normal maintenance from adversary lateral movement

### Evidence Correlation
- How to combine separate findings into a unified attack timeline
- How to correlate credential theft, lateral movement, reconnaissance and staging
- How to map hunt findings to MITRE ATT&CK
- How to turn hunt findings into new detection rules

### Reporting
- How to write a hunting report for SOC and leadership audiences
- How to explain the coverage illusion
- How to document remaining gaps and next-step recommendations

---

## Hunt Design

### Gap-driven priorities

| Priority | Technique | Hypothesis |
|----------|-----------|------------|
| P1 | T1021.002 SMB/Windows Admin Shares (PsExec) | H1: PsExec lateral movement |
| P2 | T1003.001 LSASS Memory | H2: credential dumping |
| P3 | T1047 Windows Management Instrumentation | H3: remote WMI execution |
| P4 | T1021.006 Windows Remote Management | H4: PowerShell Remoting and staging |
| P5 | T1078.002 Domain Accounts | H5: service account abuse |

### Baseline
Legitimate administration was profiled from one named administrator (`WS-ADMIN-01`, business hours 08:00–18:00, named account only) and the authorized admin schedule. Activity matching the baseline is filtered out; what remains is evaluated for source host, user, target and time anomalies.

### Principle: define "positive" first
Each hypothesis states in advance what counts as a positive finding (for example, PsExec from a non-admin workstation or outside the schedule), so results are not reinterpreted after the fact.

---

## Findings

| Hypothesis | Technique | Result | Key evidence |
|-----------|-----------|--------|--------------|
| H1 PsExec | T1021.002 | **POSITIVE, HIGH** | PsExec launched from `WS-RECV-03` against database servers at 02:14 UTC, outside the admin schedule |
| H2 LSASS | T1003.001 | **POSITIVE, HIGH** | `C:\Windows\Temp\debug_tool.exe` accessed `lsass.exe` with mask `0x1010` on `WS-RECV-03` |
| H3 WMI | T1047 | **POSITIVE, HIGH** | `WmiPrvSE.exe` spawning command-line utilities on core servers outside maintenance windows |
| H4 PS Remoting | T1021.006 | **POSITIVE, HIGH** | Remote PowerShell sessions and `Copy-Item` staging on database servers |
| H5 Service account | T1078.002 | **POSITIVE, CRITICAL** | `svc_healthsync`, authorized only for `SRV-HEALTH-DB`, authenticated interactively from `WS-RECV-03` |

### Reconstructed sequence
`Credential access` (LSASS dump on `WS-RECV-03`) → `Lateral movement` (PsExec to `SRV-HEALTH-DB` with `svc_healthsync`) → `Reconnaissance` (WMI queries) → `Staging` (PowerShell Remoting) → `Expansion` (`SRV-INS-DB`, `SRV-DC-01`).

### The coverage illusion
Coverage of 55% sounded reasonable, but the missing 45% was exactly the set of techniques Stage 4 relies on. After hunt-derived detections, coverage rose to about **80% (23 of 29)**. Percentages describe breadth, not whether the techniques that matter are covered.

---

## Detection Improvements

| Rule | Detection | Expected FP rate |
|------|-----------|------------------|
| 100100 | PsExec from a non-admin workstation or off-hours | Very low |
| 100101 | LSASS memory access from a non-system process | Low |
| 100102 | Service account interactive logon from a workstation | Very low |
| 100103 | `WmiPrvSE.exe` spawning `cmd.exe` or `powershell.exe` | Medium |
| 9000030 | Network signature for PsExec service installation over SMB | See report |

---

## Repository Structure

```text
4x04_threat_hunting/
├── README.md
├── 0-hunt_brief.sh              # Hunt brief: advisory TTPs, gaps, priorities, data sources
├── 2-baseline_profile.sh        # Legitimate administrator baseline
├── 3-data_recon.sh              # Profile of the 14-day SIEM export
├── 4-hunt_psexec.sh             # H1: PsExec lateral movement
├── 6-hunt_credentials.sh        # H2: LSASS credential access
├── 9-hunt_svcaccount.sh         # H5: service account authorization audit
├── 10-evidence_correlation.sh   # Unified attack timeline
├── 12-gap_analysis.sh           # Detection gaps for new techniques
├── 13-detection_rules.sh        # Hunt-derived rule drafts and posture update
├── 14-hunting_report.md         # Final hunting report (SOC and leadership)
└── material/4x04/
    ├── siem_export/             # wazuh_alerts_14d.json, wazuh_raw_sysmon_14d.json
    ├── baseline/                # robert_kim_activity.json
    └── reference/               # hc3_advisory_004, admin_schedule, service_accounts,
                                 # network_topology, 4x03_attack_mapping.json
```

---

## Deliverables Index

| # | File | Focus |
|---|------|-------|
| 0 | `0-hunt_brief.sh` | Advisory summary, ATT&CK gap analysis, ranked hunt priorities, data sources, time window |
| 2 | `2-baseline_profile.sh` | Profile of legitimate admin behavior used as the false-positive filter |
| 3 | `3-data_recon.sh` | Scope and shape of the 14-day alert and Sysmon datasets |
| 4 | `4-hunt_psexec.sh` | H1 hunt execution: PsExec events vs. baseline, anomalous count, timestamp |
| 6 | `6-hunt_credentials.sh` | H2 hunt: LSASS access by non-system processes |
| 9 | `9-hunt_svcaccount.sh` | H5 hunt: service account authentication vs. authorization matrix |
| 10 | `10-evidence_correlation.sh` | Correlation of credential theft, movement, recon and staging into one timeline |
| 12 | `12-gap_analysis.sh` | Which newly confirmed techniques lack detection |
| 13 | `13-detection_rules.sh` | Wazuh-style and network rule drafts with evidence and FP estimates |
| 14 | `14-hunting_report.md` | Executive summary, methodology, per-hypothesis findings, timeline, coverage update, gaps and recommendations |

H3 (WMI) and H4 (PowerShell Remoting) findings are documented in the hunting report.

---

## Data Sources

| Source | Purpose |
|--------|---------|
| `siem_export/wazuh_alerts_14d.json` | Primary: 14 days of SIEM alerts |
| `siem_export/wazuh_raw_sysmon_14d.json` | Secondary: raw Sysmon telemetry |
| `baseline/robert_kim_activity.json` | Legitimate administrator baseline |
| `reference/admin_schedule.txt` | Authorized maintenance windows |
| `reference/service_accounts.txt` | Service account authorization matrix |
| `reference/network_topology.txt` | Host and segment context |
| `reference/hc3_advisory_004.txt` | Advisory TTPs |
| `reference/4x03_attack_mapping.json` | Prior ATT&CK coverage (55%) |

---

## Getting Started

```bash
# Requirements: bash, jq, grep
cd 4x04_threat_hunting
chmod +x ./*.sh
shellcheck ./*.sh            # optional lint

./0-hunt_brief.sh            # start with the brief
./2-baseline_profile.sh      # establish the baseline before hunting
./3-data_recon.sh
./4-hunt_psexec.sh
./6-hunt_credentials.sh
./9-hunt_svcaccount.sh
./10-evidence_correlation.sh
./12-gap_analysis.sh
./13-detection_rules.sh
```

Scripts expect to be run from the project folder and read the dataset from `material/4x04/` (reference paths are noted at the top of each script).

---

## Remaining Gaps and Next Steps

- **Immediate:** isolate `WS-RECV-03`, terminate sessions, take forensic images (continues in 4x05).
- **Short term:** rotate `svc_healthsync` and `svc_insurance` credentials; audit privileged domain groups.
- **Medium term:** deploy full Sysmon configuration on all endpoints and integrate user-entity baselining.

---

## Skills Demonstrated

**Hunting:** hypothesis design, positive-finding definition, baseline-driven false-positive filtering
**Detection:** LOLBin context analysis, service account abuse detection, off-hours analysis
**Analysis:** SIEM and Sysmon querying with `jq` and `grep`, timeline correlation, ATT&CK gap mapping
**Engineering:** Wazuh-style rule drafting with FP estimation
**Reporting:** SOC and leadership hunting report, coverage-illusion explanation

---

## Project Series

| Project | Focus |
|---------|-------|
| 4x00 | Phishing email investigation and IOC extraction |
| 4x01 | Network forensics from PCAP evidence |
| 4x02 | Intelligence-driven defense against HEALTHBANE |
| 4x03 | Malware awareness: static and dynamic analysis |
| **4x04** (this project) | Threat hunting for Stage 4 lateral movement |
| 4x05 | Attack reconstruction and impact assessment |

---

*Educational project completed as part of the DLH Cybersecurity Academy curriculum. All organizations, personnel and incident details belong to a training scenario.*
