# 4x05 — Attack Reconstruction

*Cross-evidence correlation, timeline reconstruction, ATT&CK mapping and impact assessment for the HEALTHBANE intrusion*

![Track](https://img.shields.io/badge/Track-Incident%20Response%20%2F%20DFIR-blue)
![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)
![Evidence](https://img.shields.io/badge/Evidence-Memory%20%7C%20Disk%20%7C%20Firewall-informational)
![Regulatory](https://img.shields.io/badge/Regulatory-HIPAA%20Breach%20Assessment-orange)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)

> *Analyzing investigations in isolation creates blind spots. Only cross-evidence reconstruction resolves them.*

**Program:** DLH Cybersecurity Academy — SOC Analyst / Penetration Testing track
**Author:** [hafidhbakarjuma](https://github.com/hafidhbakarjuma)
**Scenario:** MedDefense Health Systems — capstone of Module 4

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Scenario](#scenario)
3. [Learning Objectives](#learning-objectives)
4. [Evidence Base](#evidence-base)
5. [Reconstructed Attack](#reconstructed-attack)
6. [Key Metrics](#key-metrics)
7. [ATT&CK Analysis](#attck-analysis)
8. [Impact Assessment](#impact-assessment)
9. [Repository Structure](#repository-structure)
10. [Deliverables Index](#deliverables-index)
11. [Getting Started](#getting-started)
12. [Skills Demonstrated](#skills-demonstrated)
13. [Project Series](#project-series)

---

## Executive Summary

Modules 4x00 to 4x04 each answered a narrow question: the email, the packets, the intelligence, the malware, the hunt. This capstone integrates all of them with new incident response evidence (memory, disk, firewall and team notes from `WS-RECV-03`) into one defensible narrative.

**What happened:** a spearphishing email led to credential theft, an HTTPS command-and-control channel, malware deployment and persistence, LSASS credential dumping, PsExec lateral movement with a stolen service account, database access and local data staging. The attacker compromised **5 hosts** and staged about **34.4 MB** of patient and billing data (about 3,200 patient records) before containment.

**How it ended:** exfiltration was **interrupted**. A proactive threat hunt flagged the activity, and the host was isolated within **1.75 hours** of detection. Because confirmed unauthorized access and staging of PHI occurred, the report assesses that the **HIPAA breach threshold was met**.

---

## Scenario

The security director and CEO need to know what happened, how far the attacker got, how it was stopped and what happens next, with every claim traceable to evidence. The board needs an executive account. The technical team needs timestamps, sources and confidence levels. One report must serve both.

---

## Learning Objectives

By the end of this project, you are expected to be able to explain to anyone, without the help of Google:

### Cross-Evidence Correlation
- How to integrate findings from multiple investigation domains (email, network, endpoint, intelligence, SIEM) into a unified analytical picture
- How to identify convergences (findings confirmed by multiple independent sources) and divergences (findings contradicted or unsupported across sources)
- How to assess evidence reliability: which sources are authoritative for which claims, and why network timestamps may not match SIEM timestamps for the same event
- How to resolve apparent contradictions between evidence sources by analyzing collection gaps, timezone differences, clock skew and evidence preservation limitations

### Attack Timeline Reconstruction
- How to construct a chronological attack narrative from fragmented, multi-source evidence spanning days or weeks
- How to establish temporal anchors: high-confidence events that serve as fixed points around which less certain events are ordered
- How to distinguish between "confirmed sequence" (event A caused event B, evidenced by direct correlation) and "inferred sequence" (event A likely preceded event B based on technique logic)
- How to identify dwell time, breakout time and operational tempo from reconstructed timelines

### ATT&CK Mapping at Scale
- How to map a complete multi-phase attack to MITRE ATT&CK with confidence annotations per technique, distinguishing between confirmed (direct evidence), probable (strong circumstantial evidence) and possible (technique logic supports but evidence is indirect)
- How to identify coverage gaps that represent genuine blind spots versus gaps that reflect collection limitations
- Why ATT&CK coverage percentages can create a false sense of security and how reconstruction reveals the techniques that matter most

### Impact Assessment
- How to determine the organizational impact of an attack by mapping compromised systems to the asset inventory and data classification
- How to distinguish between confirmed data exposure (evidence of access), potential data exposure (access was possible but unconfirmed) and prevented data exposure (staging detected before exfiltration)
- How to assess regulatory implications (HIPAA notification triggers) based on evidence rather than assumption

### Professional Reporting
- How to produce an attack reconstruction report that serves both technical and executive audiences without compromising analytical rigor
- How to structure evidence citations so that every claim in the report traces back to a specific finding, timestamp and source
- How to document what is NOT known with the same rigor as what IS known, and why intellectual honesty strengthens rather than weakens a report

---

## Evidence Base

| Domain | Source | Contribution |
|--------|--------|--------------|
| Email | `previous_findings/4x00_phishing_summary.txt` | Phishing delivery, headers, auth failures |
| Network | `previous_findings/4x01_network_timeline.txt` | PCAP flows, 5-minute C2 beaconing |
| Intelligence | `previous_findings/4x02_attack_mapping.json` | Initial adversary profile and ATT&CK mapping |
| Malware | `previous_findings/4x03_malware_summary.txt` | Dropper, implant and exfiltrator behavior |
| Hunting / SIEM | `previous_findings/4x04_hunting_report.txt` | Lateral movement, LSASS dumping |
| Memory | `ir_evidence/memory_artifacts.txt` | Processes, loaded modules, connections on `WS-RECV-03` |
| Disk | `ir_evidence/disk_forensics_report.txt` | Deleted files, query exports, staging archives, timelines |
| Firewall | `ir_evidence/firewall_sessions_ws_recv_03.json` | Stateful session logs and byte counts |
| IR team | `ir_evidence/ir_team_notes.txt` | Analyst observations and initial hypotheses |
| Reference | `reference/` | Asset inventory, network topology, IOC master, ATT&CK Navigator layer |

---

## Reconstructed Attack

| Stage | Window (UTC) | What happened | Confidence |
|-------|--------------|---------------|------------|
| 1. Initial access | 2024-02-01 | Spearphishing to 8 staff; a user on `WS-RECV-03` clicked and submitted credentials (T1566.001, T1078) | CONFIRMED |
| 2. C2 establishment | From 2024-02-01 10:55 | HTTPS beacon every 300 s to primary C2; secondary C2 appears Feb 6 (T1071.001, T1573.001) | CONFIRMED (primary); PROBABLE (secondary) |
| 3. Malware and persistence | 2024-02-04 to 02-06 | `svchost_update.exe` deployed; LSASS dumped for `svc_healthsync`; scheduled task persistence (T1204.002, T1003.001, T1053.005) | CONFIRMED |
| 4. Lateral movement and staging | 2024-02-05 to 02-11 | PsExec to `SRV-HEALTH-DB`; patient data queried, compressed into two archives; event logs cleared (T1021.002, T1005, T1560.001, T1074.001, T1070.001) | CONFIRMED |
| Detection and containment | 2024-02-12 | Threat hunt detection 09:30; host isolation 11:15 | CONFIRMED |

Compromised hosts: `WS-RECV-03`, `SRV-HEALTH-DB`, `SRV-INS-DB`, `SRV-FILE-01`, `SRV-DC-01`.

A 14-event unified timeline with per-event confidence (CONFIRMED, CONVERGED, PROBABLE) and source citations is in the final report.

### Resolving contradictions
Firewall and PCAP sensors disagreed by **4 seconds** for the same sessions. The reconstruction normalized timestamps across sources and used corroborated events as temporal anchors rather than treating either sensor as ground truth.

---

## Key Metrics

| Metric | Value (as stated in the report) |
|--------|---------------------------------|
| Dwell time | 11 days (phishing delivery to containment) |
| Detection to containment | 1.75 hours |
| Systems compromised | 5 |
| Data staged | 34.4 MB (`query_results.csv` 8.4 MB; two archives 14.2 MB and 11.8 MB) |
| Patient records accessed and staged | About 3,200 |
| Breakout time | 76 hours (initial access to first lateral pivot) |

---

## ATT&CK Analysis

| Milestone | Coverage |
|-----------|----------|
| After 4x02 (intelligence) | About 40% (12/29) |
| After 4x03 (malware) | About 55% (16/29) |
| After 4x04 (hunting) | About 80% (23/29) |
| After 4x05 (reconstruction) | About 96% (28/29) |

- **Upgraded INFERRED → CONFIRMED:** T1021.002 (SMB / Admin Shares)
- **Newly identified from IR evidence:** T1053.005, T1074.001, T1560.001, T1070.001, T1005
- **Remaining gap:** T1048.003 (exfiltration over DNS) is a known malware capability, but its execution during this incident was **not confirmed**. It is recorded as unconfirmed rather than assumed.

**On coverage percentages:** the headline figure rose from 40% to 96%, but the value of the exercise is knowing *which* techniques the attacker used and which of those were invisible to MedDefense at the time.

---

## Impact Assessment

| Data class | Status | Basis |
|------------|--------|-------|
| Patient health records (PHI) | **Confirmed accessed and staged** | Queries on `SRV-HEALTH-DB`; staging archives on `WS-RECV-03` |
| Insurance / billing data | **Probable access** | Reachable with compromised `svc_healthsync` credentials |
| Employee records | **Not exposed** | No HR system traversal detected |
| External exfiltration | **Interrupted** | Staging complete; bulk transfer cut off by isolation |

**Regulatory assessment:** confirmed unauthorized access, querying and local staging of PHI meets the reportable breach threshold under 45 CFR § 164.402. The report recommends HHS/OCR, state and individual notifications, and records the mitigating factors (rapid containment, encryption at rest).

---

## Repository Structure

```text
4x05_attack_reconstruction/
├── README.md
├── 0-evidence_index.sh          # Evidence inventory and coverage catalog
├── 1-memory_analysis.sh         # Volatile memory findings, WS-RECV-03
├── 2-disk_analysis.sh           # Disk forensics and data staging
├── 3-firewall_analysis.sh       # Firewall session analysis
├── 4-correlation_matrix.sh      # Cross-evidence correlation matrix
├── 5-stages_1_2.sh              # Initial access and C2 establishment
├── 6-stage_3.sh                 # Malware deployment and capability establishment
├── 7-stage_4.sh                 # Lateral movement, staging and containment
├── 8-unified_timeline.sh        # Unified timeline and temporal metrics
├── 9-attack_techniques.sh       # ATT&CK inventory and coverage evolution
├── 12-data_exposure.sh          # Data exposure and regulatory impact
├── 14-remediation_plan.sh       # Prioritized remediation plan
├── 15-reconstruction_report.md  # Final board and technical report
├── ir_evidence/                 # Memory, disk, firewall and IR team notes
├── previous_findings/           # Outputs from 4x00 to 4x04
└── reference/                   # Asset inventory, topology, IOC master, Navigator layer
```

---

## Deliverables Index

| # | File | Focus |
|---|------|-------|
| 0 | `0-evidence_index.sh` | Catalog of all evidence files and what each covers |
| 1 | `1-memory_analysis.sh` | Processes, injected modules, network connections from the RAM capture |
| 2 | `2-disk_analysis.sh` | Recovered files, database exports, staging archives, MFT timeline |
| 3 | `3-firewall_analysis.sh` | Sessions, byte counts and C2 connections from firewall logs |
| 4 | `4-correlation_matrix.sh` | Convergences, single-source findings and contradictions across sources |
| 5 | `5-stages_1_2.sh` | Stages 1 and 2 reconstruction with evidence and confidence |
| 6 | `6-stage_3.sh` | Stage 3 reconstruction |
| 7 | `7-stage_4.sh` | Stage 4 reconstruction through containment |
| 8 | `8-unified_timeline.sh` | Chronology, dwell time, breakout time, detection-to-containment |
| 9 | `9-attack_techniques.sh` | Final ATT&CK inventory with confidence per technique |
| 12 | `12-data_exposure.sh` | Asset-mapped data exposure and HIPAA assessment |
| 14 | `14-remediation_plan.sh` | Immediate, short-term and medium-term actions |
| 15 | `15-reconstruction_report.md` | Executive summary, methodology, reconstruction, timeline, ATT&CK, impact, posture, remediation, appendices |

---

## Getting Started

```bash
# Requirements: bash, jq
cd 4x05_attack_reconstruction
chmod +x ./*.sh
shellcheck ./*.sh            # optional lint

./0-evidence_index.sh        # confirm all evidence is present first
./1-memory_analysis.sh
./2-disk_analysis.sh
./3-firewall_analysis.sh
./4-correlation_matrix.sh
./5-stages_1_2.sh && ./6-stage_3.sh && ./7-stage_4.sh
./8-unified_timeline.sh
./9-attack_techniques.sh
./12-data_exposure.sh
./14-remediation_plan.sh
```

Then read `15-reconstruction_report.md`, the consolidated deliverable.

---

## Remediation Summary

- **Immediate:** isolate `WS-RECV-03` and affected database segments; rotate `svc_healthsync` and related credentials.
- **30 days:** segment access to `SRV-HEALTH-DB` to authorized application servers; EDR behavioral rules for PsExec and LSASS access.
- **90 days:** phishing-resistant MFA for all accounts; automated log pipelines and continuous hunting baselines.

---

## Skills Demonstrated

**Forensics:** memory, disk and firewall evidence analysis
**Correlation:** convergence and divergence analysis, clock-skew resolution, temporal anchoring
**Frameworks:** ATT&CK mapping with confirmed / probable / possible confidence
**Impact analysis:** asset-to-data mapping, HIPAA breach assessment from evidence
**Reporting:** dual-audience report, evidence citations, explicit documentation of unknowns

---

## Project Series

| Project | Focus |
|---------|-------|
| 4x00 | Phishing email investigation and IOC extraction |
| 4x01 | Network forensics from PCAP evidence |
| 4x02 | Intelligence-driven defense against HEALTHBANE |
| 4x03 | Malware awareness: static and dynamic analysis |
| 4x04 | Threat hunting for Stage 4 lateral movement |
| **4x05** (this project) | Attack reconstruction and impact assessment |

---

*Educational project completed as part of the DLH Cybersecurity Academy curriculum. All organizations, personnel and incident details belong to a training scenario.*
