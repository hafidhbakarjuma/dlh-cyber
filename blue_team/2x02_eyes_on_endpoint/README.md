# Eyes on the Endpoint — MedDefense

## Overview

**Eyes on the Endpoint** is the MedDefense endpoint telemetry engineering project.

The previous projects focused on **hardening** Windows and Linux systems. This project focused on **visibility**: collecting security telemetry, testing whether attacker activity is captured, measuring detection coverage, identifying blind spots, and preparing the telemetry for SOC analysts.

> **Protection reduces what an attacker can do. Telemetry shows what the attacker is doing.**

---

## Lab Environment

| Platform | Host           | Main Telemetry                    |
| -------- | -------------- | --------------------------------- |
| Windows  | DC01           | Sysmon, Security Logs, PowerShell |
| Linux    | billing-srv-01 | auditd, auth.log, syslog          |

---

## Project Workflow

```text
Collect Telemetry
       ↓
Run Controlled Attacks
       ↓
Record Ground Truth
       ↓
Correlate Telemetry
       ↓
Build Detection Matrix
       ↓
Measure Coverage & Quality
       ↓
Validate Handoff
       ↓
SOC Analysis
```

---

## Tasks 0–19

### Tasks 0–6 — Telemetry Collection

Built the Windows and Linux telemetry foundation.

**Windows:**

* Sysmon process, network, file, registry and DNS events
* Windows Security events
* PowerShell Script Block Logging, especially Event ID 4104

**Linux:**

* auditd syscall-level telemetry
* Process execution
* File access
* Network sockets
* Privilege-related activity
* auth.log/syslog

---

### Tasks 7–10 — Attack Simulation & Detection

Performed controlled attacker-like actions such as:

* Process execution
* Network connections
* File operations
* Registry changes
* Privilege-related activity
* Suspicious PowerShell commands

Created **ground truth** describing what was actually executed and compared it against the telemetry captured.

Detection results were classified as:

```text
CAPTURED
PARTIAL
MISSED
```

This proved whether the telemetry actually detected the simulated behavior.

---

### Tasks 11–13 — Quality & Handoff

Evaluated telemetry quality using:

* Event counts
* Required fields
* Timestamp coverage
* Source distribution
* Event categories
* Detection coverage

Telemetry was exported into structured JSON for SOC consumption.

Main handoff files:

```text
telemetry_handoff/
├── windows_events.json
├── linux_events.json
└── attack_ground_truth.json
```

---

### Task 14 — Coverage Assessment

Created:

```text
14-coverage_assessment.sh
```

which produces:

```text
telemetry_coverage_assessment.json
```

The assessment reports:

* Windows/Linux event totals
* Source and event-category distribution
* Captured and missed actions
* Multi-source detections
* MITRE ATT&CK coverage
* Known telemetry gaps
* Windows/Linux quality scores
* Final confidence rating

---

### Task 15 — Handoff Validation

Created:

```text
15-handoff_validation.sh
```

The script validates the telemetry package before it is handed to the SOC.

It checks:

* Required files exist
* JSON is valid
* Required fields are present
* Minimum event counts
* Timestamp validity
* No future timestamps
* Windows/Linux time-range overlap
* Ground truth has corresponding detection entries

Final result:

```text
VERDICT: PASS
```

or:

```text
VERDICT: FAIL
```

---

### Tasks 16–19 — Security Review

The final tasks focused on understanding the results.

Key lessons:

* **Telemetry is not protection.**
* A logging event existing does not automatically mean a detection works.
* Ground truth is required for reliable detection validation.
* PowerShell Event ID **4104** provides important script-level evidence.
* 5/6 detection coverage is useful but still leaves a blind spot.
* Auditing everything can create excessive noise.
* Windows and Linux provide different visibility strengths.
* Detection coverage should be measured as **covered, partial, or blind**.

---

## Important Telemetry

### Windows

| Event           | Purpose               |
| --------------- | --------------------- |
| Sysmon 1        | Process creation      |
| Sysmon 3        | Network connection    |
| Sysmon 7        | Image/DLL load        |
| Sysmon 10       | Process access        |
| Sysmon 11       | File creation         |
| Sysmon 13       | Registry modification |
| Sysmon 22       | DNS query             |
| Security 4624   | Successful logon      |
| Security 4625   | Failed logon          |
| Security 4688   | Process creation      |
| PowerShell 4104 | Script Block Logging  |

### Linux

```text
auditd
├── Process execution
├── File access
├── Privilege activity
└── Network sockets

auth.log / syslog
├── Authentication
├── SSH
└── System activity
```

---

## Key Deliverables

```text
14-coverage_assessment.sh
15-handoff_validation.sh

telemetry_coverage_assessment.json
handoff_validation.json

windows_detection_matrix.json
linux_detection_matrix.json
sysmon_coverage_matrix.json

windows_telemetry_quality.json
linux_telemetry_quality.json

telemetry_handoff/
├── windows_events.json
├── linux_events.json
└── attack_ground_truth.json
```

---

## What I Learned

The main lesson from this project is that **security is not only about preventing attacks; it is also about seeing them when prevention fails**.

I learned how to collect endpoint telemetry, simulate attacker behavior, establish ground truth, validate detections, measure coverage, identify blind spots, assess telemetry quality, and produce a structured handoff for SOC analysts.

```text
Harden → Instrument → Simulate → Capture
        → Correlate → Measure → Validate → Handoff
```

**Eyes on the Endpoint = making hardened systems observable and defensible.**
