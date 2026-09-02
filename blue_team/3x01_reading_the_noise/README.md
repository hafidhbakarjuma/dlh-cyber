# Reading the Noise: Behavioral Baseline & Anomaly Detection Pipeline

**A CLI-driven detection engineering toolkit that learns what "normal" looks like across a hospital network's authentication, process, and network telemetry — then surfaces the handful of events that actually deserve a human's attention.**

![Status](https://img.shields.io/badge/status-active-brightgreen)
![Language](https://img.shields.io/badge/scripts-bash%20%2B%20python3-blue)
![Data](https://img.shields.io/badge/format-JSON%20%2F%20NDJSON-lightgrey)
![Domain](https://img.shields.io/badge/Security%2B-4.4%20%7C%204.9-informational)

---

## Table of Contents

- [Overview](#overview)
- [Scenario](#scenario)
- [Why This Project Exists](#why-this-project-exists)
- [Pipeline Architecture](#pipeline-architecture)
- [Task Breakdown](#task-breakdown)
- [Quick Start](#quick-start)
- [Baseline & Evaluation Windows](#baseline--evaluation-windows)
- [Pipeline Performance](#pipeline-performance)
- [Core Detection Engineering Principles](#core-detection-engineering-principles)
- [Operational Requirements](#operational-requirements)
- [Repository Structure](#repository-structure)
- [Roadmap](#roadmap)

---

## Overview

Alert fatigue isn't caused by too little data — it's caused by too little *context*. A single failed login, a single unfamiliar process, a single unrecognized network destination: each looks harmless in isolation. This project builds the missing context layer: a behavioral baseline for every host, account, and time window in the environment, and a correlation engine that turns isolated low-confidence signals into a small number of high-confidence analyst leads.

The pipeline takes the enriched, timeline-indexed evidence produced by the upstream evidence pipeline and runs it through four stages: **taxonomy normalization**, **behavioral baselining**, **anomaly detection** (across auth, process, and network sources), and **cross-source correlation** — closing with a **backtest validation** step that proves the baselines are trustworthy before anyone relies on them in production.

## Scenario

Built for MedDefense Health Systems, a hospital group with three sites, roughly two thousand employees, and a dozen production servers that had never had a documented baseline of normal activity. Nobody could answer basic operational questions — how many failed logins are typical on a Tuesday morning, which processes are expected on the patient portal, which external destinations the billing server should be talking to — which meant every alert was equally suspicious, or equally ignorable, depending on who was on shift.

The dataset is eight days of enriched telemetry handed off from the evidence pipeline built in the prior project: twelve hosts, six source types, tens of thousands of events. The first seven days are a confirmed-clean administrative and clinical-operations baseline; the eighth day is unreviewed and reportedly contains activity that slipped past manual review. The mission: build the baselines, hunt the eighth day against them, correlate what's found across sources, and rank the output so the most dangerous item surfaces first — without ever being told in advance what to look for.

## Why This Project Exists

1. **Canonical taxonomy normalization** — standardize heterogeneous log sources (`linux_text`, auth, process, network) into one unified structure before anything else is possible.
2. **Behavioral profiling** — compute historical baselines per host, account, and time-of-day/week distribution over a clean training window.
3. **Single-source anomaly detection** — isolate deviations: unknown accounts, failure bursts, rare process executions, unfamiliar parent-child process lineages, off-hours logins.
4. **Cross-source correlation** — cluster multi-vector anomalies within a tight time window to collapse noise into a small number of high-fidelity leads.
5. **Baseline backtesting** — validate the pipeline itself using signal-to-noise measurement, so the baseline can be trusted before it's used against real traffic.

The stakes are not hypothetical: the 2020 SolarWinds campaign evaded detection for nine months precisely because the malicious activity mimicked legitimate protocols, tools, account names, and traffic volumes. The organizations that caught it early were the ones that had already written down their own environment's behavioral fingerprint — which is exactly what this project does, at hospital scale.

## Pipeline Architecture

```
Raw Logs / NDJSON
        │
        ▼
┌─────────────────────────────────┐
│ Task 3: Taxonomy & Labeling      │  3-event_taxonomy.sh
│ → labeled_events.json            │
└─────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────┐
│ Task 9: Behavioral Baselines     │  9-baseline_summary.sh
│ → baseline_summary.json          │
└─────────────────────────────────┘
        │
        ├──▶ Task 10: Auth Anomalies      → anomalies_auth.json
        ├──▶ Task 11: Process Anomalies   → anomalies_process.json
        └──▶ Task 12: Network Anomalies   → anomalies_network.json
                        │
                        ▼
        ┌─────────────────────────────────┐
        │ Task 13: Cross-Source            │  13-correlate_anomalies.sh
        │ Correlation (300s window)        │
        │ → correlated_anomalies.json      │
        └─────────────────────────────────┘
                        │
                        ▼
        ┌─────────────────────────────────┐
        │ Task 15: Baseline Validation      │  15-baseline_validation.sh
        │ → baseline_validation.json        │
        └─────────────────────────────────┘
```

## Task Breakdown

| Task | Script | Description | Output |
|---|---|---|---|
| T3 | `3-event_taxonomy.sh` | Normalizes raw logs into canonical labels and a unified event schema | `labeled_events.json` |
| T9 | `9-baseline_summary.sh` | Computes behavioral profiles and defines baseline/evaluation window boundaries | `baseline_summary.json` |
| T10 | `10-anomalies_auth.sh` | Detects authentication anomalies — unknown accounts, failure bursts, off-hours logins | `anomalies_auth.json` |
| T11 | `11-anomalies_process.sh` | Detects process execution anomalies — unbaselined binaries, unusual tooling | `anomalies_process.json` |
| T12 | `12-anomalies_network.sh` | Detects network anomalies — unknown destinations, unexpected ports | `anomalies_network.json` |
| T13 | `13-correlate_anomalies.sh` | Clusters multi-source anomalies occurring within a 300-second window | `correlated_anomalies.json` |
| T15 | `15-baseline_validation.sh` | Backtests the baseline against its own training window to compute signal-to-noise ratio | `baseline_validation.json` |
| T16 | `baseline_package/` | Self-contained toolkit — runnable against any fresh evidence handoff | — |

## Quick Start

**Prerequisites:** a Linux/Bash environment, Python 3.x (standard library only — `json`, `datetime`, `collections`, `hashlib`), and the environment configuration script `m3_env.sh`.

```bash
# 1. Load environment configuration
source ~/m3_env.sh

# 2. Normalize and label raw telemetry
./3-event_taxonomy.sh

# 3. Compute behavioral baselines
./9-baseline_summary.sh

# 4. Run the anomaly detection engines
./10-anomalies_auth.sh
./11-anomalies_process.sh
./12-anomalies_network.sh

# 5. Correlate findings across sources
./13-correlate_anomalies.sh

# 6. Validate baseline quality and signal-to-noise ratio
./15-baseline_validation.sh
```

The pipeline reads its input from the `HANDOFF_DIR` environment variable (defaulting to `~/3x00_handoff/evidence_handoff/` if unset) — never a hardcoded path — so it can be pointed at any fresh evidence drop with zero configuration changes.

## Baseline & Evaluation Windows

The enriched dataset spans eight days, split by default into:

- **Baseline window** — days 1–7, confirmed-clean administrative and clinical operations
- **Evaluation window** — day 8, the most recent 24 hours, unreviewed

Window boundaries are derived from the dataset itself at runtime, never hardcoded — an optional `BASELINE_DAYS` environment variable can override the default seven-day split for testing. All anomaly thresholds are derived from the baseline file at runtime rather than written into scripts as literals, so the same code adapts automatically to a different environment's normal.

## Pipeline Performance

**Alert compression:** the three single-source detectors (T10–T12) generated a combined **38 raw anomalies** (10 auth, 15 process, 13 network). Cross-source correlation (T13) compressed that volume into **7 high-confidence correlated findings** — pushing genuine multi-vector leads to the top of the queue instead of burying them in single-source noise.

**Baseline backtesting:** validation (T15) re-runs the detection engine against its own training window as a self-check, enforcing a strict false-alarm ceiling (**< 5**) and requiring a healthy signal-to-noise ratio (**≥ 3.0**) before the baseline is considered production-ready.

## Core Detection Engineering Principles

- **Anomaly ≠ incident.** A high correlation score — for example, a score of 26 spanning process execution, privilege escalation, and outbound network activity within 90 seconds — is a strong analytical lead, not a confirmed compromise. Automated containment without human triage risks operational outages in a hospital environment where uptime is a patient-safety issue.
- **Temporal baselining beats blind allow-listing.** A known account logging in successfully at 03:17 on a clinical workstation with zero historical night activity must still raise a flag. Suppressing alerts just because the account is "known" creates a blind spot that valid credential misuse walks straight through.
- **Baseline contamination is a real risk.** If early-stage persistence is already present when the baseline window is recorded, it gets learned as "normal." Production pipelines guard against this with authoritative asset inventories, pre-baseline threat hunts, peer-group comparison, and sliding windows with decay.

## Operational Requirements

- **Idempotent** — every script produces identical output on repeated runs against the same input.
- **No hardcoded paths** — the handoff directory is read from `HANDOFF_DIR`; no path is tied to a specific student or home directory.
- **Shell scripts** — start with `#!/bin/bash` and pass `shellcheck` cleanly.
- **Python scripts** — target `python3` and run clean under `python3 -W error`.
- **JSON / NDJSON only** — all baseline and anomaly artifacts are JSON or newline-delimited JSON.
- **No external dependencies at runtime** — no task queries a SIEM, API, or network service; everything runs as CLI against the local handoff files.
- **Self-contained toolkit** — the final `baseline_package/` must run against any fresh evidence handoff with zero configuration.
- **Newline-terminated files** — every file in the repository ends with a trailing newline.

## Repository Structure

```
3x01_baseline_anomaly_detection/
├── 3-event_taxonomy.sh          # Task 3  — taxonomy normalization
├── 9-baseline_summary.sh        # Task 9  — behavioral baseline computation
├── 10-anomalies_auth.sh         # Task 10 — authentication anomaly detection
├── 11-anomalies_process.sh      # Task 11 — process anomaly detection
├── 12-anomalies_network.sh      # Task 12 — network anomaly detection
├── 13-correlate_anomalies.sh    # Task 13 — cross-source correlation
├── 15-baseline_validation.sh    # Task 15 — backtesting & validation
├── labeled_events.json          # Output of Task 3
├── baseline_summary.json        # Output of Task 9
├── anomalies_auth.json          # Output of Task 10
├── anomalies_process.json       # Output of Task 11
├── anomalies_network.json       # Output of Task 12
├── correlated_anomalies.json    # Output of Task 13
├── baseline_validation.json     # Output of Task 15
└── baseline_package/            # Task 16 — self-contained, reusable toolkit
```

## Roadmap

- [ ] Package `baseline_package/` (Task 16) for one-command reuse against any fresh handoff
- [ ] Add peer-group comparison to reduce single-host baseline contamination risk
- [ ] Add sliding-window baselines with decay for longer-running deployments
- [ ] Feed correlated findings forward into the Module 3x02 detection rule set
- [ ] Add automated regression tests for each detection script

---

*Part of the MedDefense SOC portfolio series — the analytical toolkit built on top of the Module 3x00 evidence pipeline handoff.*
