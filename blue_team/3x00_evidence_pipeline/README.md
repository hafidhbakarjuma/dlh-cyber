# Security Telemetry Evidence Pipeline

**An automated ingestion, normalization, cleaning, and enrichment pipeline that turns raw, messy security logs into forensically sound, analyst-ready intelligence.**

![Status](https://img.shields.io/badge/status-active-brightgreen)
![Language](https://img.shields.io/badge/scripts-bash-blue)
![Data](https://img.shields.io/badge/format-JSON-lightgrey)

---

## Table of Contents

- [Overview](#overview)
- [Scenario](#scenario)
- [Why This Project Exists](#why-this-project-exists)
- [Full Pipeline Concept](#full-pipeline-concept)
- [Pipeline Architecture](#pipeline-architecture)
- [Pipeline Stages](#pipeline-stages)
  - [1. Normalization](#1-normalization)
  - [2. Data Quality & Forensic Auditability](#2-data-quality--forensic-auditability)
  - [3. Context Enrichment & Zone Routing](#3-context-enrichment--zone-routing)
- [Repository Structure](#repository-structure)
- [Data Schema](#data-schema)
- [Getting Started](#getting-started)
- [Example Use Case](#example-use-case)
- [Design Principles](#design-principles)
- [Operational Requirements](#operational-requirements)
- [Roadmap](#roadmap)

---

## Overview

Security logs coming out of real environments are almost never clean. Timestamps arrive in half a dozen formats, hostnames are capitalized inconsistently across systems, retransmissions create duplicate events, and encoding errors silently corrupt text fields. Left unaddressed, these defects create blind spots in detection, slow down triage, and undermine the integrity of incident investigations.

This project is a pipeline that takes raw logs from Windows endpoints, Linux systems, and network sensors, and turns them into a single, clean, enriched, and fully auditable dataset — ready for SOC analysis, threat hunting, or ingestion into a SIEM.

## Scenario

This project was built as a bridge solution for MedDefense Health Systems during a 48-hour SIEM migration window. With the centralized platform offline, every endpoint, firewall, and network sensor kept producing telemetry with nowhere to go, so raw exports were dropped into a shared directory in whatever format each source system natively produces — Windows EVTX, Linux syslog, Suricata JSON, and firewall CSV exports arriving from five different sources simultaneously.

The mandate: stand up an evidence pipeline capable of ingesting that flood of inconsistent, duplicated, and incomplete data, and turning it into analyst-ready evidence — without a SIEM to do the work automatically. Everything downstream (detection, triage, and investigation work) depends on this pipeline producing a trustworthy, unified dataset. The pipeline also had to be reproducible end-to-end with a single command, so it can be re-run against a fresh data drop in minutes rather than hours.

## Why This Project Exists

The pipeline is built around three goals:

1. **Eliminate schema fragmentation** — unify disparate log sources into one consistent event schema.
2. **Guarantee forensic auditability** — every correction made to the data is detected, logged, and justified, never silently applied.
3. **Add situational context automatically** — enrich every event with asset ownership, criticality, and network zone information so analysts don't need to run manual lookups mid-investigation.

## Full Pipeline Concept

The end-to-end evidence pipeline is designed around seven conceptual stages, from raw file to searchable, validated timeline:

| Stage | Purpose |
|---|---|
| **Intake** | Collect raw exports from every source directory (EVTX, syslog, Suricata EVE JSON, firewall CSV) |
| **Parse** | Convert each source-specific format into structured JSON |
| **Normalize** | Map parsed fields into one unified event schema |
| **Clean** | Detect and repair data-quality defects, with every change logged |
| **Enrich** | Attach asset inventory and network zone context to each event |
| **Index** | Build a chronological, source-attributed timeline for analyst lookup |
| **Validate** | Confirm schema conformance and completeness before handoff |

This README documents the three stages currently implemented in this repository — **Normalization**, **Data Quality**, and **Enrichment** — which form the core of the pipeline. Intake/parsing (per source format) and the indexing/validation stages build on top of these outputs and are noted in the [Roadmap](#roadmap).

## Pipeline Architecture

```
Raw Logs (Windows / Linux / Network Sensors)
            │
            ▼
┌───────────────────────────────┐
│  Stage 1: Normalization        │   5-normalize.sh
│  → normalized_events.json      │
│  → quarantine.json (rejects)   │
└───────────────────────────────┘
            │
            ▼
┌───────────────────────────────┐
│  Stage 2: Data Quality &       │   8-data_quality.sh
│  Forensic Remediation          │
│  → cleaned_events.json         │
│  → cleaning_log.json (audit)   │
└───────────────────────────────┘
            │
            ▼
┌───────────────────────────────┐
│  Stage 3: Context Enrichment   │   9-enrich.sh
│  & Zone Routing                │
│  → enriched_events.json        │
└───────────────────────────────┘
```

Each stage reads only the output of the previous stage, so the pipeline can be re-run, resumed, or debugged one step at a time without reprocessing everything from scratch.

## Pipeline Stages

### 1. Normalization

**Script:** `5-normalize.sh`

Reads raw logs from heterogeneous sources and maps them into one flat, uniform JSON schema.

**What it handles:**
- Timestamp parsing across multiple formats (ISO 8601, Unix epoch, custom string patterns)
- Field mapping from source-specific layouts into a common schema
- Isolation of malformed or incomplete records that are missing core fields

**Output fields:** `timestamp`, `hostname`, `source_type`, `event_category`, `severity`, `user`, `process_name`, `src_ip`, `dst_ip`, `raw_message`

**Why it matters:** Analysts and detection engines (e.g. Sigma rules) can query Windows Sysmon logs and Linux syslog/audit data the same way, without writing source-specific parsing logic for every rule.

### 2. Data Quality & Forensic Auditability

**Script:** `8-data_quality.sh`

Scans the normalized events for known classes of data defects and repairs or removes them — while logging every change.

| Defect | Handling |
|---|---|
| Malformed timestamps | Repaired where possible; unrepairable records are dropped |
| Duplicate events | Exact duplicates from retransmission are removed, keeping the first occurrence |
| Inconsistent hostname casing | Normalized to lowercase |
| Encoding errors / mojibake | Detected and safely re-decoded |
| Timezone anomalies | Flagged when events fall outside expected time windows |

**Why it matters:** Silent data corruption is one of the most dangerous failure modes in a SOC pipeline — it can quietly hide or distort evidence. Every correction here is written to `cleaning_log.json` with the original value, the corrected value, and the reason for the change, so the process itself is defensible in an investigation.

### 3. Context Enrichment & Zone Routing

**Script:** `9-enrich.sh`

Merges static enterprise context directly into each event.

**What it adds:**
- **Asset inventory lookup** — matches `hostname` against an asset database to attach `role`, `criticality`, `os`, `owner`, and `zone`
- **CIDR-based zone resolution** — evaluates `src_ip` / `dst_ip` against defined network boundaries (e.g. `CLINICAL`, `DMZ`, `INTERNET`) to assign `src_zone` and `dst_zone`

**Why it matters:** An analyst looking at an alert can immediately see whether it touches a critical asset (e.g. `db-patient-01`) or crosses a security boundary, without pausing to run manual cross-database lookups mid-investigation.

## Repository Structure

```
3x00_evidence_pipeline/
├── 5-normalize.sh           # Stage 1 — schema normalization
├── 8-data_quality.sh        # Stage 2 — cleaning & forensic logging
├── 9-enrich.sh              # Stage 3 — asset & network zone enrichment
├── normalized_events.json   # Output of Stage 1
├── cleaned_events.json      # Output of Stage 2
├── cleaning_log.json        # Audit trail of every correction made in Stage 2
├── quarantine.json          # Records rejected during Stage 1
└── enriched_events.json     # Final output — fully enriched dataset
```

## Data Schema

Example of a fully processed event in `enriched_events.json`:

```json
{
  "timestamp": "2026-06-14T02:31:07Z",
  "hostname": "db-patient-01",
  "source_type": "windows_sysmon",
  "event_category": "network_connection",
  "severity": "high",
  "user": "svc_backup",
  "process_name": "sqlservr.exe",
  "src_ip": "10.20.5.14",
  "dst_ip": "10.20.50.9",
  "src_zone": "CLINICAL",
  "dst_zone": "DMZ",
  "asset": {
    "role": "database_server",
    "criticality": "critical",
    "os": "Windows Server 2019",
    "owner": "IT-Infrastructure",
    "zone": "CLINICAL"
  },
  "raw_message": "..."
}
```

## Getting Started

```bash
# 1. Normalize raw logs into a unified schema
./5-normalize.sh --input raw_logs/ --output normalized_events.json

# 2. Clean and validate the normalized data
./8-data_quality.sh --input normalized_events.json --output cleaned_events.json

# 3. Enrich with asset and network zone context
./9-enrich.sh --input cleaned_events.json --output enriched_events.json
```

> Adjust flags/paths to match your actual script arguments — update this section once the CLI interface is finalized.

## Example Use Case

An analyst investigating a brute-force alert on `db-patient-01` can query `enriched_events.json` directly and immediately see that the connection crossed from the `CLINICAL` zone into the `DMZ`, that the target asset is marked `critical`, and who owns it — without cross-referencing a separate asset database.

## Design Principles

- **Fail loud, not silent** — defects are corrected transparently and logged, never silently dropped without a trace.
- **Idempotent stages** — each stage can be re-run independently against its own input/output pair.
- **Zero-join analysis** — enrichment happens once, upstream, so downstream detection rules and dashboards don't need external lookups.

## Operational Requirements

This pipeline is built to standards that let another engineer rebuild or rerun it without guesswork:

- **Idempotent** — running any stage twice against the same input produces the same output, so re-running the full pipeline against a fresh data drop is always safe.
- **Portable paths** — no hardcoded home directories; all paths are passed as variables or arguments.
- **Shell scripts** — start with `#!/bin/bash` and pass `shellcheck` cleanly.
- **Python scripts** (where used) — target `python3` and run clean under `python3 -W error` (no syntax warnings).
- **Single-command execution** — the full pipeline is designed to run end to end from one entry point, so it completes against a fresh drop in minutes, not hours.
- **Newline-terminated files** — every file in the repository ends with a trailing newline.

## Roadmap

- [ ] Add intake/parsing stage for raw source formats (Windows EVTX, Linux syslog, Suricata EVE JSON, firewall CSV) ahead of normalization
- [ ] Add chronological, source-attributed timeline indexing stage
- [ ] Add a validation stage to confirm schema conformance and completeness before handoff
- [ ] Wrap all stages into a single end-to-end pipeline script (one command, full run)
- [ ] Add automated tests for each stage
- [ ] Add configuration file for CIDR zone definitions and asset inventory source
- [ ] Add Sigma rule examples that query the enriched schema
- [ ] Package as a scheduled pipeline (cron / systemd timer)

---

*Part of the MedDefense SOC portfolio series — built as the evidence pipeline foundation for Module 3.*
