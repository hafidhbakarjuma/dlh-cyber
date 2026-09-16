# The 24-Hour Watch — MedDefense Capstone Shift Operation

**The full-chain capstone: one unseen 24-hour evidence pack, one shift, every skill from Modules 3x00–3x04 run end to end — pipeline, baselines, detection catalog, triage, cross-platform investigation, and a cryptographically manifested handoff package a Tier 2 analyst can act on without a single follow-up call.**

![Status](https://img.shields.io/badge/status-capstone-critical)
![Language](https://img.shields.io/badge/scripts-bash%20%2B%20python3-blue)
![Data](https://img.shields.io/badge/format-JSON%20%2F%20JSONL-lightgrey)
![Threat](https://img.shields.io/badge/advisory-HC--RED7-red)
![Security+](https://img.shields.io/badge/Security%2B-Domain%204-informational)

---

## Table of Contents

- [Overview](#overview)
- [Scenario — Heightened Monitoring Posture](#scenario--heightened-monitoring-posture)
- [Why This Project Exists](#why-this-project-exists)
- [The Evidence Pack](#the-evidence-pack)
- [What's Known Going In](#whats-known-going-in)
- [Shift Workflow](#shift-workflow)
- [Workspace Structure](#workspace-structure)
- [Core Automation Pipeline](#core-automation-pipeline)
- [Investigation Standards](#investigation-standards)
- [Getting Started](#getting-started)
- [Key Operational Standards](#key-operational-standards)
- [Environment Contract](#environment-contract)
- [Roadmap](#roadmap)

---

## Overview

Every prior module in this series built one piece of the detection chain: 3x00 built the pipeline, 3x01 built the baselines, 3x02 built the detection catalog, 3x03 built the triage floor, and 3x04 built fluency across CLI and SIEM interfaces. None of them asked the question this capstone answers: **can the full chain run, unsupervised, against data never seen before, inside a single shift — and produce a handoff package the next analyst can act on without calling back for clarification?**

This project is that question made operational. A fresh 24-hour evidence pack lands with no advance knowledge of what's inside it. The pipeline runs against raw logs, baselines execute, the detection catalog fires, triage runs its course, and every incident that surfaces gets investigated, documented, and handed off — with every conclusion traceable to a specific, counted observation.

## Scenario — Heightened Monitoring Posture

An ISAC advisory confirmed that a threat cluster designated **HC-RED7** has been targeting regional healthcare networks for six weeks, with three hospitals in the region already confirming intrusions tied to it. Initial access comes through a mix of credential compromise and targeted phishing; the cluster installs service-based persistence, beacons on an irregular interval, and stages data against approved business processes specifically to blend in with legitimate activity.

SOC Lead James Chen has activated the shift pack protocol under Dr. Morales' authorization for 24 hours of heightened monitoring. The job for the shift:

1. Run the pipeline against the fresh evidence pack
2. Run baselines and fire the detection catalog
3. Triage everything that fires
4. Investigate identified incidents using both CLI tools and Wazuh exports
5. Document each incident, map ATT&CK techniques, propose tuning, and assemble the full shift handoff package

The standing instruction for ambiguous cases: **document the ambiguity, note what would resolve it, and escalate on paper rather than guessing or closing prematurely.**

## Why This Project Exists

Sustained analytical operation under time pressure with imperfect information is the single skill that the BTL1 practical, real SOC blue-team rotations, and Security+ Domain 4 all converge on. Every task here maps to a deliverable a real Tier 1 analyst produces during an actual shift — a running pipeline, a triaged queue, investigation findings, incident reports, tuning proposals, and a clean handoff — and every one of those deliverables is **countable**, so a grader (or a hiring manager) never has to guess whether the work is "good enough." This is also the project that becomes the strongest portfolio exhibit: rather than describing a SOC shift in theory, this is a directory, a `MANIFEST.json`, and a set of JSON files that prove each phase actually happened.

## The Evidence Pack

Delivered at `$CAPSTONE_PACK`, captured from MedDefense production sources during a real 24-hour window, in the same input format 3x00 already expects — no shortcut around the pipeline:

- Windows `.evtx` exports from three sites (clinical, radiology, billing)
- Linux `syslog`, `auth.log`, and `audit.log` from endpoints and servers
- Sysmon JSON telemetry from the endpoints hardened in Module 2
- Suricata `eve.json` IDS alerts
- Firewall logs in CEF-like format
- Network artifacts (PCAP slices, NetFlow summaries)
- Updated asset inventory (`assets.json`) — site, zone, criticality, data classification
- The HC-RED7 IOC feed (`ioc_feed.json`) — network and host indicators
- ISAC advisory summary (`hc_red7_advisory.md`)
- Change management log for the window (`change_tickets.json`)
- Partial triage log from the previous shift (`prior_shift_notes.md`)

## What's Known Going In

Disclosed up front — deliberately, since discovering these through trial and error would waste shift time better spent investigating:

- **At least three incidents** are hidden in the pack
- **At least one** matches the HC-RED7 IOC feed
- **At least one is ambiguous** and requires context beyond the raw events to resolve
- The pack contains **realistic dirty data**: clock skew on one host, a duplicate event stream on another, a Sysmon telemetry gap during an agent restart, and malformed syslog lines
- Some firing alerts are **false positives tied to approved change activity**
- Some firing alerts are **noise**, to be batch-closed with justification

What is *not* disclosed: which host is compromised, which user is involved, or which rule catches which incident. Grading is based on countable outputs, not on matching a specific expected narrative.

## Shift Workflow

```
$CAPSTONE_PACK (raw, unseen evidence)
            │
            ▼
   Pipeline (3x00 logic) → enriched/enriched_events.jsonl
            │
            ▼
   Baselines (3x01 logic) → enriched/baseline.json
            │
            ▼
   Detection catalog fires (3x02 logic) → alerts/alert_queue.json
            │
            ▼
   Triage (3x03 logic) → alerts/triage_log.jsonl → alerts/incidents.json
            │
            ▼
   Investigation — CLI + Wazuh exports (3x04 fluency)
            │
            ▼
   investigations/incident_A.json, incident_B.json, incident_C_cli.json
            │
            ▼
   Campaign correlation → campaign/campaign_assessment.json
            │
            ▼
   Incident reports (11-incident_reports.sh) → reports/*.md
            │
            ▼
   Containment + IOC packaging (13-containment_package.sh) → response/
            │
            ▼
   Shift handoff + MANIFEST.json (14-shift_handoff.sh) → handoff/
```

## Workspace Structure

The shift workspace (`$SHIFT_WORKSPACE`) follows a strict, locked layout required for verification and cryptographic manifesting:

```
blue_team/3x05_the_24_hour_watch/
├── 11-incident_reports.sh          # Automated Markdown incident report generator
├── 13-containment_package.sh       # Prioritized containment list & TLP:AMBER IOC package generator
├── 14-shift_handoff.sh             # Workspace validation, handoff compilation, & MANIFEST.json creator
├── alerts/
│   ├── alert_queue.json            # Raw incoming alert queue
│   ├── shift_briefing.json         # Shift context and advisory notes
│   ├── triage_log.jsonl            # Chronological analyst triage log
│   └── incidents.json              # Validated shift incidents
├── enriched/
│   ├── baseline.json               # Asset and environment baseline data
│   └── enriched_events.jsonl       # Enriched security telemetry
├── investigations/
│   ├── incident_A.json             # Deep-dive investigation findings for Incident A
│   ├── incident_B.json             # Deep-dive investigation findings for Incident B
│   └── incident_C_cli.json         # Deep-dive investigation findings for Incident C
├── campaign/
│   └── campaign_assessment.json    # Cross-incident cluster assessment & linkage metrics
├── reports/                        # Generated bounded Markdown reports (A, B, C)
├── response/
│   ├── containment.json            # Prioritized, bounded containment actions
│   └── ioc_package.json            # Shareable TLP:AMBER defanged indicator package
├── handoff/
│   └── shift_handoff.md            # Structured checklist-based handoff document
└── MANIFEST.json                   # Cryptographic SHA-256 manifest of all shift artifacts
```

## Core Automation Pipeline

**1. Incident Report Generation** — `11-incident_reports.sh`
Parses raw investigation files, the asset database, and enriched telemetry to generate standardized Markdown reports (`incident_A.md`, `incident_B.md`, `incident_C.md`). Enforces strict caps to keep reports actionable rather than exhaustive: 3–5 sentence executive summaries, ≤15 timeline events, ≤10 affected-asset rows, ≤15 defanged IOC entries, and every cited event independently traceable back to source.

**2. Containment & IOC Packaging** — `13-containment_package.sh`
Derives prioritized containment actions — **Immediate**, **Short-term**, **Medium-term** — each mapped to a specific incident ID, its operational impact, and the approval workflow it requires. Compiles both newly discovered and feed-backed indicators into an H-ISAC / peer-hospital-shareable **TLP:AMBER** package (`ioc_package.json`), with every network indicator automatically defanged (e.g. `198[.]51[.]100[.]73`).

**3. Handoff Assembly & Manifest Creation** — `14-shift_handoff.sh`
Validates that every required file in the workspace layout exists and is non-empty before proceeding. Compiles a structured, ≤900-word handoff document (`handoff/shift_handoff.md`) covering all six mandatory operational sections. Recursively computes file sizes and SHA-256 hashes for every artifact produced during the shift, writing the tamper-evident `MANIFEST.json`.

## Investigation Standards

Every artifact in this project holds to the same evidentiary bar, regardless of which script or analyst produced it:

- **All timestamps are UTC, ISO-8601** — no ambiguity across the three sites or log sources
- **All IP addresses inside report files are defanged** using the `a[.]b[.]c[.]d` convention
- **Every cited event references a real entry** in `$SHIFT_WORKSPACE/enriched/enriched_events.jsonl` or a raw file under `$CAPSTONE_PACK/`
- **Every incident report, tuning entry, and IOC traces back to at least one counted observation** — no conclusion is asserted without a citable source

## Getting Started

Ensure `$SHIFT_WORKSPACE` and `$ASSETS_DIR` are correctly exported, then run the pipeline scripts in sequence:

```bash
# 1. Generate structured incident reports
./11-incident_reports.sh

# 2. Produce prioritized containment actions and the TLP:AMBER IOC package
./13-containment_package.sh

# 3. Validate workspace layout, compile the handoff markdown, and generate MANIFEST.json
./14-shift_handoff.sh
```

## Key Operational Standards

- **Strict handoff enforcement** — the pipeline aborts immediately if any required artifact is missing or empty, protecting the incoming shift from operational blind spots and compliance gaps.
- **Mechanical campaign correlation** — incidents are linked via deterministic tradecraft overlap and tight temporal windows (≤24 hours), never subjective narrative-matching.
- **Defanged threat sharing** — every network indicator exported for external sharing is automatically defanged to prevent accidental callback or secondary exposure.
- **Bash scripting discipline** — every script is executable (`chmod +x`), starts with `#!/bin/bash`, and exits non-zero on failure so a broken stage never silently produces a corrupt handoff.
- **Newline-terminated files** — every file in the repository ends with a trailing newline.

## Environment Contract

| Variable | Purpose |
|---|---|
| `$CAPSTONE_PACK` | Path to the fresh, unseen 24-hour evidence pack |
| `$SHIFT_WORKSPACE` | Root of this project's locked workspace layout |
| `$ASSETS_DIR` | Supporting assets — asset inventory, IOC feed, advisory summary |

## Roadmap

- [ ] Automate campaign-assessment scoring so linkage confidence is fully derivable from tradecraft overlap and time-window proximity without manual review
- [ ] Extend `MANIFEST.json` verification into a standalone pre-handoff check script, runnable independently of the full pipeline
- [ ] Add a post-shift retrospective template capturing which HC-RED7 tuning proposals were adopted downstream
- [ ] Fold confirmed HC-RED7 detections back into the 3x02 detection catalog as permanent, tuned rules

---

*The MedDefense SOC portfolio capstone — the full-chain proof point built on top of the 3x00 evidence pipeline, 3x01 baseline package, 3x02 detection catalog, 3x03 Tier 1 triage, and 3x04 cross-platform investigation handoffs.*
