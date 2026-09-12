# MedDefense Health Systems — Tier 1 SOC Triage Operations

**A flat-file-driven alert triage pipeline that takes a live detection queue from zero to a fully documented, audit-ready `triage_package/` — classification, escalation, correlation, and shift metrics included.**

![Status](https://img.shields.io/badge/status-active-brightgreen)
![Language](https://img.shields.io/badge/scripts-bash%20%2B%20python3-blue)
![Data](https://img.shields.io/badge/format-JSON-lightgrey)
![Domain](https://img.shields.io/badge/role-SOC%20Tier%201-critical)

---

## Table of Contents

- [Overview](#overview)
- [Scenario](#scenario)
- [Why This Project Exists](#why-this-project-exists)
- [Data Sources](#data-sources)
- [Triage Workflow](#triage-workflow)
- [Task Breakdown](#task-breakdown)
- [Triage Methodology](#triage-methodology)
- [Classification Taxonomy](#classification-taxonomy)
- [Shift Deliverables](#shift-deliverables)
- [Sample Shift Metrics](#sample-shift-metrics)
- [Operational Requirements](#operational-requirements)
- [Repository Structure](#repository-structure)
- [Roadmap](#roadmap)

---

## Overview

A detection engine can fire an alert. It cannot decide whether that alert matters. This project is the human-judgment layer that sits on top of the MedDefense detection catalog (3x02): every alert in a live queue gets classified, justified, and either closed or escalated — with the reasoning and evidence recorded well enough that Tier 2 never has to redo the work, and Compliance can reconstruct exactly what happened months later.

There is no SIEM dashboard here. The entire shift runs against five flat JSON files and a set of purpose-built triage scripts — because a Tier 1 analyst who can only click through a dashboard is stuck the moment the dashboard is unavailable or the investigation needs a field the UI doesn't expose.

## Scenario

Working as a Tier 1 SOC analyst for MedDefense Health Systems, on the first shift where the detection catalog built in the prior project (3x02) is live and producing a real, populated alert queue overnight. The queue is realistic for a small hospital SOC on a quiet Tuesday: a handful of clear true positives needing fast escalation, a larger batch of clear false positives that need to be closed with justification, a middle block of genuinely ambiguous alerts where classification depends on context that has to be actively fetched, and a pocket of correlated alerts where two or three queue entries actually describe one underlying incident.

The mandate from SOC Lead James Chen is threefold: triage and document every alert with a structured ticket (no free-form "looks fine" closures), assemble a clean Tier-2-ready escalation package for every true positive, and produce a shift report plus `triage_package/` directory that Compliance can audit and that stands as the concrete output of MedDefense's first analyst shift. Any rule generating false positives also needs a specific, actionable tuning recommendation — not "fix the rule," but which exclusion to add or threshold to change, and the expected effect on TP/FP counts.

## Why This Project Exists

Alert triage is the highest-volume skill in defensive security — a Tier 1 analyst processes 100–500 alerts per shift, and the industry-average false positive rate sits around 45%. That means roughly half of what the pipeline flags is wrong on any given day, and the entire job is telling which half, consistently, under time pressure, with incomplete information. Three numbers define SOC operational health — **MTTD** (mean time to detect), **MTTR** (mean time to respond), and **false positive rate** — and triage quality drives all three directly. This project produces one full shift's worth of triage, on real alert data, in a form that documents not just the decisions but the reasoning behind them.

## Data Sources

The shift runs entirely against five flat files — no SIEM, no dashboard:

| Source | Origin | Purpose |
|---|---|---|
| `alert_queue.json` | 3x02 detection catalog | The queue itself — every alert to be triaged |
| `asset_inventory.json` | 3x00 evidence pipeline | Which host each alert hit, and how critical that host is |
| `baseline_summary.json` | 3x01 baseline package | What "normal" looks like, for comparing observed patterns against a baseline |
| `enriched_events.json` | 3x00 evidence pipeline | The underlying event store every alert references |
| `ioc_context.json` | Threat intel integration (`~/3x03_assets/`) | Reputation, geolocation, and threat-feed category tags for every external IP/domain a detection touched |

## Triage Workflow

```
alert_queue.json + asset/baseline/event/IOC context
            │
            ▼
┌──────────────────────────────────┐
│ 2-context_assembly.sh             │  Merges all five sources into one
│ → enriched_queue.json             │  unified, queryable record set
└──────────────────────────────────┘
            │
            ▼
┌──────────────────────────────────┐  ┌──────────────────────────────────┐
│ 3-triage_clearcut_tp.sh           │  │ 4-triage_clearcut_fp.sh          │
│ Clear true positives → escalate   │  │ Clear false positives → close    │
│ → batch1_clearcut_tp.json         │  │ → batch2_clearcut_fp.json        │
└──────────────────────────────────┘  └──────────────────────────────────┘
            │                                       │
            ▼                                       │
┌──────────────────────────────────┐                │
│ 6-triage_ambiguous_auth.sh        │                │
│ Auth anomalies vs. history        │                │
└──────────────────────────────────┘                │
            │                                       │
            ▼                                       │
┌──────────────────────────────────┐                │
│ 7-triage_ambiguous_proc_net.sh    │                │
│ Process/network vs. IOC + baseline│                │
└──────────────────────────────────┘                │
            │                                       │
            ▼                                       ▼
┌──────────────────────────────────────────────────────────┐
│ 8-triage_correlation.sh                                    │
│ Groups same-host alerts within a 600s window into           │
│ consolidated incidents → batch6_incidents.json              │
└──────────────────────────────────────────────────────────┘
            │
            ▼
┌──────────────────────────────────┐
│ 11-incident_assembly.sh           │  Compiles TPs + correlated incidents
│ → incidents.json                  │  into full Tier 2 handover records
└──────────────────────────────────┘
```

## Task Breakdown

| Task | Script / Doc | What It Does |
|---|---|---|
| 1 | `triage_methodology.md` | Bounded (~380 word) methodology doc: classification taxonomy, priority ordering, evidence requirements, escalation criteria, SLAs, documentation standards |
| 2 | `2-context_assembly.sh` | Merges the alert queue with asset inventory, enriched events, baseline summaries, and IOC context into one `enriched_queue.json` |
| 3 | `3-triage_clearcut_tp.sh` | Filters critical alerts with malicious IOCs and clear baseline deviations, escalates to Tier 2, writes `tickets/batch1_clearcut_tp.json` |
| 4 | `4-triage_clearcut_fp.sh` | Identifies authorized service-account activity, management-subnet traffic, and baseline-matching processes; tags each with an `fp_reason`, writes `tickets/batch2_clearcut_fp.json` |
| 6 | `6-triage_ambiguous_auth.sh` | Resolves authentication anomalies against historical login patterns, source IPs, failure bursts, and asset criticality |
| 7 | `7-triage_ambiguous_proc_net.sh` | Evaluates ambiguous process executions and outbound connections by joining event records with IOC reputation and baseline host distributions |
| 8 | `8-triage_correlation.sh` | Groups related alerts on the same host within a 600-second sliding window into consolidated incident packages (`tickets/batch6_incidents.json`) |
| 11 | `11-incident_assembly.sh` | Compiles every confirmed true positive and correlated incident into full Tier 2 handover records (`incidents.json`) |

## Triage Methodology

Documented in full in [`triage_methodology.md`](./triage_methodology.md). Covers:

- **Classification taxonomy** — the operational definitions used to sort every alert
- **Priority ordering rule** — how rule severity, asset criticality, and baseline deviation combine into a single triage priority
- **Evidence requirement** — what must be referenced before a classification is valid
- **Escalation criteria** — the bar an alert must clear to become a Tier 2 incident rather than a closed ticket
- **SLAs** — time targets for triage-to-decision by priority tier
- **Documentation standards** — the minimum structure every ticket must contain

## Classification Taxonomy

- **True Positive** — the alert reflects genuinely malicious or unauthorized activity and is escalated.
- **False Positive** — the rule fired correctly on activity that turns out to be authorized or benign. Critically: a rule that correctly triggers on *authorized* activity is still a false positive — correct rule behavior and correct classification are not the same thing.
- **Benign** — closed with justification but distinct from a false positive where relevant (e.g. expected noise vs. a rule matching legitimate business activity).
- **Correlated Incident** — two or more individually-ambiguous or individually-low-severity alerts that, grouped together, describe one underlying event and must be triaged as a unit rather than independently.

Classification for a given rule is **context-dependent** — the same rule firing on `patch-srv-01` talking to an internal update server and on an unrecognized external host with a flagged IOC can land in opposite categories. Baseline data, asset criticality, and IOC enrichment exist specifically to resolve that ambiguity without re-running a full investigation from scratch each time.

## Shift Deliverables

The shift's output is a single `triage_package/` directory, structured to survive a Compliance audit on its own:

- **Structured tickets** for every alert — classification, justification, and referenced evidence, no free-form closures
- **Escalation packages** for every true positive — timeline, affected assets, extracted IOCs, ATT&CK technique mapping (from the source rule), and a recommended first containment action
- **Rule tuning recommendations** for any rule producing false positives — specific exclusion or threshold change, plus expected impact on TP/FP counts
- **Shift handoff report** — the numbers, the notable cases, and open items for the next analyst and for Tier 2

## Sample Shift Metrics

Illustrative of the kind of end-of-shift numbers this pipeline produces and that a shift report is built around:

| Metric | Example Value |
|---|---|
| Queue size | 38 |
| False positive rate | 0.29 |
| MTTD | 00:14:22 |
| MTTR | 00:23:41 |
| SLA compliance | 94.7% |
| Escalation ratio | 0.158 |

A per-rule false positive rate significantly above the shift average (e.g. a single rule at 0.60 against a shift average of 0.29) is exactly the kind of signal that turns into a specific, targeted tuning recommendation rather than a generic "this rule is noisy" note.

## Operational Requirements

- **Idempotent** — every script produces identical output on repeated runs against the same input.
- **No hardcoded paths** — all dependency paths are read from environment variables:
  - `CATALOG_DIR` → 3x02 `detection_catalog/` (default `~/3x02_package/detection_catalog/`)
  - `HANDOFF_DIR` → 3x00 `evidence_handoff/` (default `~/3x00_handoff/evidence_handoff/`)
  - `BASELINE_PKG` → 3x01 `baseline_package/` (default `~/3x01_package/baseline_package/`)
  - `ASSETS_DIR` → `~/3x03_assets/`, containing `ioc_context.json`
- **Shell scripts** — start with `#!/bin/bash` and pass `shellcheck` cleanly.
- **Python scripts** — target `python3` and run clean under `python3 -W error`.
- **Newline-terminated files** — every file in the repository ends with a trailing newline.

## Repository Structure

```
3x03_tier1_triage/
├── triage_methodology.md            # Task 1  — triage methodology document
├── 2-context_assembly.sh            # Task 2  — merges all sources into enriched_queue.json
├── 3-triage_clearcut_tp.sh          # Task 3  — clear true positive triage
├── 4-triage_clearcut_fp.sh          # Task 4  — clear false positive triage
├── 6-triage_ambiguous_auth.sh       # Task 6  — ambiguous auth alert resolution
├── 7-triage_ambiguous_proc_net.sh   # Task 7  — ambiguous process/network resolution
├── 8-triage_correlation.sh          # Task 8  — multi-alert correlation
├── 11-incident_assembly.sh          # Task 11 — Tier 2 handover incident assembly
├── enriched_queue.json              # Output of Task 2
├── tickets/
│   ├── batch1_clearcut_tp.json      # Output of Task 3
│   ├── batch2_clearcut_fp.json      # Output of Task 4
│   └── batch6_incidents.json        # Output of Task 8
├── incidents.json                   # Output of Task 11
├── shift_metrics.json               # End-of-shift KPI summary
└── triage_package/                  # Final, audit-ready shift deliverable
```

## Roadmap

- [ ] Automate SLA-compliance tracking per ticket rather than at shift-summary level
- [ ] Feed accepted rule tuning recommendations back into the 3x02 detection catalog
- [ ] Add regression tests for the correlation window logic (Task 8)
- [ ] Extend the shift handoff report template with a trend view across multiple shifts

---

*Part of the MedDefense SOC portfolio series — Tier 1 triage operations built on the 3x00 evidence pipeline, 3x01 baseline package, and 3x02 detection catalog handoffs.*
