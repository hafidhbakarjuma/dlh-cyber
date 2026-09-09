# MedDefense Health Systems — Detection Engineering Catalog

**A vendor-neutral, production-grade detection engineering catalog and evaluation pipeline for a HIPAA-regulated healthcare SOC.** Custom Sigma rules, quantitative quality scoring, risk-based prioritization, and an immutable, schema-contracted triage feed — all built to survive contact with a real Tier 1 queue.

![Status](https://img.shields.io/badge/status-active-brightgreen)
![Language](https://img.shields.io/badge/scripts-bash%20%2B%20python3-blue)
![Rules](https://img.shields.io/badge/format-Sigma-orange)
![Compliance](https://img.shields.io/badge/environment-HIPAA--regulated-critical)

---

## Table of Contents

- [Overview](#overview)
- [Why This Project Exists](#why-this-project-exists)
- [Pipeline Architecture](#pipeline-architecture)
- [Toolchain & Task Breakdown](#toolchain--task-breakdown)
- [Directory Structure](#directory-structure)
- [Quick Start](#quick-start)
- [Governance & Quality Gates](#governance--quality-gates)
- [Detection Engineering Specification](#detection-engineering-specification)
- [Design Principles](#design-principles)
- [Roadmap](#roadmap)

---

## Overview

A SIEM with every default rule enabled does not produce security — it produces noise. This catalog exists to turn a pile of Sigma detection ideas into a *measured, prioritized, production-safe* detection program: every rule is scored against ground truth, ranked by actual organizational risk rather than gut feeling, deduplicated before it ever reaches an analyst, and delivered through a schema-locked contract that a downstream triage system can trust without re-validating it.

The catalog is built specifically for MedDefense Health Systems: a healthcare environment where detection gaps and alert fatigue carry patient-safety and HIPAA-compliance consequences, not just operational ones.

## Why This Project Exists

1. **Evidence over intuition** — every rule's real-world performance (precision, recall, F1) is measured against labeled ground truth before it's trusted in production.
2. **Risk over rule count** — prioritization is driven by likelihood × impact against the organization's actual risk register, not by how many rules exist or how loudly they fire.
3. **A stable contract, not a firehose** — the Tier 1 triage shift (3x03) consumes a single, schema-locked alert queue, so upstream tuning and rule changes never break downstream ingestion.

## Pipeline Architecture

```
Sigma Rules (rules/sigma/*.yml)
            │
            ▼
┌───────────────────────────────────┐
│  3-sigma_runner.sh                 │  Executes rules against normalized
│  Rule Execution Engine             │  log data with windowing/aggregation
└───────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────┐
│  10-fp_baseline.sh                 │  Runs rules against clean baseline
│  False Positive Baseline           │  windows → flags noisy signatures
│  → fp_baseline.json                │
└───────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────┐
│  13-rule_quality.sh                │  Precision / recall / F1 against
│  Quality Scoring                   │  labeled ground truth
│  → rule_quality.json               │
└───────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────┐
│  14-rule_prioritization.sh         │  Risk-weighted priority scoring
│  Risk-Based Prioritization         │  (likelihood × impact)
│  → rule_prioritization.json        │
└───────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────┐
│  15-generate_alerts.sh             │  Deduplicated, schema-locked
│  Triage Alert Queue Generation     │  alert feed for 3x03
│  → alert_queue.json                │
│  → alert_queue_schema.json         │
└───────────────────────────────────┘
```

## Toolchain & Task Breakdown

| Task | Script | What It Does |
|---|---|---|
| T3 | `3-sigma_runner.sh` | Core execution engine — translates Sigma rules into query filters and runs them against normalized log datasets, with windowing and aggregation support |
| T10 | `10-fp_baseline.sh` | Evaluates active rules against clean baseline windows to compute false-positive rates and flag noisy signatures needing tuning |
| T13 | `13-rule_quality.sh` | Computes precision, recall, and F1 against labeled ground truth; classifies rules as `[STRONG]` (F1 ≥ 0.70) or `[WEAK]` (F1 < 0.30) |
| T14 | `14-rule_prioritization.sh` | Reads `risk_register.json`, `rule_quality.json`, and `attack_coverage.json`; computes risk and priority scores (likelihood × impact weighted by rule performance); outputs a ranked `rule_prioritization.json`, prints the top 10 rules, and gracefully handles orphan rules with no coverage mapping |
| T15 | `15-generate_alerts.sh` | Enumerates active rules, executes them via `3-sigma_runner.sh`, maps matches to alert objects with UUID5 identifiers, enriches each with asset inventory and risk score, applies 60-second deduplication, sorts descending by priority score, and writes `alert_queue.json` alongside its schema contract |
| T17 | `spec/detection_spec.md` | Bounded, two-page (<800 word) formal specification: Purpose, Inputs, Rule Authoring Standard, Execution Model, Quality Thresholds, Tuning Protocol, Risk Ranking Model, Outputs, Failure Modes, and Reviewer Checklist |

## Directory Structure

```
detection_catalog/
├── rules/
│   └── sigma/
│       ├── tuned/                    # Refined rules with environment-specific exclusions
│       └── *.yml                     # Core Sigma detection rules (001–013)
├── spec/
│   └── detection_spec.md             # Formal detection engineering specification
├── 3-sigma_runner.sh                 # Rule execution and aggregation engine
├── 10-fp_baseline.sh                 # False positive baseline analysis
├── 13-rule_quality.sh                # Precision / recall / F1 scoring
├── 14-rule_prioritization.sh         # Risk-weighted priority scoring
├── 15-generate_alerts.sh             # Triage alert queue + schema generator
├── fp_baseline.json                  # Baseline false-positive metrics
├── rule_quality.json                 # Per-rule quality evaluations
├── rule_prioritization.json          # Risk-ranked rule inventory
├── alert_queue.json                  # Production alert queue for 3x03
└── alert_queue_schema.json           # Strict JSON schema contract for alert feeds
```

## Quick Start

**1. Load environment configuration** — ensure `NORM_DIR`, `BASELINE_PKG`, `ASSETS_DIR`, and `HANDOFF_DIR` are exported:

```bash
source ~/m3_env.sh
```

**2. Run false positive baseline analysis:**

```bash
chmod +x 10-fp_baseline.sh
./10-fp_baseline.sh
```

**3. Compute quality metrics:**

```bash
chmod +x 13-rule_quality.sh
./13-rule_quality.sh
```

**4. Generate risk-based priorities:**

```bash
chmod +x 14-rule_prioritization.sh
./14-rule_prioritization.sh
```

**5. Generate the triage alert queue and schema:**

```bash
chmod +x 15-generate_alerts.sh
./15-generate_alerts.sh
```

## Governance & Quality Gates

- **Minimum F1 threshold** — production rules must score **F1 ≥ 0.70** (`[STRONG]`) for a reliable signal-to-noise ratio; rules scoring below **0.30** (`[WEAK]`) are flagged for tuning or retirement.
- **Deduplication window** — alerts from the same rule, hostname, and user within a **60-second window** are automatically collapsed into one, so a burst of identical activity doesn't flood the queue during a real incident.
- **Risk over raw performance** — priority ranking is *not* a simple F1 leaderboard: a lower-F1 rule protecting a higher-risk asset (e.g. patient data access) can and should outrank a higher-F1 rule on a lower-risk target, because prioritization is driven by likelihood × impact, not detection accuracy alone.
- **Data contract enforcement** — the 3x03 Tier 1 triage shift consumes `alert_queue.json` under the strict typing defined in `alert_queue_schema.json`. Schema drift or unauthorized structural changes must fail ingestion validation rather than silently degrade downstream triage.

## Detection Engineering Specification

The full engineering standard lives in [`spec/detection_spec.md`](./spec/detection_spec.md) — a deliberately bounded (<800 word) document covering:

- **Purpose & Inputs** — what the catalog is for and what data it consumes
- **Rule Authoring Standard** — how a new Sigma rule must be written to be accepted
- **Execution Model** — how rules are run and aggregated
- **Quality Thresholds** — the F1 gates described above
- **Tuning Protocol** — how a noisy or weak rule gets fixed or retired
- **Risk Ranking Model** — how priority scores are computed
- **Outputs** — the artifacts this pipeline is responsible for producing
- **Failure Modes** — what breaks, and how it's supposed to fail safely
- **Reviewer Checklist** — what a peer reviewer verifies before a rule ships

## Design Principles

- **Correlation over single-source noise** — where a correlated, multi-event rule (e.g. failed-then-successful VPN login pairing) provides materially better signal than an isolated single-source rule, the single-source rule is a candidate for retirement rather than indefinite parallel maintenance.
- **Coverage gaps are tracked, not ignored** — ATT&CK tactics without a corresponding rule (e.g. `defense_evasion`, `exfiltration`, `impact`) are explicitly documented rather than left as a silent blind spot, with sub-technique-level justification for what gets prioritized next.
- **File integrity as a first-class detection surface** — critical server file integrity monitoring is treated as a core detection category, not an afterthought bolted on after network and auth coverage.

## Roadmap

- [ ] Close tracked ATT&CK coverage gaps (`defense_evasion`, `exfiltration`, `impact`), starting with T1567 sub-technique coverage
- [ ] Expand correlation rule set to retire redundant single-source rules
- [ ] Add automated regression testing for rule quality scoring
- [ ] Extend `alert_queue_schema.json` versioning so downstream 3x03 consumers can detect and reject drift automatically

---

*Part of the MedDefense SOC portfolio series — the detection layer built on top of the evidence pipeline (3x00) and behavioral baseline/anomaly detection (3x01) handoffs.*
