# THE DEFENSIBLE ENDPOINT PACKAGE

## Project Hawthorne: Defensible Endpoint & Enterprise Handoff Capstone

Welcome to the **Defensible Endpoint Capstone**, an integrated security engineering workflow that unifies Linux host hardening, Windows endpoint hardening, telemetry instrumentation, automated patch management, offline network defense, and rigorous self-verifying validation into a single production-grade pipeline.

---

## 🏗️ Architectural Overview & Workflow

This capstone transitions security engineering from isolated scripts into a cohesive, continuous engineering lifecycle. The project is executed sequentially across eleven core phases:

```
[Task 0-1: Scaffolding & Recon]
              │
              ▼
[Task 2-3: Target State & Host Hardening (Linux/Windows)]
              │
              ▼
[Task 4-5: Telemetry Instrumentation & Patch Pipeline]
              │
              ▼
[Task 6-7: Perimeter Defense & Offline Suricata Replay]
              │
              ▼
[Task 8-11: End-to-End Validation, Compliance Mapping & Final Handoff]
```

---

## 📂 Repository Structure

```text
blue_team/2x05_defensible_endpoint/
├── capstone/
│   ├── target_state.json      # Master declarative control baseline (Task 2)
│   ├── validation.json        # Empirical execution pass/fail report (Task 8)
│   ├── compliance.json        # Regulatory framework control mapping (Task 10)
│   ├── manifest.json          # Cryptographic inventory & file integrity (Task 11)
│   └── exec/                  # Execution logs and diagnostic run outputs
├── 0-scaffold.sh              # Environment initialization & directory setup
├── 2-target_state.sh          # Target state generator & schema validator
├── 8-validate_all.sh          # End-to-end validation engine & family aggregator
├── 10-compliance.sh           # Regulatory mapping & gap analysis runner
└── 11-manifest.sh             # Handoff packaging and checksum generator
```

---

## 🚀 Execution & Verification Guide

### 1. Initialize the Environment (Task 0)

Set up the required directory tree and workspace permissions:

```bash
bash 0-scaffold.sh
```

### 2. Generate and Validate the Target State (Task 2)

Establish the declarative baseline (`capstone/target_state.json`) which defines all required security controls, check types, and expected values:

```bash
bash 2-target_state.sh
```

### 3. Run the End-to-End Validation Suite (Task 8)

Evaluate all control families against the live environment. This script checks file paths, JSON fields, exit codes, and regex patterns, rendering a family-grouped summary table and writing results to `capstone/validation.json`:

```bash
bash 8-validate_all.sh
```

### 4. Run Compliance Mapping (Task 10)

Map implemented technical controls against baseline benchmarks to generate `capstone/compliance.json`:

```bash
bash 10-compliance.sh
```

### 5. Generate the Final Handoff Manifest (Task 11)

Compile the final delivery package by generating cryptographic checksums and cataloging all assets into `capstone/manifest.json`:

```bash
bash 11-manifest.sh
```

---

## 🛡️ Core Verification Artifacts

The handoff package relies on four foundational artifacts to ensure it is fully self-verifying for incoming engineers and Module 3 analysts:

- **`target_state.json`** — Defines baseline design intent and expected control parameters.
- **`validation.json`** — Provides empirical proof of execution success, containing pass/fail counts and verdicts.
- **`compliance.json`** — Maps technical configurations against regulatory and structural security frameworks.
- **`manifest.json`** — Inventories all package deliverables and guarantees file integrity via checksums.

---

## 👥 Professional Handoff & Operations

Designed in accordance with professional security engineering standards, this repository requires no verbal intervention from the original author. Incoming analysts can verify telemetry trustworthiness instantly via `validation.json` and deploy the environment safely on day one.
