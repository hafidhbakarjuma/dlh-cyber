# MedDefense Network Security Project

**Perimeter and Network Defense**

> **MedDefense Health Systems — Network Perimeter & Defense Engineering**
>
> **Mission:** Reduce the attack surface of the MedDefense infrastructure through network visibility, zone-based segmentation, host-based enforcement, secure protocol controls, DNS filtering, network detection, and structured security evidence.

---

## Project Overview

The **MedDefense Network Security Project** is a defensive security engineering project focused on identifying, reducing, and controlling the network attack surface of MedDefense Health Systems.

The project addresses a critical architectural weakness: **flat network architecture**, where systems and services can communicate with insufficient segmentation or enforcement boundaries.

The security strategy is built around four core principles:

1. **Visibility** — Identify which services, ports, processes, and protocols are reachable.
2. **Segmentation** — Separate systems into security zones according to their function and risk.
3. **Default Deny** — Explicitly permit required traffic and deny everything else.
4. **Evidence** — Produce structured, machine-readable artifacts for security analysis and auditing.

The project progressively transforms the environment from a broadly trusted network into a **segmented, least-privilege, and defensible network architecture**.

---

## Security Objectives

The project is designed to:

- Enumerate network-reachable services.
- Establish a reproducible network security baseline.
- Identify unnecessary or dangerous network exposure.
- Map listening sockets to processes, binaries, packages, and services.
- Classify services according to function and criticality.
- Identify insecure or unnecessarily exposed protocols.
- Design security zones around system roles and trust boundaries.
- Enforce host-based firewall policies using `nftables`.
- Implement a default-deny inbound security posture.
- Implement DNS filtering and sinkholing.
- Analyze network traffic using offline PCAP investigation.
- Apply Suricata rules in offline/replay mode.
- Generate structured JSON security evidence.
- Validate security controls automatically.
- Produce artifacts suitable for SOC analysis and auditing.

---

## Defensive Architecture

The project follows a **defense-in-depth** model:

```text
                    ┌───────────────────────┐
                    │      External         │
                    │       Network         │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │   Perimeter Controls  │
                    │ Firewall / Filtering  │
                    └───────────┬───────────┘
                                │
                    ┌───────────┴───────────┐
                    │    Security Zones     │
                    └───────────┬───────────┘
                                │
              ┌─────────────────┼─────────────────┐
              │                 │                 │
              ▼                 ▼                 ▼
        Server Zone         User Zone        Restricted Zone
              │                 │                 │
              ▼                 ▼                 ▼
        Host Firewall      Host Firewall     Host Firewall
              │                 │                 │
              └─────────────────┼─────────────────┘
                                │
                                ▼
                     DNS Filtering / IDS
                                │
                                ▼
                       Security Evidence
                                │
                                ▼
                          SOC Analysis
```

The architecture assumes that network location alone does not establish trust.

Traffic must be explicitly justified by:

- Source
- Destination
- Protocol
- Port
- Business function
- Security requirement

---

## Project Workflow

The project follows a progressive security-engineering workflow:

```text
T0  Network Baseline
     │
     ▼
T1  Attack Surface Mapping
     │
     ▼
T2  Zone / Segmentation Design
     │
     ▼
T3+ Host Firewall Enforcement
     │
     ▼
    DNS Security
     │
     ▼
    Secure Protocol Controls
     │
     ▼
    Suricata / Network Detection
     │
     ▼
    PCAP Investigation
     │
     ▼
    Validation & Evidence
     │
     ▼
    SOC-Ready Security Package
```

Each stage builds on evidence produced by the previous stage.

### T0 — Network Baseline

The first stage establishes a reproducible picture of the endpoint's network state.

The baseline identifies:

- Listening TCP sockets
- Listening UDP sockets
- Bind addresses
- Ports
- Processes
- Network interfaces
- Host information

Example:

```text
0.0.0.0:22
0.0.0.0:3306
127.0.0.1:53
0.0.0.0:445
```

The important distinction is:

> "What is listening?" versus "Should this service be reachable?"

The T0 artifact becomes the primary evidence source for the attack-surface analysis performed in T1.

### T1 — Attack Surface Mapping

T1 consumes:

```text
network_baseline.json
```

and produces:

```text
attack_surface.json
```

The purpose is to determine not only what is listening, but whether the service should be exposed.

For every listening socket, the analysis attempts to identify:

- Protocol
- Port
- Bind address
- Owning process
- Executable
- Debian package
- System service
- Service function
- Criticality
- Exposure violations

#### Service Functions

Services are classified using the project service catalog:

- database
- web
- ssh
- dns
- ntp
- rpc
- smb
- print
- telemetry
- unknown

#### Criticality

Services are assigned:

- critical
- high
- medium
- low

Unknown functions are retained rather than discarded so they can be reviewed during later analysis.

#### Exposure Detection

The attack-surface analysis identifies services that should not be broadly exposed.

**Database Exposure**

`0.0.0.0` + database produces:

- `bound_0.0.0.0`
- `database_exposed`

**RPC Exposure**

`0.0.0.0` + rpc produces:

- `bound_0.0.0.0`
- `rpc_exposed`

**Insecure Protocols**

The project also identifies:

- telnet
- ftp
- snmpv1
- snmpv2c
- rlogin
- NFS v2/v3

These findings are represented as structured exposure flags.

Example:

```json
{
  "port": 3306,
  "process": "mysqld",
  "function": "database",
  "criticality": "critical",
  "exposure_flags": [
    "bound_0.0.0.0",
    "database_exposed"
  ]
}
```

### T2 — Zone-Based Segmentation

The project addresses flat network architecture through security zones.

Systems are separated according to:

- Business function
- Trust level
- Exposure
- Data sensitivity
- Administrative requirements
- Security criticality

The objective is to reduce the blast radius of a compromise.

Instead of:

```text
Host A ───── Host B ───── Host C
   │            │            │
   └────────────┴────────────┘
        Broad Connectivity
```

the target architecture is:

```text
             ┌──────────────┐
             │   Perimeter  │
             └──────┬───────┘
                    │
          ┌─────────┴─────────┐
          │   Policy Boundary │
          └─────────┬─────────┘
                    │
       ┌────────────┼────────────┐
       │            │            │
       ▼            ▼            ▼
    Server       User        Restricted
     Zone         Zone          Zone
       │            │            │
       └────────────┴────────────┘
              Explicit ACLs
```

Only required communication paths are permitted between zones.

#### Host-Based Firewall Enforcement

Linux systems use `nftables` to enforce host-level network policy.

The firewall design follows:

```text
Default Policy   → DROP
Required Traffic → ACCEPT
Security Events  → LOG
```

The rules are designed to be:

- Explicit
- Auditable
- Reproducible
- Idempotent
- Compatible with the zone model

Host-based enforcement provides an additional security boundary even if network-level segmentation fails.

### DNS Security

DNS is treated as a security control rather than simply a name-resolution service.

The project implements localized DNS filtering and sinkholing to prevent systems from communicating with known malicious infrastructure.

The defensive flow is:

```text
Malware
   │
   ▼
DNS Query
   │
   ▼
Malicious Domain
   │
   X
DNS Sinkhole / Block
```

This provides an additional defensive layer against malicious destinations and command-and-control infrastructure.

### Secure Protocol Enforcement

The project evaluates network services for unnecessary or insecure protocols.

Examples include:

- Telnet
- FTP
- Legacy SNMP variants
- Rlogin
- Legacy NFS versions
- Unnecessary RPC exposure
- Broad database exposure

The objective is to replace, restrict, or remove insecure protocols and reduce the network attack surface.

### Network Detection & PCAP Analysis

Network detection is performed using offline traffic analysis.

The project uses:

- Suricata
- PCAP files
- Detection rules
- Offline replay
- Network investigation scripts

Suricata operates in offline/replay mode for analysis tasks. This avoids introducing unnecessary persistent services into the assessment environment.

The analysis focuses on:

- Suspicious connections
- Malicious communication
- Protocol anomalies
- Command-and-control indicators
- Policy violations
- Potential lateral movement

### Structured Security Evidence

A major design requirement is JSON-first security evidence.

Each major task produces machine-readable artifacts.

Example:

```json
{
  "generated_at": "2026-08-17T10:30:00+02:00",
  "hostname": "billing-srv-01",
  "sockets": [],
  "summary": {
    "total_sockets": 0,
    "flagged_sockets": 0,
    "unknown_functions": 0
  }
}
```

Structured artifacts provide:

- Repeatable analysis
- Automated validation
- Easier comparison between runs
- SOC ingestion
- Evidence preservation
- Reduced manual transcription
- Scriptable downstream reporting

---

## Repository Structure

```text
.
├── 00_.../
│   └── Network baseline and foundational analysis
│
├── 01_.../
│   └── Attack surface analysis
│
├── 02_.../
│   └── Segmentation and zone design
│
├── 03_.../
│   └── Host firewall enforcement
│
├── ...
│
├── 19_.../
│   └── Final audit and evidence packaging
│
├── docs/
│   ├── architecture/
│   ├── security-design/
│   └── investigation-notes/
│
├── bin/
│   └── Validation and auditing utilities
│
└── README.md
```

Each task directory contains the scripts, configurations, catalogs, and generated evidence associated with that stage.

---

## Task Roadmap

| Phase | Tasks | Focus |
|---|---|---|
| Foundations | T0–T5 | Network visibility, baseline analysis, attack-surface identification |
| Segmentation | T6–T10 | Security zones, nftables, default-deny enforcement |
| Defense Layers | T11–T14 | DNS filtering, secure protocols, IDS and traffic analysis |
| Audit & Package | T15–T19 | Validation, evidence collection, reporting and SOC packaging |

---

## Operational Principles

### Idempotency

Scripts that modify system state are designed to be safely re-run.

Repeated execution should not:

- Duplicate firewall rules
- Corrupt configuration
- Create uncontrolled state
- Produce inconsistent security policies

### No Persistent Analysis Daemons

Network-analysis components such as Suricata operate in offline/replay mode where possible.

The objective is to analyze evidence without introducing unnecessary persistent services.

### JSON-First

Security tasks produce machine-readable artifacts whenever practical.

```text
System State
     │
     ▼
Security Script
     │
     ▼
JSON Evidence
     │
     ▼
Validation
     │
     ▼
SOC Analysis
```

### Local Execution

The project is designed to operate without requiring:

- Live Internet access
- A centralized SIEM
- Cloud management infrastructure
- External security platforms

This makes the assessment reproducible in an isolated lab or controlled enterprise environment.

### Validation

Each task includes validation logic wherever practical.

A typical workflow is:

```bash
./task.sh
```

followed by:

```bash
jq empty output.json
```

and additional task-specific checks.

Scripts should report:

- Success/failure status
- Validation results
- Generated artifacts
- Relevant security findings

This creates an auditable chain from system state to security conclusion.

---

## Evidence Lifecycle

The project treats security artifacts as an evidence pipeline:

```text
Collection
    │
    ▼
Normalization
    │
    ▼
Classification
    │
    ▼
Detection
    │
    ▼
Validation
    │
    ▼
Analysis
    │
    ▼
SOC Consumption
```

This allows individual task outputs to become inputs for later security decisions.

For example:

```text
network_baseline.json
        │
        ▼
attack_surface.json
        │
        ▼
segmentation policy
        │
        ▼
nftables rules
        │
        ▼
network validation
        │
        ▼
SOC evidence
```

---

## Security Outcomes

The project is designed to produce measurable improvements in the MedDefense security posture.

**Visibility**
Identify what is actually exposed rather than relying on configuration assumptions.

**Attack Surface Reduction**
Remove or restrict services that do not require broad network access.

**Segmentation**
Reduce lateral movement opportunities by enforcing security boundaries.

**Least Privilege**
Permit only the communication required for legitimate business functions.

**Detection**
Identify suspicious traffic and protocol behavior through offline network analysis.

**Evidence**
Maintain structured artifacts demonstrating what was discovered, changed, and validated.

---

## Design Philosophy

The project follows a simple defensive principle:

> You cannot secure what you cannot see, and you cannot effectively segment what you have not first mapped.

Therefore, implementation begins with visibility and measurement before enforcement.

```text
                 VISIBILITY
                     │
                     ▼
              ATTACK SURFACE
                     │
                     ▼
               SEGMENTATION
                     │
                     ▼
                ENFORCEMENT
                     │
                     ▼
                 DETECTION
                     │
                     ▼
                VALIDATION
                     │
                     ▼
                  EVIDENCE
```

Each layer supports the next.

---

## Intended Audience

This repository is intended for:

- Blue Team engineers
- SOC analysts
- Network security engineers
- Security administrators
- Infrastructure engineers
- Security students
- Auditors reviewing defensive controls

The project emphasizes repeatability, evidence, automation, and practical defensive engineering rather than purely theoretical security controls.

---

## Final Objective

The final objective is to transform the MedDefense network from a relatively flat and implicitly trusted environment into a:

- Measured
- Segmented
- Least-privilege
- Monitored
- Validated
- Defensible

network architecture.

The project combines:

```text
Network Visibility
        +
Attack Surface Management
        +
Zone Segmentation
        +
Host Firewall Enforcement
        +
DNS Security
        +
Protocol Hardening
        +
Network Detection
        +
Structured Evidence
```

to establish a layered defensive architecture capable of reducing attack surface, limiting lateral movement, detecting suspicious network activity, and providing auditable security evidence.

---

**MedDefense Health Systems**
*Internal Security Operations — Network Security Engineering*

> Security is not a single control. It is the continuous process of measuring, reducing, enforcing, detecting, and validating risk.
