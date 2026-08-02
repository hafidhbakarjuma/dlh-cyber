# LOCKING THE GATE

# MedDefense Production Hardening Framework

Welcome to the **MedDefense Security Hardening Pipeline**. This repository contains an automated, dependency-ordered production hardening framework designed to secure Linux environments to rigorous compliance and defense standards.

---

## 🚀 Overview & Pipeline Architecture

The hardening process is structured into a sequential, idempotent master pipeline controlled by an orchestration script (`14-hardening_orchestrator.sh`). It executes modular security controls ranging from baseline snapshots and access control configuration to kernel-level hardening, audit coverage validation, and telemetry reporting.

### Complete Task Matrix (Tasks 0 – 21)

| Task ID | Script Name | Description | Focus Area |
| :--- | :--- | :--- | :--- |
| **00** | `0-baseline_snapshot.sh` | Captures initial system and security baseline metrics. | Baseline & Telemetry |
| **01** | *N/A (Config)* | Environment setup and directory preparation. | Initialization |
| **02** | `2-lynis_parse.sh` | Parses Lynis security auditing scans for automated parsing. | Vulnerability Assessment |
| **03** | *N/A (Config)* | Package manager and repository locking. | Supply Chain |
| **04** | `4-ssh_hardening.sh` | Hardens SSH daemon configurations (disables root login, restricts ciphers). | Remote Access |
| **05** | `5-sysctl_hardening.sh` | Applies secure Linux kernel parameters via `sysctl` (network/memory protections). | Kernel Security |
| **06** | `6-filesystem_hardening.sh` | Secures file permissions, mounts, and removes insecure filesystems. | Storage & Integrity |
| **07** | `7-service_minimization.sh` | Disables unnecessary legacy and network services. | Attack Surface |
| **08** | `8-pam_hardening.sh` | Enforces strong Pluggable Authentication Modules (PAM) policies (password complexity, lockout). | Identity & Access |
| **09** | `9-apparmor_config.sh` | Configures and enforces AppArmor mandatory access control profiles. | Mandatory Access Control |
| **10** | `10-auditd_config.sh` | Deploys comprehensive `auditd` rules to track security-relevant system calls. | Monitoring & Forensics |
| **11** | `11-audit_coverage_test.sh` | Executes controlled audit test events and evaluates telemetry capture coverage. | Compliance Testing |
| **12** | `12-log_config.sh` | Configures structured `rsyslog` channels, log rotation policies, and file permissions. | Log Management |
| **13** | `13-firewall_baseline.sh` | Configures UFW with default-deny inbound policies, port restrictions, and logging. | Network Security |
| **14** | `14-hardening_orchestrator.sh` | Master pipeline executor, prerequisite checker, and JSON telemetry reporter. | Orchestration |
| **15** | `15-validation.sh` | Final end-to-end security posture validation check. | Verification |
| **16–21** | *Extension Modules* | Advanced container security, integrity monitoring, automated rollback, and reporting. | Enterprise Hardening |

---

## 🛠️ Execution Instructions

### Prerequisites
* **Root Privileges**: All scripts must be run as `root`.
* **Supported OS**: Ubuntu / Debian-based Linux distributions.

### Running the Pipeline
To execute the complete production hardening pipeline in proper dependency order, run the master orchestrator:

```bash
sudo ./14-hardening_orchestrator.sh
