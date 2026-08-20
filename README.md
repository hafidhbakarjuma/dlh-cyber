
<div align="center">

# 🛡️ DLH Cyber Security

### A Hands-On Blue Team Engineering Portfolio

*Progressive, project-based coursework from DLH Cybersecurity Academy — from foundational security concepts to production-grade defensive engineering pipelines.*

![Bash](https://img.shields.io/badge/Bash-4EAA25?style=flat&logo=gnubash&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=flat&logo=powershell&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=flat&logo=windows&logoColor=white)
![NIST CSF](https://img.shields.io/badge/Framework-NIST%20CSF%202.0-blue)
![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)
![CIS Controls](https://img.shields.io/badge/Framework-CIS%20Controls%20v8-green)

</div>

---

## 📌 About This Repository

This repository is a structured, portfolio-grade record of my cybersecurity engineering coursework — built as a **defender's curriculum**, not a collection of one-off scripts. Every module produces real, working artifacts: hardening scripts, detection rules, risk registers, compliance mappings, and validation engines that actually run against live environments.

The work is organized into two layers:

- **`Common_Core/`** — foundational security engineering skills: Linux/Windows fundamentals, networking, scripting, cryptography, forensics, threat modeling, and web application security.
- **`blue_team/`** — a 12-module progressive **Blue Team track**, moving from security posture assessment through to a fully self-verifying, production-grade endpoint hardening and handoff pipeline.

Each module is self-contained, documented, and designed to demonstrate not just "I ran a tool" but **why the control matters, how it maps to a framework, and how its success is proven** — the same standard expected of a working SOC Analyst or Security Engineer.

---

## 🎯 Skills Demonstrated

| Domain | Highlights |
|---|---|
| **Security Hardening** | Linux (CIS Benchmarks), Windows/Active Directory, SSH, firewall (nftables / Windows Firewall) |
| **Threat & Risk Analysis** | STRIDE, MITRE ATT&CK mapping, kill chains, risk registers, ALE/SLE/ARO quantitative risk |
| **Governance & Compliance** | NIST CSF 2.0, CIS Controls v8, ISO 27001, policy drafting, gap analysis |
| **Detection & Telemetry** | Sysmon tuning, Windows Event Log auditing, auditd, log pipeline configuration |
| **Vulnerability & Patch Management** | CVE triage, CVSS contextualization, patch pipelines, change management |
| **Network Defense** | Network segmentation, Suricata IDS, PCAP/traffic analysis, DNS filtering |
| **Cryptography & PKI** | Symmetric/asymmetric encryption, CSR generation, TLS auditing, disk encryption (LUKS) |
| **Scripting & Automation** | Bash, PowerShell, and Python for security automation and validation |
| **Web Application Security** | OWASP Top 10, Burp Suite, content discovery, upload vulnerabilities |
| **Incident Response** | Threat scenario analysis, emergency response planning, board-level communication |

---

## 📂 Repository Structure

```text
dlh-cyber/
├── Common_Core/                       # Foundational security engineering skills
│   ├── cybersecurity_basics/
│   ├── linux_security/
│   ├── network_security/
│   ├── scripting_cyber/
│   ├── threat-modeling-fundamentals/
│   └── web_application_security/
│
├── blue_team/                         # Progressive 12-module Blue Team track
│   ├── 1x00_first_watch/
│   ├── 1x01_know_your_enemy/
│   ├── 1x02_the_weak_links/
│   ├── 1x03_defense_blueprint/
│   ├── 1x04_crypto_foundation/
│   ├── 1x05_board_briefing/
│   ├── 2x00_locking_the_gates/
│   ├── 2x01_windows_fortress/
│   ├── 2x02_eyes_on_endpoint/
│   ├── 2x03_patch_equation/
│   ├── 2x04_perimeter_defense/
│   └── 2x05_defensible_endpoint/      # 🏆 Capstone: full defensive engineering pipeline
│
├── maintenance_window.json
└── README.md
```

---

## 🧱 Common Core — Foundational Modules

Core security engineering fundamentals that underpin every module in the Blue Team track.

| Module | Focus |
|---|---|
| **`cybersecurity_basics/`** | Core security concepts, shell fundamentals, process & signal handling, forensic methodologies, cryptography basics |
| **`linux_security/`** | Linux hardening fundamentals, file permissions, SUID/SGID, mandatory access control (SELinux/AppArmor), network protocols, forensic methodology |
| **`network_security/`** | Passive & active reconnaissance, Nmap live host discovery, network traffic monitoring and analysis |
| **`scripting_cyber/`** | Python scripting for security automation — packet crafting, DNS/network utilities, and tooling |
| **`threat-modeling-fundamentals/`** | Applied STRIDE threat modeling across real-world system types: e-commerce, healthcare mobile apps, IoT devices, financial trading platforms |
| **`web_application_security/`** | OWASP Top 10 labs, Burp Suite fundamentals, content discovery (Gobuster/ffuf), file upload vulnerability exploitation |

---

## 🔵 Blue Team Track — Progressive Defensive Engineering

A story-driven, 12-module simulation of a security engineer's lifecycle inside an organization — from initial assessment to full production handoff.

### Series 1 — Assessment, Threat Intelligence & Governance

| Module | Title | Focus |
|---|---|---|
| **1x00** | `first_watch` | Initial security posture assessment — incident classification, control matrix, gap analysis, CISO briefing |
| **1x01** | `know_your_enemy` | Threat landscape analysis — threat actor taxonomy, kill chains, STRIDE, MITRE ATT&CK mapping, threat prioritization |
| **1x02** | `the_weak_links` | Vulnerability management — CVE ecosystem, false-positive triage, legacy systems, CVSS contextualization |
| **1x03** | `defense_blueprint` | Governance & risk — NIST CSF mapping, risk register, control selection, security strategy, risk appetite |
| **1x04** | `crypto_foundation` | Applied cryptography — symmetric encryption, CSR generation, TLS auditing, disk encryption, key management |
| **1x05** | `board_briefing` | Crisis response — CVE deep-dive, kill chain overlay, emergency planning, board-level presentation |

### Series 2 — Hardening, Detection & Production Handoff

| Module | Title | Focus |
|---|---|---|
| **2x00** | `locking_the_gates` | Linux hardening — CIS profile baselining, auditd configuration, firewall baseline, compliance bundling |
| **2x01** | `windows_fortress` | Windows/AD hardening — domain baseline, event log assessment, Sysmon tuning, AppLocker, RDP & service account hardening |
| **2x02** | `eyes_on_endpoint` | Telemetry & detection — Sysmon coverage matrix, PowerShell logging, cross-platform attack simulation & detection proof |
| **2x03** | `patch_equation` | Patch management — vulnerability inventory, pre-patch snapshots, patch pipeline automation, compliance reporting |
| **2x04** | `perimeter_defense` | Network defense — attack surface mapping, segmentation rules, nftables/Windows Firewall, Suricata IDS, PCAP investigation |
| **2x05** | 🏆 `defensible_endpoint` | **Capstone** — unifies Linux/Windows hardening, telemetry, patch pipelines, and perimeter defense into a single self-verifying, production-grade handoff package (declarative target state → empirical validation → compliance mapping → cryptographic manifest) |

> 📄 See [`blue_team/2x05_defensible_endpoint/README.md`](./blue_team/2x05_defensible_endpoint/README.md) for the full capstone architecture and execution guide.

---

## 🚀 Getting Started

Each module is self-contained. To explore a module:

```bash
git clone https://github.com/hafidhbakarjuma/dlh-cyber.git
cd dlh-cyber/blue_team/<module_name>
```

Most modules ship with numbered scripts (`0-...`, `1-...`, etc.) representing sequential tasks, alongside Markdown deliverables documenting findings, decisions, and analysis. Bash scripts target Linux (tested on Kali/Ubuntu), PowerShell scripts target Windows Server/AD environments.

---

## 🧪 Related Work

This repository complements my broader hands-on lab environment:

- **MedDefense SOC Lab** — a multi-VM home lab (OPNsense, Graylog SIEM, Wazuh HIDS, LibreNMS, Active Directory) used to apply and validate the controls built in this repository against a live, monitored environment.

---

## 👤 About Me

I'm a cybersecurity and software engineering student pursuing the **SOC Analyst / Penetration Testing** track at DLH Cybersecurity Academy, alongside coursework at **42 Luxembourg**. This repository reflects hands-on, framework-aligned defensive security engineering work as I build toward a career as a SOC Analyst / Junior Penetration Tester.

- **GitHub:** [@hafidhbakarjuma](https://github.com/hafidhbakarjuma)
- **LinkedIn:** [hafidhbakarjuma](https://www.linkedin.com/in/hafidhbakarjuma)

---

<div align="center">

*⭐ If you find this useful as a reference for structuring your own blue team learning path, consider starring the repo.*

</div>
