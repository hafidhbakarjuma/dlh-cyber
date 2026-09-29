# 4x02 — Intelligence-Driven Defense: The HEALTHBANE Campaign

![Track](https://img.shields.io/badge/Track-SOC%20Analyst%20%2F%20Threat%20Intelligence-blue)
![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)
![Detection](https://img.shields.io/badge/Detection-YARA-orange)
![Sharing](https://img.shields.io/badge/Advisory-TLP%3ACLEAR-green)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)

> *"The goal is to turn data into information, and information into insight."* — Carly Fiorina

**Organization (scenario):** MedDefense Health Systems
**Program:** DLH Cybersecurity Academy — SOC Analyst / Penetration Testing track
**Author:** [hafidhbakarjuma](https://github.com/hafidhbakarjuma)
**Repository path:** [`threat_detection/4x02_intelligence_driven_defense`](https://github.com/hafidhbakarjuma/dlh-cyber/tree/main/threat_detection)

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Scenario & Context](#scenario--context)
3. [Objectives](#objectives)
4. [Intelligence Sources](#intelligence-sources)
5. [Repository Structure](#repository-structure)
6. [Task Index](#task-index)
7. [Core Deliverables](#core-deliverables)
8. [Methodology](#methodology)
9. [Getting Started](#getting-started)
10. [Analytical Principles](#analytical-principles)
11. [Skills Demonstrated](#skills-demonstrated)
12. [References](#references)

---

## Executive Summary

Modules 4x00 (phishing analysis) and 4x01 (packet capture analysis) were **reactive**: evidence arrived, was analyzed, and findings were reported. This project moves to **proactive, intelligence-driven defense**.

MedDefense received four conflicting intelligence inputs about a healthcare-targeting campaign designated **HEALTHBANE**. The task was to convert raw, noisy, partially contradictory reporting into decision-ready intelligence:

- What do we **trust**, and why?
- What can we **detect** today?
- What **can't** we detect?
- What are we **doing about it**?

The result is an evidence-based workflow covering source assessment, indicator triage and enrichment, infrastructure clustering, kill-chain reconstruction, ATT&CK mapping, detection gap analysis, YARA rule development and testing, and a final executive intelligence brief for the board.

---

## Scenario & Context

Week twelve at MedDefense. HC3 has published a TLP:CLEAR advisory describing a coordinated campaign against healthcare organizations, built partly on IOCs MedDefense submitted after the 4x00 phishing investigation.

| Stage | Activity | MedDefense exposure |
|-------|----------|---------------------|
| 1 | Phishing delivery (credential-harvesting lures) | Observed and stopped (user report + fast investigation) |
| 2 | Malware delivery | Seen at two other organizations |
| 3 | Data exfiltration | Seen at two other organizations |

Because the attacker may return with **new infrastructure**, static domain/IP blocklists are insufficient. Defense must target **adversary behavior**, not only yesterday's IOCs. The Chief Medical stakeholder needs a board-ready position in 10 days.

---

## Objectives

- Apply the **threat intelligence lifecycle** (direction, collection, processing, analysis, dissemination, feedback).
- Assess sources with a structured method (**Admiralty Code**) — source reliability separated from information credibility.
- Deduplicate, normalize and classify indicators as **ACTIONABLE**, **CONTEXTUAL** or **NOISE**.
- Enrich IOCs (WHOIS, DNS, certificate transparency, VirusTotal-style, passive DNS) and cluster infrastructure.
- Map behavior to **MITRE ATT&CK**, separating **OBSERVED** from **INFERRED** techniques.
- Identify detection gaps and prioritize engineering work.
- Write, compile and **test YARA rules** (TP / FP / FN, precision, detection rate).
- Deliver a final intelligence brief with consistent **HIGH / MEDIUM / LOW** confidence.

---

## Intelligence Sources

| Source | Label / Attribution | Handling notes |
|--------|--------------------|----------------|
| HC3 sector advisory (TLP:CLEAR) | HEALTHBANE; attribution **unconfirmed** | Confirmed sector intelligence; high value |
| Commercial CTI feed extract (JSON) | VITALSCORE | Contains intentional noise and weakly clustered indicators |
| Public researcher blog | APT-MEDAGENT (**medium** confidence) | Attribution claim not independently corroborated |
| MedDefense internal 4x00 findings | No attribution | First-party evidence; strongest provenance |
| YARA sample corpus | — | Benign and malicious PDFs and `.eml` files for rule testing |

Attribution conflicts (HEALTHBANE vs. VITALSCORE vs. APT-MEDAGENT) are **documented, not merged**. Every indicator retains the source(s) that reported it.

---

## Repository Structure

```text
4x02_intelligence_driven_defense/
├── README.md
├── healthbane_layer.json          # ATT&CK Navigator layer (Task 7)
├── 8-detection_gaps.md            # Detection gap assessment (Task 8)
├── 9-yara_phishing_pdf.yar        # Baseline YARA rule (Task 9)
├── 10-*.yar                       # Email header + composite rules (Task 10)
├── 11-yara_testing.sh             # Automated rule validation (Task 11)
├── 13-intelligence_brief.md       # Executive intelligence brief (Task 13)
├── sources/                       # Provided intelligence (unmodified originals)
│   ├── HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt
│   ├── commercial_feed_extract.json
│   ├── researcher_blog_analysis.txt
│   └── meddefense_4x00_findings.txt
└── samples/                       # YARA corpus (benign + malicious)
    ├── phishing_sample.pdf
    ├── healthbane_lure_02.pdf
    ├── clean_invoice.pdf
    ├── benign_invoice.pdf
    ├── healthbane_email_01.eml
    ├── healthbane_email_02.eml
    ├── healthbane_email_03.eml
    ├── benign_newsletter.eml
    └── samples_manifest.txt
```

> Provided source and sample files are **never modified in place**; all working copies live in the project directory.

---

## Task Index

### Part 1 — Campaign Analysis & Threat Intelligence Foundation

| Task | Focus |
|------|-------|
| 0–4 | Initial triage, source reliability assessment, artifact processing |
| 5 | IOC database extraction, normalization and tagging |
| 6 | Three-stage kill chain breakdown and timeline mapping |

### Part 2 — MITRE ATT&CK & Detection Engineering

| Task | Focus | Deliverable |
|------|-------|-------------|
| 7 | ATT&CK mapping and Navigator layer | `healthbane_layer.json` |
| 8 | Detection gap analysis (DETECTED / PARTIALLY DETECTED / NOT DETECTED) with prioritized action plan | `8-detection_gaps.md` |
| 9 | YARA foundations — rule for `wkhtmltopdf`-generated phishing PDFs with credential-harvesting paths and parameters | `9-yara_phishing_pdf.yar` |
| 10 | YARA arsenal expansion — email header and composite campaign rules | `10-*.yar` |
| 11 | Rule testing against the corpus: TP/FP/FN, detection rate, FPR, precision, and a `DEPLOY` / `TUNE` / `MONITOR` recommendation | `11-yara_testing.sh` |
| 12–13 | Adversary profiling and final executive brief | `13-intelligence_brief.md` |

### Part 3 — Operational Review & Analytical Evaluations

| Task | Topic | Key question |
|------|-------|--------------|
| 15 | Intelligence source assessment | How to prioritize indicators from a government advisory, an unverified researcher and a commercial feed, and what trade-offs exist between timeliness, corroboration and false-positive risk? |
| 16 | ATT&CK analytical reasoning | How should ambiguous statements (e.g., generic "move laterally") be mapped versus confirmed artifacts (spearphishing, RAT via macro documents), and what are the risks of marking vague claims as observed? |
| 17 | YARA operational context | Why is a rule relying solely on a generic creator string (`wkhtmltopdf`) not production-ready, and how do compound conditions tune it for deployment? |
| 18 | The intelligence cycle in practice | How do 4x00 and 4x02 together demonstrate direction, collection, processing, analysis, dissemination and feedback, and why is the cycle continuous? |

---

## Core Deliverables

1. **`healthbane_layer.json`** — ATT&CK Navigator layer distinguishing OBSERVED and INFERRED techniques.
2. **`8-detection_gaps.md`** — Gap assessment covering blind spots across initial access, execution and command-and-control, with prioritized actions.
3. **`9-yara_phishing_pdf.yar` and arsenal** — Compiled, tested YARA rules for malicious PDF structure and email indicators.
4. **`11-yara_testing.sh`** — Automated validation script producing TP/FP/FN and deployment recommendations.
5. **`13-intelligence_brief.md`** — Board-level brief: risk profile, timeline, trusted vs. untrusted intelligence, detection posture and mitigations.

---

## Methodology

```text
Direction ─► Collection ─► Processing ─► Analysis ─► Dissemination ─► Feedback
   │                                                                     │
   └─────────────────────────── (cycle repeats) ◄────────────────────────┘
```

1. **Source assessment** — Admiralty Code rating; reliability and credibility scored independently.
2. **Indicator triage** — Deduplicate, normalize, preserve provenance, classify ACTIONABLE / CONTEXTUAL / NOISE.
3. **Enrichment and clustering** — Registrar, hosting, TLS certificate, naming and tooling patterns; identify pivots between clusters.
4. **Kill chain reconstruction** — Three-stage campaign built from incomplete data, with gaps stated explicitly.
5. **ATT&CK mapping** — Each technique tagged OBSERVED or INFERRED with written justification.
6. **Gap analysis** — Compare mapped behavior against current detection capability.
7. **Detection engineering** — YARA rules written, compiled, tested and scored.
8. **Dissemination** — Executive brief and partner-shareable output.

---

## Getting Started

### Prerequisites

- `yara`, `jq`, `grep`, `bash`
- `whois`, `dig` (for enrichment references)
- `shellcheck` (optional, for script linting)

No live SIEM, Wazuh server, Suricata sensor or prior-module infrastructure is required. Everything runs locally on the provided materials.

### Validate the deliverables

```bash
# Confirm the ATT&CK layer is valid JSON
jq empty healthbane_layer.json && echo "layer OK"

# Confirm YARA rules compile
yara -C 9-yara_phishing_pdf.yar 2>/dev/null || yarac 9-yara_phishing_pdf.yar /tmp/rules.out

# Lint the test script
shellcheck 11-yara_testing.sh

# Run the full YARA test suite against the corpus
chmod +x 11-yara_testing.sh
./11-yara_testing.sh
```

Load `healthbane_layer.json` into the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) via **Open Existing Layer → Upload from local**.

---

## Analytical Principles

- **Facts vs. assessments** — Confirmed evidence is labeled separately from inference.
- **Consistent confidence** — HIGH, MEDIUM and LOW, applied the same way throughout.
- **No overclaimed attribution** — When sources conflict, the conflict is documented with a recommendation.
- **Provenance preserved** — Every indicator tracks which source reported it.
- **Reproducible** — All judgments are documented and outputs regenerate from local files.
- **Behavior over indicators** — Detections target TTPs, since infrastructure is cheap for the adversary to change.

---

## Skills Demonstrated

**Threat intelligence:** lifecycle, Admiralty Code, strategic/operational/tactical intelligence, conflicting-source reconciliation
**Analysis:** IOC triage, enrichment, infrastructure clustering, campaign reconstruction
**Frameworks:** MITRE ATT&CK, Navigator layers, observed-vs-inferred discipline
**Detection engineering:** YARA authoring, testing, metrics, deployment decisions
**Communication:** executive briefing, gap analysis, prioritized action planning
**Tooling:** Bash, `jq`, `yara`, `whois`, `dig`, `shellcheck`

---

## References

- [MITRE ATT&CK](https://attack.mitre.org/) and [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [CISA Cyber Threats and Advisories](https://www.cisa.gov/topics/cyber-threats-and-advisories)
- [HHS HC3 Products](https://www.hhs.gov/about/agencies/asa/ocio/hc3/index.html)
- [YARA Documentation](https://yara.readthedocs.io/)
- [VirusTotal](https://www.virustotal.com/), [crt.sh](https://crt.sh/), [URLhaus](https://urlhaus.abuse.ch/)

---

*Educational project completed as part of the DLH Cybersecurity Academy curriculum. All organizations, personnel and campaign details are part of a training scenario.*
