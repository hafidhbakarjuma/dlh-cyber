# Cross-Platform Detection Analysis — CLI vs. SIEM Vendor Evaluation

**A hands-on SIEM vendor evaluation built on real investigations, not a feature spreadsheet.** The same three incidents, investigated twice — once through a CLI pipeline (jq, Sigma, the 3x00–3x03 handoff artifacts), once through Wazuh evidence exports — with every claim in the final vendor brief backed by counted, measurable evidence.

![Status](https://img.shields.io/badge/status-active-brightgreen)
![Language](https://img.shields.io/badge/scripts-bash%20%2B%20python3-blue)
![Data](https://img.shields.io/badge/format-JSON-lightgrey)
![Security+](https://img.shields.io/badge/Security%2B-4.4%20%7C%204.7-informational)

---

## Table of Contents

- [Overview](#overview)
- [Scenario](#scenario)
- [Why This Project Exists](#why-this-project-exists)
- [Platform Note — Export Mode](#platform-note--export-mode)
- [Investigation Workflow](#investigation-workflow)
- [Task Breakdown](#task-breakdown)
- [Finding Schema](#finding-schema)
- [Query Language Comparison](#query-language-comparison)
- [Deliverables](#deliverables)
- [Environment Variables](#environment-variables)
- [Required Tools](#required-tools)
- [Repository Structure](#repository-structure)
- [Roadmap](#roadmap)

---

## Overview

A detection analyst who only knows one interface is a liability the moment their organization changes platforms — and every serious SOC changes its primary platform every three to five years. This project proves that the analytical skill built across the previous four MedDefense modules (evidence pipeline, baselining, detection engineering, Tier 1 triage) is genuinely tool-agnostic: the same investigation, run through a raw CLI pipeline and through a SIEM's exported evidence, produces the same findings — because the cognitive workflow doesn't change, even when the access method does.

The output is a complete, evidence-backed vendor evaluation package that MedDefense's SOC Lead can hand directly to leadership ahead of a platform decision — grounded in real incidents investigated on both interfaces under consideration, not a copied feature comparison from a vendor's website.

## Scenario

MedDefense's board has approved an infrastructure review, and Compliance wants proof of a vendor-informed SIEM decision ahead of the annual security program audit. Rather than a features spreadsheet, SOC Lead James Chen wants an analyst report: the same three real incidents, investigated on every interface under evaluation, with defensible, counted evidence behind the final recommendation.

Two interfaces are compared head-to-head:

- **CLI pipeline** — `jq`, `sigma-cli`, and the flat-file handoffs already built in 3x00–3x03
- **Wazuh evidence export** — pre-indexed search results and dashboard workflow traces, staged by the infrastructure team from the same 339,000-event evidence pack

Same evidence. Same three scenarios. Same ATT&CK techniques. Two completely different interaction models — and the deliverable is a brief that tells leadership, with evidence, which one actually performs better under real investigative pressure.

## Why This Project Exists

1. **The SOC hires analysts, not SIEM operators.** An analyst who can only investigate through one dashboard becomes a liability at every platform transition. This project builds and proves the transferable skill: decomposing any query interface into filters, aggregations, and time windows.
2. **Evidence-based platform decisions, not vendor marketing.** Compliance needs to see that a real analyst investigated real incidents on every platform considered — not that the SOC just kept whatever was convenient.
3. **Operational reality includes non-live access.** Some platforms are accessed live, some through exported evidence during a maintenance window, some through an API. An analyst who can only work through an open browser tab isn't deployable everywhere.

## Platform Note — Export Mode

This module runs in **Wazuh export mode**: rather than querying a live dashboard, the investigation reads local JSON files that capture exactly what the Wazuh interface would show — pre-exported search results and dashboard workflow traces, generated from the same evidence pack used by the CLI pipeline. The investigation workflow, finding schema, and comparison deliverables are identical to a live-dashboard design; only the access method differs. This mirrors a real operational constraint: maintenance windows, API-only access, and offline evidence review are all normal SOC conditions, not edge cases.

## Investigation Workflow

```
Same 339,000-event evidence pack
            │
      ┌─────┴─────┐
      ▼           ▼
┌───────────┐ ┌────────────────────┐
│ CLI        │ │ Wazuh Evidence      │
│ Pipeline   │ │ Export              │
│ (jq,       │ │ (search results +   │
│ sigma-cli, │ │ dashboard traces)   │
│ 3x00-3x03) │ │                     │
└─────┬──────┘ └──────────┬──────────┘
      │                   │
      ▼                   ▼
   3 scenarios investigated on each interface
   (anchor, scenario_a, scenario_b, scenario_c)
      │                   │
      └─────────┬─────────┘
                ▼
   6 structured findings, locked JSON schema
                │
                ▼
   Time-to-first-answer, fields touched,
   events reviewed — counted, not opinion
                │
                ▼
   Sigma → Wazuh XML rule translation (validated, xmllint)
                │
                ▼
   4-language query comparison (jq / Sigma / KQL / Lucene)
                │
                ▼
   Tool-agnostic investigation playbook
                │
                ▼
   Vendor evaluation brief → tool_evaluation/ package + manifest
```

## Task Breakdown

| Task | Deliverable | What It Covers |
|---|---|---|
| T1 | Workspace init | Confirms container image reference and lab environment setup |
| T2–T9 | 6 structured findings | Each of 3 scenarios investigated through both the CLI pipeline and the Wazuh evidence export, conforming to the locked finding schema |
| T10 | Sigma → Wazuh XML translation | 3 Sigma rules translated to native Wazuh XML, validated with `xmllint` |
| T11–T12 | Query language comparison | The same investigative question expressed in `jq`, Sigma detection blocks, KQL, and Lucene |
| T13 | `workflow_comparison.json` | Time-to-first-answer, fields touched, and events reviewed, compared side by side across interfaces per scenario |
| T14 | Tool-agnostic investigation playbook | Documents which skills are interface-independent vs. interface-dependent, plus a field-name translation table |
| T15 | `vendor_brief.md` | Bounded, two-page (~900 word) evaluation brief for Dr. Morales, with a fixed section order and evidence standard |
| T16–T18 | `tool_evaluation/` package | Final locked-layout deliverable package with a `MANIFEST.json` of SHA-256 hashes over every artifact |

## Finding Schema

Every structured finding — regardless of which interface produced it — conforms to this locked schema, so a finding from `jq` and a finding from a Wazuh search result export read identically:

```json
{
  "finding_id": "scenario_a_cli",
  "scenario_id": "scenario_a",
  "interface": "cli",
  "investigation_start": "2026-06-14T02:10:00Z",
  "investigation_end": "2026-06-14T02:24:00Z",
  "time_to_first_answer_seconds": 187,
  "actions": ["jq filter on src_ip", "pivot to auth log", "..."],
  "fields_touched": ["src_ip", "user", "event_category"],
  "event_refs": ["evt_00231", "evt_00245"],
  "attack_techniques": ["T1110"],
  "hypothesis": "Two-sentence maximum working theory.",
  "confidence": "medium",
  "created_at": "2026-06-14T02:25:00Z"
}
```

- `scenario_id` — one of `anchor`, `scenario_a`, `scenario_b`, `scenario_c`
- `interface` — one of `cli`, `wazuh_export`
- `actions` — ordered list, capped at 20 entries
- `confidence` — one of `low`, `medium`, `high`

## Query Language Comparison

The core insight this module builds toward: any SIEM query, regardless of syntax, decomposes into the same three canonical components — **filter**, **aggregation**, and **time window**. The comparison table expresses one investigative question across all four languages this way, making the differences purely syntactic rather than conceptual:

| Language | Role in this project |
|---|---|
| `jq` | CLI-native filtering and transformation of flat JSON evidence |
| Sigma (YAML) | Vendor-neutral detection abstraction layer |
| KQL | Query syntax exposed through the Wazuh dashboard filter bar |
| Lucene | Legacy query syntax underlying Wazuh/OpenSearch searches |

## Deliverables

- **Six structured findings** — 3 scenarios × 2 interfaces, locked JSON schema
- **Three translated detection rules** — Sigma → native Wazuh XML, `xmllint`-validated
- **A four-language query comparison table** — jq, Sigma, KQL, Lucene
- **A tool-agnostic investigation playbook** — interface-independent vs. interface-dependent skills, field-name translation table
- **`vendor_brief.md`** — the bounded evaluation brief for Dr. Morales
- **`tool_evaluation/`** — the complete, manifest-verified package handed to leadership

## Environment Variables

No hardcoded paths — every dependency is read from an environment variable, defaulting as follows:

| Variable | Default | Purpose |
|---|---|---|
| `HANDOFF_DIR` | `~/3x00_handoff/evidence_handoff` | 3x00 evidence pipeline handoff |
| `BASELINE_PKG` | `~/3x01_package/baseline_package` | 3x01 baseline package |
| `CATALOG_DIR` | `~/3x02_package/detection_catalog` | 3x02 detection catalog |
| `TRIAGE_PKG` | `~/3x03_package/triage_package` | 3x03 triage package |
| `ASSETS_DIR` | `~/3x04_assets` | This module's lab assets |
| `WAZUH_EXPORTS` | `~/3x04_assets/wazuh_exports` | Wazuh evidence export artifacts |

## Required Tools

- `jq` 1.6+
- `yq` (Mike Farah binary)
- `python3` 3.10+ with `pyyaml` and `requests`
- `sigma-cli`
- `xmllint` — for Wazuh XML rule validation (Task 10)

## Repository Structure

```
3x04_cross_platform_detection/
├── findings/
│   ├── anchor_cli.json
│   ├── anchor_wazuh_export.json
│   ├── scenario_a_cli.json
│   ├── scenario_a_wazuh_export.json
│   ├── scenario_b_cli.json
│   ├── scenario_b_wazuh_export.json
│   ├── scenario_c_cli.json
│   └── scenario_c_wazuh_export.json
├── rules/
│   └── wazuh_xml/                    # Sigma rules translated to native Wazuh XML
├── query_comparison/
│   └── query_language_comparison.md  # jq / Sigma / KQL / Lucene, side by side
├── workflow_comparison.json          # Time-to-first-answer, fields touched, events reviewed
├── playbook/
│   └── investigation_playbook.md     # Tool-agnostic workflow + field-name translation table
├── brief/
│   └── vendor_brief.md               # Bounded evaluation brief for Dr. Morales
└── tool_evaluation/
    ├── MANIFEST.json                 # SHA-256 hashes over every artifact in the package
    └── ...                           # Locked-layout final deliverable package
```

## Roadmap

- [ ] Extend the query language comparison to include a fifth platform if the board shortlist grows
- [ ] Automate `workflow_comparison.json` generation directly from timestamped action logs rather than manual entry
- [ ] Add a fourth scenario once a live Wazuh dashboard becomes available, to compare export-mode timing against live-interface timing
- [ ] Feed the field-name translation table back into the 3x02 detection catalog documentation for future rule authors

---

*Part of the MedDefense SOC portfolio series — the cross-platform validation layer built on top of the 3x00 evidence pipeline, 3x01 baseline package, 3x02 detection catalog, and 3x03 Tier 1 triage handoffs.*
